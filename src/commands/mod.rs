//! One module per command group, plus the shared [`Ctx`] they read from.

pub mod accounts;
pub mod api;
pub mod auth;
pub mod dividends;
pub mod documents;
pub mod fanout;
pub mod instruments;
pub mod interest;
pub mod misc;
pub mod networth;
pub mod option_events;
pub mod option_instruments;
pub mod options;
pub mod positions;
pub mod profiles;
pub mod transactions;
pub mod transfers;

use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::{output, CliError, CommonArgs, Money};
use pk_cli_secrets::CredentialStore;
use serde::Serialize;
use serde_json::Value;

use crate::fixed::normalize_amount;

use crate::client::{Origin, Rh, Tokens};
use crate::config::{self, Config};

/// Read a provider money string (`"1234.5600"`) as a [`Money`].
///
/// Robinhood returns fixed-point strings with four decimal places. They stay
/// strings all the way through — never floats, per SPEC v1 §1.4 — but the
/// trailing zeros are trimmed so a table reads `$1234.56` rather than
/// `$1234.5600`. Sub-cent precision is preserved when it is actually
/// significant, because option and crypto prices genuinely carry it.
pub fn money_at(v: &Value, key: &str) -> Option<Money> {
    let raw = v.get(key)?.as_str()?;
    if raw.is_empty() {
        return None;
    }
    Some(Money::usd(normalize_amount(raw)))
}

/// Read a provider money **object** (`{"amount": "1.23", "currency_code":
/// "USD", …}`) as a [`Money`].
///
/// The newer endpoints (cash sweeps, DRIP execution prices) nest money this
/// way instead of the flat string [`money_at`] reads. `currency_code` is
/// kept verbatim — assuming USD here would misreport an FX row.
pub fn money_obj_at(v: &Value, key: &str) -> Option<Money> {
    let obj = v.get(key)?;
    let raw = obj.get("amount")?.as_str()?;
    if raw.is_empty() {
        return None;
    }
    Some(Money {
        amount: normalize_amount(raw),
        currency: obj
            .get("currency_code")
            .and_then(Value::as_str)
            .unwrap_or("USD")
            .to_string(),
    })
}

/// A money field that may arrive as a flat string (`"150.0000"`), a nested
/// money object, or — in one community model's reading — a JSON number.
/// Numbers go through `serde_json::Number`'s own rendering; no float
/// arithmetic ever touches the value.
pub fn money_any(v: &Value, key: &str) -> Option<Money> {
    match v.get(key)? {
        Value::String(_) => money_at(v, key),
        Value::Object(_) => money_obj_at(v, key),
        Value::Number(n) => Some(Money::usd(normalize_amount(&n.to_string()))),
        _ => None,
    }
}

/// An unsigned wire magnitude at `key`, signed by the row's `direction` —
/// the cash-flow convention every options DTO shares: `credit` stays
/// positive (cash in), `debit` goes negative (cash out). A zero or an
/// unknown direction is left unsigned — inventing a sign would be worse
/// than omitting one.
pub fn signed_by_direction(v: &Value, key: &str) -> Option<Money> {
    let m = money_at(v, key)?;
    let is_zero = m.amount.chars().all(|c| c == '0' || c == '.');
    if !is_zero && str_at(v, "direction").as_deref() == Some("debit") {
        return Some(Money {
            amount: format!("-{}", m.amount),
            currency: m.currency,
        });
    }
    Some(m)
}

/// Inclusive `--since`/`--until` test for a dated row — the comparison every
/// date-bearing list shares.
///
/// Undated-row policy deliberately stays at each call site: the
/// transaction-like lists keep undated rows (silently losing a payment is
/// the worse failure for tax work), while documents excludes them when an
/// explicit range is set (there is nothing to compare against).
pub fn date_within(date: &str, since: Option<&str>, until: Option<&str>) -> bool {
    let after_since = match since {
        Some(s) => date >= s,
        None => true,
    };
    let before_until = match until {
        Some(u) => date <= u,
        None => true,
    };
    after_since && before_until
}

/// Trim a provider quantity string (`"10.00000000"` → `"10"`).
///
/// Quantities are not money — they carry no currency and fractional shares are
/// real — so they keep their own formatting rather than going through
/// [`money_at`]. Significant fractional digits are preserved.
pub fn trim_quantity(raw: &str) -> String {
    match raw.split_once('.') {
        Some((int, frac)) => {
            let trimmed = frac.trim_end_matches('0');
            if trimmed.is_empty() {
                int.to_string()
            } else {
                format!("{int}.{trimmed}")
            }
        }
        None => raw.to_string(),
    }
}

/// The date part of an RFC-3339 timestamp (`2026-03-14T12:00:00.000000Z` →
/// `2026-03-14`), so date flags and output agree on ISO dates.
pub fn date_of(v: &Value, key: &str) -> Option<String> {
    let raw = v.get(key)?.as_str()?;
    let date = raw.split('T').next().unwrap_or(raw);
    (date.len() == 10).then(|| date.to_string())
}

/// A plain string field, absent rather than empty.
pub fn str_at(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Emit a single (non-list) DTO per the output contract, tagged
/// `<schema>/v1`. Lists use `Paged::emit` instead.
pub fn emit_one<T: Serialize>(schema: &str, dto: &T, json_mode: bool) {
    let payload = serde_json::to_value(dto).unwrap_or(Value::Null);
    output::emit(json_mode, schema, payload, output::render);
}

/// Emit a DTO that already carries its own `schema` field (the
/// `documents/v1` profile types do), so it is not tagged twice.
pub fn emit_self_tagged<T: Serialize>(dto: &T, json_mode: bool) {
    let v = serde_json::to_value(dto).unwrap_or(Value::Null);
    if json_mode {
        output::json(&v);
    } else {
        output::render(&v);
    }
}

/// The UUID out of `https://api.robinhood.com/instruments/<uuid>/`.
pub fn instrument_id(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit('/').next()?;
    (!last.is_empty() && last != "instruments").then(|| last.to_string())
}

/// What every provider-reading command needs: which login, which brokerage
/// account, and a client that can talk to it.
///
/// Constructing a `Ctx` performs **no** network I/O and reads no keychain
/// entry — argument validation has to be able to fail before either. The
/// session is fetched lazily by [`Ctx::tokens`], on first use.
pub struct Ctx {
    pub common: CommonArgs,
    /// Active login profile name.
    pub profile: String,
    /// Brokerage account number to act on, once resolved.
    pub account: Option<String>,
    pub rh: Rh,
    creds: CredentialStore,
}

impl Ctx {
    pub fn new(
        common: CommonArgs,
        cfg: Config,
        profile: String,
        account_flag: Option<String>,
    ) -> Result<Self, CliError> {
        let account = cfg.resolve_account(&profile, account_flag.as_deref());
        Ok(Ctx {
            common,
            profile,
            account,
            rh: Rh::new()?,
            creds: CredentialStore::for_binary(config::BIN),
        })
    }

    /// The cached OAuth tokens for this profile, or a pointed auth error.
    ///
    /// Deliberately does not attempt a silent password login: a first login on
    /// an unrecognized device raises a challenge that needs the account
    /// owner's phone, and doing that implicitly in the middle of an unrelated
    /// read is both surprising and a lockout risk.
    pub fn tokens(&self) -> Result<Tokens, CliError> {
        let raw = self
            .creds
            .get(&config::token_key(&self.profile))?
            .ok_or_else(|| {
                CliError::Auth(format!(
                    "no cached session for profile `{}` — run `rhd auth login --browser --profile {}`",
                    self.profile, self.profile
                ))
            })?;
        Tokens::from_json(raw.expose())
    }

    /// The access token to present, refreshing it first when it has expired
    /// and a refresh token is available.
    ///
    /// Refreshing is safe to do implicitly (it needs no second factor and
    /// raises no challenge), which is exactly why it is the one part of the
    /// login flow this method will do on its own.
    pub fn access_token(&self) -> Result<String, CliError> {
        let tokens = self.tokens()?;
        if !tokens.is_expired() {
            return Ok(tokens.access_token);
        }
        if tokens.refresh_token.is_none() {
            return Err(self.not_renewable(&tokens));
        }
        let token_key = config::token_key(&self.profile);
        let fresh = renew_session(
            &RefreshLock::for_binary(config::BIN)?,
            || self.tokens(),
            |stored| self.not_renewable(stored),
            |stored, refresh| self.grant(stored, refresh),
            |fresh| self.creds.set(&token_key, &fresh.to_secret()),
        )?;
        Ok(fresh.access_token)
    }

    /// Why an expired session cannot be renewed: it holds no refresh token.
    fn not_renewable(&self, tokens: &Tokens) -> CliError {
        CliError::Auth(match tokens.origin {
            Origin::Bearer => format!(
                "the browser session imported into `{p}` has expired — a bare bearer token \
                 cannot be renewed; sign in again with `rhd auth login --browser --profile \
                 {p}`, which stores the renewable web:auth_state shape",
                p = self.profile
            ),
            _ => format!(
                "the cached session for `{p}` expired and carries no refresh token — run \
                 `rhd auth login --browser --profile {p}`",
                p = self.profile
            ),
        })
    }

    /// Spend `refresh`, the session's refresh token, for a new bundle.
    fn grant(&self, tokens: &Tokens, refresh: &str) -> Result<Tokens, CliError> {
        // Only a password session renews with the profile's device token, so
        // an imported one never reads that keychain item at all.
        let profile_device = if tokens.origin.is_password() {
            self.creds
                .get(&config::device_key(&self.profile))?
                .map(|s| s.expose().to_string())
        } else {
            None
        };
        Ok(self
            .rh
            .refresh(refresh, tokens.refresh_device(profile_device.as_deref()))
            .map_err(|e| match e {
                CliError::Auth(msg) if tokens.origin.is_browser() => CliError::Auth(format!(
                    "{msg} (this session came from a browser: sign in again with `rhd auth login \
                     --browser --profile {}`)",
                    self.profile
                )),
                other => other,
            })?
            .renewed(tokens))
    }

    /// The account number to act on, or a usage error naming how to pick one.
    pub fn require_account(&self) -> Result<&str, CliError> {
        self.account.as_deref().ok_or_else(|| {
            CliError::Usage(
                "no brokerage account selected — pass `-a <ACCOUNT_NUMBER>`, set one with \
                 `rhd profiles add <NAME> --account <ID>`, or run `rhd accounts list` to see them"
                    .into(),
            )
        })
    }
}

/// One renewal, safe against every other `rhd` process: the long-running
/// `mcp --http` server, a stdio server, a command in a terminal. They share one
/// refresh token, which rotates on every use (docs/api.md §2.5), and a process
/// that presents a retired one loses the session, which costs the owner a
/// sign-in. So the session is read again under the lock, and one no longer
/// expired means another process renewed while this one waited: no grant.
fn renew_session(
    lock: &RefreshLock,
    read: impl FnOnce() -> Result<Tokens, CliError>,
    not_renewable: impl FnOnce(&Tokens) -> CliError,
    grant: impl FnOnce(&Tokens, &str) -> Result<Tokens, CliError>,
    store: impl FnOnce(&Tokens) -> Result<(), CliError>,
) -> Result<Tokens, CliError> {
    lock.renew(read, Tokens::is_expired, |stored| {
        let Some(refresh) = stored.refresh_token.as_deref() else {
            return Err(not_renewable(&stored));
        };
        let fresh = grant(&stored, refresh)?;
        store(&fresh)?;
        Ok(fresh)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::Duration;

    fn session(refresh: Option<&str>, expires_at: u64) -> Tokens {
        Tokens {
            access_token: "dummy-access".into(),
            refresh_token: refresh.map(String::from),
            expires_at: Some(expires_at),
            read_only_token: None,
            origin: Origin::WebAuthState,
            device_token: None,
        }
    }

    fn expired(refresh: &str) -> Tokens {
        session(Some(refresh), 1)
    }

    fn live(refresh: &str) -> Tokens {
        session(Some(refresh), crate::client::now_unix() + 3600)
    }

    fn not_renewable(_: &Tokens) -> CliError {
        CliError::Auth("dummy: cannot be renewed".into())
    }

    /// Two processes' worth of contenders: each has its own open of the lock
    /// file, which is what contends, and both saw the same session expired.
    /// Offline, with the keychain and the token endpoint stood in for.
    #[test]
    fn two_contenders_post_one_grant_and_both_use_its_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        let stored = Arc::new(Mutex::new(expired("dummy-refresh-1")));
        let grants = Arc::new(Mutex::new(Vec::new()));
        let start = Arc::new(Barrier::new(2));
        let contenders: Vec<_> = (0..2)
            .map(|_| {
                let (path, stored, grants, start) = (
                    path.clone(),
                    Arc::clone(&stored),
                    Arc::clone(&grants),
                    Arc::clone(&start),
                );
                std::thread::spawn(move || {
                    start.wait();
                    renew_session(
                        &RefreshLock::at(path),
                        || Ok(stored.lock().unwrap().clone()),
                        not_renewable,
                        |_, refresh| {
                            grants.lock().unwrap().push(refresh.to_string());
                            std::thread::sleep(Duration::from_millis(100));
                            Ok(live("dummy-refresh-2"))
                        },
                        |fresh| {
                            *stored.lock().unwrap() = fresh.clone();
                            Ok(())
                        },
                    )
                })
            })
            .collect();
        for contender in contenders {
            let session = contender.join().unwrap().unwrap();
            assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
        }
        assert_eq!(*grants.lock().unwrap(), ["dummy-refresh-1"]);
    }

    #[test]
    fn a_session_no_longer_expired_skips_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        let session = renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            || Ok(live("dummy-refresh-2")),
            not_renewable,
            |_, _| panic!("another process renewed: no grant"),
            |_| panic!("nothing new to store"),
        )
        .unwrap();
        assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
    }

    #[test]
    fn the_grant_presents_the_token_read_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let stored = Mutex::new(None);
        let fresh = renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            || Ok(expired("dummy-refresh-newest")),
            not_renewable,
            |_, refresh| {
                assert_eq!(refresh, "dummy-refresh-newest");
                Ok(live("dummy-refresh-next"))
            },
            |fresh| {
                *stored.lock().unwrap() = Some(fresh.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(fresh.refresh_token.as_deref(), Some("dummy-refresh-next"));
        let stored = stored.lock().unwrap();
        assert_eq!(
            stored.as_ref().unwrap().refresh_token.as_deref(),
            Some("dummy-refresh-next")
        );
    }

    #[test]
    fn an_expired_session_replaced_by_one_with_no_refresh_token_posts_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let err = renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            || Ok(session(None, 1)),
            not_renewable,
            |_, _| panic!("no refresh token: no grant"),
            |_| panic!("nothing to store"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn a_logout_while_waiting_is_an_auth_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let err = renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            || Err(CliError::Auth("dummy: no cached session".into())),
            not_renewable,
            |_, _| panic!("logged out: no grant"),
            |_| panic!("logged out: nothing to store"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn a_held_lock_is_a_bounded_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        RefreshLock::at(&path)
            .hold(|| {
                let err = renew_session(
                    &RefreshLock::at(&path).wait_at_most(Duration::from_millis(100)),
                    || panic!("no read without the lock"),
                    not_renewable,
                    |_, _| panic!("no grant without the lock"),
                    |_| panic!("nothing to store"),
                )
                .unwrap_err();
                assert!(err.to_string().contains("try again"), "{err}");
                Ok(())
            })
            .unwrap();
    }
}
