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
        let Some(refresh) = tokens.refresh_token.as_deref() else {
            return Err(CliError::Auth(match tokens.origin {
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
            }));
        };
        // Only a password session renews with the profile's device token, so
        // an imported one never reads that keychain item at all.
        let profile_device = if tokens.origin.is_password() {
            self.creds
                .get(&config::device_key(&self.profile))?
                .map(|s| s.expose().to_string())
        } else {
            None
        };
        let fresh = self
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
            .renewed(&tokens);
        self.creds
            .set(&config::token_key(&self.profile), &fresh.to_secret())?;
        Ok(fresh.access_token)
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
