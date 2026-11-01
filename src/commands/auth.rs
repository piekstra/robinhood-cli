//! `rhd auth …` — login (a browser sign-in, a browser-session import, or the
//! password with its device-approval dance), status, logout, and raw
//! credential writes.
//!
//! The shape of the login flow is deliberate and is the part to preserve if
//! this file is ever rewritten:
//!
//! - **One attempt per invocation.** No loops. A loop against a device
//!   challenge is how an account gets locked.
//! - **Park, don't re-ask.** When a challenge is raised without a TTY to
//!   prompt on, the in-flight attempt is stored and the user resumes it with
//!   `--code`. A code is bound to the attempt that requested it.
//! - **Prove before storing.** A session is only written to the keychain
//!   after a real read succeeds with it, so a login that authenticates but
//!   can't fetch anything leaves nothing broken behind. That holds for a
//!   session from a browser (`--browser`, `--session-stdin`) too.

use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserError, Launch};
use pk_cli_config::ConfigStore;
use pk_cli_core::{CliError, CommonArgs};
use pk_cli_secrets::{CredentialStore, Secret};
use serde::Serialize;
use serde_json::Value;

use crate::capture::{self, Captured, Source};
use crate::client::{ChallengeKind, Channel, LoginOutcome, Parked, ReadFailure, Rh, Tokens};
use crate::config::{self, Config};

/// The bits of `auth login` this module needs, decoupled from the clap tree.
pub struct LoginInput<'a> {
    pub base: &'a LoginArgs,
    pub username: Option<&'a str>,
    pub code: Option<&'a str>,
    /// Continue a parked attempt that needs no code — the phone-approval case.
    pub resume: bool,
    pub channel: Channel,
}

pub fn login(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    profile: &str,
    input: &LoginInput<'_>,
) -> Result<(), CliError> {
    let creds = CredentialStore::for_binary(config::BIN);
    let rh = Rh::new()?;

    let username = resolve_username(&cfg, profile, input, common)?;
    let password = resolve_password(&creds, profile, input, common)?;

    // A code (or an explicit --resume) belongs to the attempt that raised the
    // challenge, so resume *that* attempt rather than starting a fresh one:
    // a code is bound to the workflow that issued it.
    if input.code.is_some() || input.resume {
        let raw = creds.get(&config::pending_key(profile))?.ok_or_else(|| {
            CliError::Usage(format!(
                "no login is waiting to be resumed — run `rhd auth login --profile {profile}` first"
            ))
        })?;
        let parked: Parked = serde_json::from_str(raw.expose())
            .map_err(|e| CliError::Other(format!("the parked login could not be read ({e})")))?;

        if parked.kind == ChallengeKind::Prompt && !common.quiet {
            eprintln!("waiting for the approval in your Robinhood app...");
        }

        let result = rh.resume(
            &parked,
            input.code.map(str::trim),
            &username,
            password.expose(),
            input.channel,
        );
        // Spent either way: a stale attempt must never be replayed twice.
        creds.delete(&config::pending_key(profile))?;
        let tokens = result?;
        return finish(
            common,
            store,
            &mut cfg,
            &creds,
            &rh,
            profile,
            &username,
            &parked.device_token,
            tokens,
        );
    }

    // Reuse this profile's device token if it has one. Minting a fresh token
    // presents as a brand-new device and re-raises the approval challenge, so
    // it happens exactly once per profile.
    let device_token = match creds.get(&config::device_key(profile))? {
        Some(d) => d.expose().to_string(),
        None => Rh::new_device_token(),
    };

    match rh.login(&username, password.expose(), &device_token, input.channel)? {
        LoginOutcome::Session(tokens) => finish(
            common,
            store,
            &mut cfg,
            &creds,
            &rh,
            profile,
            &username,
            &device_token,
            *tokens,
        ),
        LoginOutcome::NeedsApproval { parked, hint } => {
            // Park before doing anything else, so even an attempt the user
            // abandons can be resumed later instead of started over — a fresh
            // login would raise a second challenge.
            creds.set(
                &config::pending_key(profile),
                &Secret::new(serde_json::to_string(&parked).unwrap_or_default()),
            )?;

            // Without a TTY there is nobody to prompt and nothing to wait on,
            // so hand back the exact command that resumes this attempt.
            if !common.interactive() {
                let how = match parked.kind {
                    ChallengeKind::Prompt => format!(
                        "approve it, then re-run `rhd auth login --profile {profile} --resume`"
                    ),
                    ChallengeKind::Code => {
                        format!("re-run with `rhd auth login --profile {profile} --code <CODE>`")
                    }
                };
                return Err(CliError::Auth(format!("{hint} — {how}")));
            }

            eprintln!("{hint}");
            let code = match parked.kind {
                // Nothing to type: the user taps approve and we poll.
                ChallengeKind::Prompt => None,
                ChallengeKind::Code => Some(prompt_line("Verification code: ")?),
            };
            let result = rh.resume(
                &parked,
                code.as_deref().map(str::trim),
                &username,
                password.expose(),
                input.channel,
            );
            creds.delete(&config::pending_key(profile))?;
            let tokens = result?;
            finish(
                common,
                store,
                &mut cfg,
                &creds,
                &rh,
                profile,
                &username,
                &parked.device_token,
                tokens,
            )
        }
    }
}

/// Prove the session works, then persist it.
///
/// The proving read happens *before* the write so a login that authenticated
/// but can't actually read the account leaves no half-working session in the
/// keychain for the next command to trip over.
#[allow(clippy::too_many_arguments)]
fn finish(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: &mut Config,
    creds: &CredentialStore,
    rh: &Rh,
    profile: &str,
    username: &str,
    device_token: &str,
    tokens: Tokens,
) -> Result<(), CliError> {
    let accounts = rh.paginate(
        &tokens.access_token,
        crate::commands::accounts::PATH,
        &crate::commands::accounts::all_accounts_query(),
        None,
    )?;

    creds.set(&config::token_key(profile), &tokens.to_secret())?;
    creds.set(
        &config::device_key(profile),
        &Secret::new(device_token.to_string()),
    )?;

    // `paginate` walked every page, so the listing is the whole login.
    record_profile(store, cfg, profile, Some(username), &accounts, true)?;

    if !common.quiet {
        eprintln!(
            "logged in as {username} (profile `{profile}`) — {} account{} visible",
            accounts.len(),
            if accounts.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

/// The profile bookkeeping every successful login does, password or
/// imported: remember the username when the login names one, adopt the
/// login's account as the profile default when it holds exactly one, and
/// make the profile the default when none is set. Saved before returning.
fn record_profile(
    store: &ConfigStore,
    cfg: &mut Config,
    profile: &str,
    username: Option<&str>,
    accounts: &[Value],
    complete: bool,
) -> Result<(), CliError> {
    note_login(cfg, profile, username, accounts, complete);
    store.save(cfg)
}

/// [`record_profile`] without the save, so the rules are testable.
///
/// `complete` says whether `accounts` is the whole listing. A single row from
/// one page of several is not a login with one account, and guessing there
/// would mean reading the wrong account.
fn note_login(
    cfg: &mut Config,
    profile: &str,
    username: Option<&str>,
    accounts: &[Value],
    complete: bool,
) {
    let entry = cfg.profiles.entry(profile.to_string()).or_default();
    if let Some(u) = username {
        entry.username = Some(u.to_string());
    }
    if entry.account.is_none() && complete && accounts.len() == 1 {
        entry.account = accounts[0]
            .get("account_number")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if cfg.default_profile.is_none() {
        cfg.default_profile = Some(profile.to_string());
    }
}

/// `rhd auth login --browser`: the owner signs in on robinhood.com in a
/// scratch Chrome, and the session the web app stores is read out of it
/// (docs/api.md §2.8).
///
/// The capture answers with the `web:auth_state` JSON the `--session-stdin`
/// Console snippet copies, so from there it takes the same road:
/// [`capture::parse`], one proving read, the same keychain item. The crate
/// closes the tab the moment the session is read, so the web app cannot
/// renew (and so rotate) the refresh token `rhd` is about to store, then
/// kills Chrome and deletes its profile.
pub fn browser_login(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: Config,
    profile: &str,
) -> Result<(), CliError> {
    let captured = pk_cli_browser::capture(
        Launch::new(config::BIN)
            .url(capture::LOGIN_URL)
            .quiet(common.quiet)
            .login_hint(format!("rhd auth login --browser --profile {profile}")),
        &capture::browser_capture()?,
        pk_cli_browser::DEFAULT_TIMEOUT,
    )
    .map_err(browser_failed)?;
    let value = captured.value().ok_or_else(|| {
        CliError::Other("the browser capture came back without the session".into())
    })?;
    let raw = capture::fill_device_token(
        value.expose(),
        captured.cookie(capture::DEVICE_COOKIE).map(Secret::expose),
    );
    import(common, store, cfg, profile, &raw, Source::Browser)
}

/// A failed browser sign-in as the family error, pointing at the DevTools
/// fallback when there is no Chrome to sign in through.
fn browser_failed(e: BrowserError) -> CliError {
    match e {
        BrowserError::ChromeNotFound(msg) => CliError::Other(format!(
            "{msg}. Without Chrome, import a session from your own browser instead: `rhd auth \
             login --help` walks through `--session-stdin`"
        )),
        other => other.into(),
    }
}

/// `rhd auth login --session-stdin`: import a session copied out of a
/// logged-in robinhood.com tab (docs/api.md §2.8). Parsed before anything
/// else, so bad input fails as usage without a keychain read or a request.
pub fn import_session(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: Config,
    profile: &str,
    non_interactive: bool,
) -> Result<(), CliError> {
    let raw = read_capture(common, non_interactive)?;
    import(common, store, cfg, profile, &raw, Source::Stdin)
}

/// The import both `--browser` and `--session-stdin` end in: parse, then
/// prove with **one** authenticated read, then store exactly where a
/// password login stores its bundle, so every command and the refresh path
/// use it unchanged. The profile's own device token is left alone — the
/// session carries the browser's.
fn import(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    profile: &str,
    raw: &Secret,
    source: Source,
) -> Result<(), CliError> {
    let Captured { shape, tokens } =
        capture::parse(raw.expose(), crate::client::now_unix(), source)?;

    let rh = Rh::new()?;
    // `probe`, not `get`: a refusal here must name the session, not send the
    // owner back to the password login (see `unproven`).
    let page = rh
        .probe(
            &tokens.access_token,
            &rh.url(crate::commands::accounts::PATH),
            &crate::commands::accounts::all_accounts_query(),
        )
        .map_err(|failure| unproven(failure, shape, source))?;
    let (visible, more) = accounts_page(&page).ok_or_else(|| {
        unproven(
            ReadFailure::Upstream(
                "the accounts read answered without a `results` list, so the session is \
                 unproven"
                    .into(),
            ),
            shape,
            source,
        )
    })?;

    let creds = CredentialStore::for_binary(config::BIN);
    creds.set(&config::token_key(profile), &tokens.to_secret())?;
    // A captured session names no username; the proving read was one page.
    record_profile(store, &mut cfg, profile, None, &visible, !more)?;

    let report = SessionImport {
        profile: profile.to_string(),
        source,
        shape,
        accounts_visible: visible.len(),
        more_accounts: more,
        renewable: tokens.refresh_token.is_some(),
        expires_at: tokens.expires_at_rfc3339(),
        device_token: tokens.device_token.is_some(),
        read_only_token: tokens.read_only_token.is_some(),
    };
    if common.json {
        crate::commands::emit_one("session-import/v1", &report, true);
    } else if !common.quiet {
        for line in report.lines() {
            eprintln!("{line}");
        }
    }
    Ok(())
}

/// What `--browser` or `--session-stdin` stored, without a single token
/// value (`session-import/v1`).
#[derive(Debug, Serialize)]
struct SessionImport {
    profile: String,
    /// `browser` or `stdin` ([`Source`]'s serialization).
    source: Source,
    /// `web_auth_state` or `bearer` ([`capture::Shape`]'s serialization).
    shape: capture::Shape,
    /// Accounts on the proving read's page.
    accounts_visible: usize,
    /// The read was one page of several (the proof spends one request).
    more_accounts: bool,
    /// A refresh token was stored, so rhd renews the session unattended.
    renewable: bool,
    /// When the access token expires (RFC 3339), if the token says.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    /// The browser's device id came with the session; renewal presents it.
    device_token: bool,
    /// The session carries a read-only secondary token (stored, not used).
    read_only_token: bool,
}

impl SessionImport {
    fn lines(&self) -> Vec<String> {
        let shape = match self.shape {
            capture::Shape::WebAuthState => "web:auth_state",
            capture::Shape::Bearer => "bearer token",
        };
        let n = self.accounts_visible;
        let what = match self.source {
            Source::Browser => "stored the browser sign-in's session",
            Source::Stdin => "imported a browser session",
        };
        let mut out = vec![format!(
            "{what} ({shape}) into profile `{}` — {n}{} account{} visible",
            self.profile,
            if self.more_accounts { "+" } else { "" },
            if n == 1 && !self.more_accounts {
                ""
            } else {
                "s"
            }
        )];
        let until = match &self.expires_at {
            Some(at) => format!("until {at}"),
            None => "until Robinhood expires it (the token does not say when)".into(),
        };
        if self.renewable {
            out.push(format!(
                "renews unattended: the refresh token is stored; the access token is good {until}"
            ));
            if !self.device_token {
                let again = match self.source {
                    Source::Browser => "sign in again with `rhd auth login --browser`",
                    Source::Stdin => {
                        "re-import with the Console snippet in `rhd auth login --help`"
                    }
                };
                out.push(format!(
                    "no device id came with it, so renewal will present none — UNVERIFIED that \
                     Robinhood accepts that; if renewal fails, {again}"
                ));
            }
        } else {
            out.push(format!(
                "cannot renew: a bearer token has no refresh token, so this session lasts \
                 {until}; then capture again (the web:auth_state shape renews itself)"
            ));
        }
        out.push(match self.source {
            // The window closed on capture, and its profile went with it.
            Source::Browser => "the sign-in window and its Chrome profile are gone, so rhd holds \
                                the session's only copy: no browser can renew it or log it out"
                .into(),
            Source::Stdin => "close the robinhood.com tab, but do not click Log out: logging out \
                              revokes the session rhd just stored"
                .into(),
        });
        out
    }
}

/// A failed proving read, said for the import: the cause, where the session
/// came from and which shape it was read as, and that nothing was stored.
/// Built from the typed cause, which carries no "run `rhd auth login`" — for
/// an import that advice would point back at a login the owner just did. A
/// refusal stays an auth failure (exit 3); anything else is upstream (exit 5).
fn unproven(failure: ReadFailure, shape: capture::Shape, source: Source) -> CliError {
    let msg = format!(
        "{} — {}; nothing was stored",
        failure.cause(),
        source.read_as(shape)
    );
    if failure.is_auth() {
        CliError::Auth(format!("Robinhood refused the imported session: {msg}"))
    } else {
        CliError::Upstream(msg)
    }
}

/// The proving read's accounts and whether more pages follow, or `None` if
/// the body is not the collection envelope at all.
fn accounts_page(page: &Value) -> Option<(Vec<Value>, bool)> {
    let rows = page.get("results")?.as_array()?.clone();
    let more = page
        .get("next")
        .and_then(Value::as_str)
        .is_some_and(|n| !n.is_empty());
    Some((rows, more))
}

/// The captured session: piped stdin, or a hidden paste on a terminal so the
/// token is never echoed to the screen.
fn read_capture(common: &CommonArgs, non_interactive: bool) -> Result<Secret, CliError> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return pk_cli_secrets::read_stdin();
    }
    if non_interactive || !common.interactive() {
        return Err(CliError::Usage(
            "--session-stdin reads the captured session from stdin — pipe it in: `pbpaste | \
             rhd auth login --session-stdin`"
                .into(),
        ));
    }
    Secret::prompt("Paste the captured session (input hidden), then press Enter")
}

pub fn status(
    common: &CommonArgs,
    cfg: &Config,
    profile: &str,
    account_flag: Option<&str>,
    verify: bool,
) -> Result<(), CliError> {
    let creds = CredentialStore::for_binary(config::BIN);
    let stored = cfg.profile(profile);

    let mut s = AuthStatus::new(true, false, AuthMethod::Password);
    s.username = stored.and_then(|p| p.username.clone());
    // The global `-a/--account` has to be honored here too, or `auth status`
    // reports a different account than the very next command would act on.
    s.account = cfg.resolve_account(profile, account_flag);

    let has_password = creds.get(&config::password_key(profile))?.is_some();
    s.credential_in_keychain = Some(has_password);

    match creds.get(&config::token_key(profile))? {
        Some(raw) => {
            let tokens = Tokens::from_json(raw.expose())?;
            if tokens.origin.is_browser() {
                s.method = AuthMethod::BrowserSession;
            }
            s.expires_at = tokens.expires_at_rfc3339();
            // Locally we can only say the token hasn't expired; only --verify
            // spends a request to learn whether the provider still honors it.
            if verify {
                let rh = Rh::new()?;
                let ok = rh
                    .get(
                        &tokens.access_token,
                        &format!("{}{}", rh.base(), crate::commands::accounts::PATH),
                        &[],
                    )
                    .is_ok();
                s.session_valid = Some(ok);
                s.authenticated = ok;
            } else {
                s.authenticated = !tokens.is_expired();
            }
        }
        None => {
            s.authenticated = false;
            if verify {
                s.session_valid = Some(false);
            }
        }
    }

    s.emit(common.json);
    Ok(())
}

pub fn logout(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    profile: &str,
    forget: bool,
) -> Result<(), CliError> {
    let creds = CredentialStore::for_binary(config::BIN);

    // The cached session and any half-finished login always go; `logout`
    // that leaves a resumable attempt behind isn't a logout.
    creds.delete(&config::token_key(profile))?;
    creds.delete(&config::pending_key(profile))?;

    if forget {
        creds.delete(&config::password_key(profile))?;
        creds.delete(&config::device_key(profile))?;
        cfg.profiles.remove(profile);
        if cfg.default_profile.as_deref() == Some(profile) {
            cfg.default_profile = None;
        }
        store.save(&cfg)?;
    }

    if !common.quiet {
        eprintln!(
            "logged out of profile `{profile}`{}",
            if forget {
                " and forgot its stored credentials"
            } else {
                ""
            }
        );
    }
    Ok(())
}

pub fn set_credential(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    profile: &str,
    args: &SetCredentialArgs,
) -> Result<(), CliError> {
    let creds = CredentialStore::for_binary(config::BIN);
    let key = config::password_key(profile);
    if creds.get(&key)?.is_some() && !args.overwrite {
        return Err(CliError::Usage(format!(
            "a password is already stored for profile `{profile}` — pass --overwrite to replace it"
        )));
    }
    // Headless by contract: no prompt fallback, an explicit source is required.
    let secret = args.source.read(None)?;
    if secret.is_empty() {
        return Err(CliError::Usage("the supplied password was empty".into()));
    }
    creds.set(&key, &secret)?;

    // Make sure the profile exists, so `profiles list` shows what was just set.
    cfg.profiles.entry(profile.to_string()).or_default();
    store.save(&cfg)?;

    if !common.quiet {
        eprintln!("password stored for profile `{profile}`");
    }
    Ok(())
}

fn resolve_username(
    cfg: &Config,
    profile: &str,
    input: &LoginInput<'_>,
    common: &CommonArgs,
) -> Result<String, CliError> {
    if let Some(u) = input.username {
        return Ok(u.to_string());
    }
    if let Some(u) = cfg.profile(profile).and_then(|p| p.username.clone()) {
        return Ok(u);
    }
    if common.interactive() {
        let u = prompt_line("Robinhood username (email): ")?;
        if !u.trim().is_empty() {
            return Ok(u.trim().to_string());
        }
    }
    Err(CliError::Usage(format!(
        "no username for profile `{profile}` — pass `--username <EMAIL>` or set it with \
         `rhd profiles add {profile} --username <EMAIL>`"
    )))
}

/// Get the password, storing it when it arrives from an explicit source so a
/// later `--code` resume can re-present it without asking again.
fn resolve_password(
    creds: &CredentialStore,
    profile: &str,
    input: &LoginInput<'_>,
    common: &CommonArgs,
) -> Result<Secret, CliError> {
    let key = config::password_key(profile);
    let explicit = input.base.source.stdin || input.base.source.from_env.is_some();

    if explicit {
        let secret = input.base.source.read(None)?;
        if secret.is_empty() {
            return Err(CliError::Usage("the supplied password was empty".into()));
        }
        creds.set(&key, &secret)?;
        return Ok(secret);
    }

    if let Some(existing) = creds.get(&key)? {
        return Ok(existing);
    }

    if input.base.non_interactive || !common.interactive() {
        return Err(CliError::Usage(format!(
            "no password stored for profile `{profile}` — supply one with \
             `rhd auth login --profile {profile} --stdin` or \
             `rhd auth set-credential --profile {profile} --stdin`"
        )));
    }

    let secret = Secret::prompt("Robinhood password")?;
    if secret.is_empty() {
        return Err(CliError::Usage("the supplied password was empty".into()));
    }
    creds.set(&key, &secret)?;
    Ok(secret)
}

fn prompt_line(label: &str) -> Result<String, CliError> {
    use std::io::{BufRead, Write};
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("reading input: {e}")))?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_parked_attempt_serializes_without_a_secret() {
        let parked = Parked {
            flow: crate::client::Flow::Workflow,
            kind: ChallengeKind::Prompt,
            workflow_id: Some("wf-1".into()),
            machine_id: Some("m-1".into()),
            challenge_id: Some("c-1".into()),
            device_token: "dev-1".into(),
        };
        let raw = serde_json::to_string(&parked).unwrap();
        assert!(!raw.to_lowercase().contains("password"));
        assert!(raw.contains("dev-1"));
    }

    #[test]
    fn status_reports_the_family_dto() {
        let mut s = AuthStatus::new(true, true, AuthMethod::Password);
        s.username = Some("user@example.com".into());
        s.credential_in_keychain = Some(true);
        let v = s.to_json();
        assert_eq!(v["schema"], "auth-status/v1");
        assert_eq!(v["method"], "password");
        assert_eq!(v["required"], true);
        // session_valid stays absent unless --verify spent a request on it.
        assert!(v.get("session_valid").is_none());
    }

    /// The bookkeeping both logins share adopts a sole account as the
    /// profile default; with several — or with one row from a listing that
    /// had more pages — it must not guess, since guessing means reading the
    /// wrong account.
    #[test]
    fn a_sole_account_becomes_the_default() {
        let one = [json!({"account_number": "SAMPLE01"})];
        let mut cfg = Config::default();
        note_login(&mut cfg, "primary", Some("user@example.com"), &one, true);
        let p = cfg.profile("primary").unwrap();
        assert_eq!(p.account.as_deref(), Some("SAMPLE01"));
        assert_eq!(p.username.as_deref(), Some("user@example.com"));
        assert_eq!(cfg.default_profile.as_deref(), Some("primary"));

        let many = [
            json!({"account_number": "SAMPLE01"}),
            json!({"account_number": "SAMPLE02"}),
        ];
        let mut cfg = Config::default();
        note_login(&mut cfg, "primary", None, &many, true);
        assert_eq!(
            cfg.profile("primary").unwrap().account,
            None,
            "must not guess between several accounts"
        );

        let mut cfg = Config::default();
        note_login(&mut cfg, "primary", None, &one, false);
        assert_eq!(
            cfg.profile("primary").unwrap().account,
            None,
            "one row of a paged listing is not a one-account login"
        );
    }

    /// An import names no username, so it keeps the configured one; an
    /// existing default profile or account is never replaced.
    #[test]
    fn a_login_keeps_what_is_already_configured() {
        let mut cfg = Config::default();
        note_login(&mut cfg, "spouse", Some("user@example.com"), &[], true);
        cfg.profiles.get_mut("spouse").unwrap().account = Some("SAMPLE02".into());

        let one = [json!({"account_number": "SAMPLE01"})];
        note_login(&mut cfg, "spouse", None, &one, true);
        note_login(&mut cfg, "primary", None, &one, true);

        let spouse = cfg.profile("spouse").unwrap();
        assert_eq!(spouse.username.as_deref(), Some("user@example.com"));
        assert_eq!(spouse.account.as_deref(), Some("SAMPLE02"));
        assert_eq!(cfg.default_profile.as_deref(), Some("spouse"));
    }

    fn report(shape: capture::Shape, renewable: bool, device: bool) -> SessionImport {
        SessionImport {
            profile: "primary".into(),
            source: Source::Stdin,
            shape,
            accounts_visible: 4,
            more_accounts: false,
            renewable,
            expires_at: Some("2026-11-03T00:00:00Z".into()),
            device_token: device,
            read_only_token: renewable,
        }
    }

    /// The import report is the owner's only view of what was stored, so
    /// it has to say whether the session renews and when it ends — and it
    /// must never carry a token.
    #[test]
    fn the_import_report_says_whether_the_session_renews() {
        use capture::Shape::{Bearer, WebAuthState};
        let web = report(WebAuthState, true, true).lines().join("\n");
        assert!(web.contains("(web:auth_state)"), "{web}");
        assert!(web.contains("renews unattended"), "{web}");
        assert!(web.contains("2026-11-03T00:00:00Z"), "{web}");
        assert!(!web.contains("UNVERIFIED"), "{web}");
        assert!(web.contains("do not click Log out"), "{web}");

        let no_device = report(WebAuthState, true, false).lines().join("\n");
        assert!(no_device.contains("present none"), "{no_device}");

        let bearer = report(Bearer, false, false).lines().join("\n");
        assert!(bearer.contains("(bearer token)"), "{bearer}");
        assert!(bearer.contains("cannot renew"), "{bearer}");
        assert!(bearer.contains("until 2026-11-03T00:00:00Z"), "{bearer}");

        let v = serde_json::to_value(report(Bearer, false, false)).unwrap();
        assert_eq!(v["source"], "stdin");
        assert_eq!(v["shape"], "bearer");
        assert_eq!(v["renewable"], false);
        assert_eq!(
            serde_json::to_value(report(WebAuthState, true, true)).unwrap()["shape"],
            "web_auth_state"
        );
        for key in ["access_token", "refresh_token", "token"] {
            assert!(v.get(key).is_none(), "the DTO must not carry `{key}`");
        }
    }

    /// A browser sign-in's report says the window is gone (there is no tab
    /// left to log out of), and its no-device remedy is the browser again.
    #[test]
    fn the_browser_report_says_rhd_holds_the_only_copy() {
        let mut r = report(capture::Shape::WebAuthState, true, false);
        r.source = Source::Browser;
        let text = r.lines().join("\n");
        assert!(
            text.contains("stored the browser sign-in's session"),
            "{text}"
        );
        assert!(text.contains("renews unattended"), "{text}");
        assert!(text.contains("rhd auth login --browser"), "{text}");
        assert!(text.contains("only copy"), "{text}");
        assert!(!text.contains("Console snippet"), "{text}");
        assert!(!text.contains("close the robinhood.com tab"), "{text}");
        assert_eq!(serde_json::to_value(&r).unwrap()["source"], "browser");
    }

    /// The proving read's refusal names where the session came from.
    #[test]
    fn a_refused_browser_session_says_it_came_from_the_browser() {
        let rejected = ReadFailure::Rejected {
            status: 401,
            detail: None,
        };
        let msg = unproven(rejected, capture::Shape::WebAuthState, Source::Browser).to_string();
        assert!(
            msg.contains("read the browser sign-in's session as the web:auth_state JSON"),
            "{msg}"
        );
        assert!(!msg.contains("stdin"), "{msg}");
    }

    /// No Chrome is the one browser failure with a fallback to name.
    #[test]
    fn no_chrome_points_at_the_devtools_fallback() {
        let err = browser_failed(BrowserError::ChromeNotFound(
            "no Chrome found — install Google Chrome, or set RHD_CHROME to a Chrome binary".into(),
        ));
        assert_eq!(err.exit_code(), 1);
        let msg = err.to_string();
        assert!(msg.contains("RHD_CHROME"), "{msg}");
        assert!(msg.contains("--session-stdin"), "{msg}");

        let timed_out = browser_failed(BrowserError::TimedOut("timed out".into()));
        assert_eq!(timed_out.exit_code(), 3);
        assert_eq!(timed_out.to_string(), "timed out");
    }

    /// A 401 on the proving read stays an auth failure (exit 3), names the
    /// shape stdin was read as, says nothing was stored, and does not send
    /// the owner back to the password login.
    #[test]
    fn a_refused_import_names_the_shape_and_stores_nothing() {
        let rejected = ReadFailure::Rejected {
            status: 401,
            detail: Some("Incorrect authentication credentials.".into()),
        };
        let err = unproven(rejected, capture::Shape::Bearer, Source::Stdin);
        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(msg.contains("HTTP 401"), "{msg}");
        assert!(
            msg.contains("Incorrect authentication credentials."),
            "{msg}"
        );
        assert!(msg.contains("read stdin as a bearer token"), "{msg}");
        assert!(msg.contains("nothing was stored"), "{msg}");
        assert!(!msg.contains("rhd auth login`"), "{msg}");

        let html = ReadFailure::Html {
            status: 200,
            url: "https://api.robinhood.com/accounts/".into(),
        };
        let err = unproven(html, capture::Shape::WebAuthState, Source::Stdin);
        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(msg.contains("the web:auth_state JSON"), "{msg}");
        assert!(!msg.contains("rhd auth login`"), "{msg}");

        for failure in [
            ReadFailure::Throttled {
                retry_after: Some("51".into()),
            },
            ReadFailure::NotFound {
                url: "https://api.robinhood.com/accounts/".into(),
            },
            ReadFailure::Upstream("Robinhood returned HTTP 503".into()),
        ] {
            let err = unproven(failure, capture::Shape::Bearer, Source::Stdin);
            assert_eq!(err.exit_code(), 5, "{err}");
            assert!(err.to_string().contains("nothing was stored"), "{err}");
        }
    }

    #[test]
    fn the_proving_read_must_be_the_collection_envelope() {
        let page = json!({"next": null, "results": [{"account_number": "SAMPLE01"}]});
        let (rows, more) = accounts_page(&page).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!more);

        let paged = json!({"next": "https://api.robinhood.com/accounts/?cursor=x", "results": []});
        assert!(accounts_page(&paged).unwrap().1);

        // A 200 that is not the listing proves nothing.
        assert!(accounts_page(&json!({"detail": "ok"})).is_none());
        assert!(accounts_page(&Value::Null).is_none());
    }
}
