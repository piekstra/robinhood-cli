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
//! - **A window's tokens do not stay.** `--browser` runs Chrome in a profile kept per
//!   login, so a re-login often asks for less. The page keeps the tokens in
//!   `localStorage`, so [`browser_launch`] turns on `clear_site_storage`. The capture
//!   only reads ([`capture::SESSION_EXPRESSION`]), and the tab closes only on a session
//!   Robinhood accepts ([`confirm_candidate`]).
//! - **The kept profile is a full Chrome profile:** Robinhood's cookies, browsing
//!   history with full URLs, query strings included, and the HTTP cache. Chrome's
//!   cookie encryption does not cover anything but the cookies, so the directory's `0700` mode is their only protection, and
//!   ordinary backups usually include it. On Linux with no desktop keyring Chrome
//!   encrypts the cookies with a fixed, publicly known key, so there the session
//!   cookie has only `0700` too. It stays on disk until `auth logout` or `profiles remove`
//!   removes it ([`finish_logout`]), after a failed sign-in too
//!   ([`through_the_window`]).

use std::sync::Mutex;

use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserError, Confirm, Launch};
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
    // Before anything is spent: an approval or a code cannot be had twice.
    RefreshLock::for_binary(config::BIN)?.before_signin()?;
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

    // The device token first: it needs no lock, and it is what keeps the next
    // attempt from presenting as a new device if the session cannot be stored.
    creds.set(
        &config::device_key(profile),
        &Secret::new(device_token.to_string()),
    )?;
    store_session(creds, profile, &tokens)?;

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

/// `rhd auth login --browser`: the owner signs in on robinhood.com in the
/// Chrome profile `rhd` keeps for this login, and the session the web app
/// stores is read out of it (docs/api.md §2.8).
///
/// The capture answers with the `web:auth_state` JSON the `--session-stdin`
/// Console snippet copies, so from there it takes the same road:
/// [`capture::parse`], one proving read, the same keychain item. The crate
/// closes the tab the moment the session is read, so the web app cannot
/// renew (and so rotate) the refresh token `rhd` is about to store, then
/// stops Chrome; its profile stays for the next sign-in, unless
/// `--fresh-profile` asked for a scratch one.
pub fn browser_login(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: Config,
    profile: &str,
    fresh_profile: bool,
) -> Result<(), CliError> {
    let launch = browser_launch(profile, fresh_profile, common.quiet)?;
    // Before the window: a sign-in the owner has finished is not thrown away.
    RefreshLock::for_binary(config::BIN)?.before_signin()?;
    let refused = Mutex::new(None);
    let capture = capture::browser_capture()?.confirm(move |candidate| {
        confirm_candidate(
            candidate,
            crate::client::now_unix(),
            &refused,
            prove_session,
        )
    });
    through_the_window(
        profile,
        fresh_profile,
        || pk_cli_browser::capture(launch, &capture, pk_cli_browser::DEFAULT_TIMEOUT),
        |raw| import(common, store, cfg, profile, &raw, Source::Browser),
    )
}

/// A browser sign-in from the window on, with every way it can fail in one
/// place, so a new one cannot miss [`failed_sign_in`]: the window's own ending,
/// the confirm hook's, the read after it and the keychain write.
///
/// Only four failures skip the note, because they end the sign-in before this
/// Chrome uses the profile: no Chrome, which points at the DevTools fallback
/// instead, a malformed launch, and a profile refused for repair or already in use,
/// whose own messages name the path and the fix.
fn through_the_window(
    profile: &str,
    fresh_profile: bool,
    capture: impl FnOnce() -> Result<pk_cli_browser::Captured, BrowserError>,
    finish: impl FnOnce(Secret) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let captured = match capture() {
        Err(BrowserError::ChromeNotFound(msg)) => {
            return Err(CliError::Other(format!(
                "{msg}. Without Chrome, import a session from your own browser instead: `rhd \
                 auth login --help` walks through `--session-stdin`"
            )))
        }
        Err(
            e @ (BrowserError::Invalid(_)
            | BrowserError::Profile(_)
            | BrowserError::ProfileInUse(_)),
        ) => return Err(e.into()),
        other => other,
    };
    captured
        .map_err(CliError::from)
        .and_then(|captured| finish(session_text(&captured)?))
        .map_err(|e| failed_sign_in(e, profile, fresh_profile))
}

/// The Chrome launch for `profile`'s sign-in, in a Chrome profile of its own,
/// so one household login's sign-in never opens already signed in as another.
///
/// A login profile whose name a Chrome profile cannot carry (one made before
/// the rule, or named by `--profile` or `RHD_PROFILE` on a fresh install) is
/// refused here, before Chrome starts: the name is checked and never rewritten,
/// so it can never land on another login's profile. `--fresh-profile` needs no
/// name, so it still signs such a login in.
///
/// The page keeps the session's tokens in `localStorage`, and a refresh token left on
/// disk could be presented by a later window after `rhd` has rotated it. So the kept
/// profile keeps its cookies, the `device_id` among them, and never its site storage.
fn browser_launch(profile: &str, fresh_profile: bool, quiet: bool) -> Result<Launch, CliError> {
    let launch = Launch::new(config::BIN)
        .url(capture::LOGIN_URL)
        .clear_site_storage(true)
        .quiet(quiet);
    if fresh_profile {
        return Ok(launch.fresh_profile(true).login_hint(format!(
            "rhd auth login --browser --profile {profile} --fresh-profile"
        )));
    }
    if !config::profile_name_ok(profile) {
        return Err(CliError::Usage(format!(
            "login profile `{profile}` cannot keep a browser profile: the name must be 1 to 64 \
             ASCII letters, digits, `-` or `_`. Sign in once with `--fresh-profile`, or use a \
             profile with such a name (`rhd profiles add <NAME>`)"
        )));
    }
    Ok(launch
        .profile_name(profile)
        .login_hint(format!("rhd auth login --browser --profile {profile}")))
}

/// Whether the session in the window is one to take, which closes the tab.
///
/// Site storage goes before Chrome starts ([`browser_launch`]), so what the page
/// holds was written in this window. Taking a session Robinhood will not honour would
/// still close the tab before the web app could ask the owner to sign in. So a session
/// that does not parse, is past the point `rhd` would renew it, or that Robinhood
/// refuses keeps the tab open.
///
/// That point is [`Tokens::is_expired_at`], `rhd`'s own renewal rule, not the
/// token's bare expiry, so a session is never stored already due for renewal.
///
/// A token Robinhood refused is remembered and not sent again (one attempt, no
/// loops), so a tab sitting on a dead session costs one read rather than one
/// per poll. A read that cannot decide ends the wait and takes nothing: a
/// throttle, Robinhood down, or an answer that is not the accounts list.
fn confirm_candidate(
    candidate: &pk_cli_browser::Captured,
    now: u64,
    refused: &Mutex<Option<Secret>>,
    prove: impl FnOnce(&str) -> Result<Value, ReadFailure>,
) -> Confirm {
    const DEAD: &str =
        "Robinhood refused the session this window holds, and no new sign-in has finished";
    let raw = match session_text(candidate) {
        Ok(raw) => raw,
        Err(e) => return Confirm::NotYet(e.to_string()),
    };
    let Captured { shape, tokens } = match capture::parse(raw.expose(), now, Source::Browser) {
        Ok(captured) => captured,
        Err(e) => return Confirm::NotYet(e.to_string()),
    };
    if tokens.is_expired_at(now) {
        return Confirm::NotYet(
            "the session this window holds has expired, and no new sign-in has finished".into(),
        );
    }
    let mut refused = refused.lock().unwrap_or_else(|e| e.into_inner());
    if refused
        .as_ref()
        .is_some_and(|token| token.expose() == tokens.access_token)
    {
        return Confirm::NotYet(DEAD.into());
    }
    match prove(&tokens.access_token) {
        Ok(page) if accounts_page(&page).is_some() => Confirm::Ready,
        Ok(_) => Confirm::Fail(unproven(no_accounts_list(), shape, Source::Browser)),
        Err(failure) if failure.is_auth() => {
            *refused = Some(Secret::new(tokens.access_token.clone()));
            Confirm::NotYet(DEAD.into())
        }
        Err(failure) => Confirm::Fail(unproven(failure, shape, Source::Browser)),
    }
}

/// The session a capture read, as `--session-stdin` would have it.
fn session_text(captured: &pk_cli_browser::Captured) -> Result<Secret, CliError> {
    let value = captured.value().ok_or_else(|| {
        CliError::Other("the browser capture came back without the session".into())
    })?;
    Ok(capture::fill_device_token(
        value.expose(),
        captured.cookie(capture::DEVICE_COOKIE).map(Secret::expose),
    ))
}

/// The confirm hook's read, on its own client: the hook has to be `Sync` and
/// [`Rh`] is not. Bounded by that client's 60 s timeout.
fn prove_session(access_token: &str) -> Result<Value, ReadFailure> {
    let rh = Rh::new().map_err(|e| ReadFailure::Upstream(e.to_string()))?;
    read_accounts(&rh, access_token)
}

/// The one authenticated read that proves a session. `probe`, not `get`: a
/// refusal here must name the session, not send the owner back to the password
/// login (see [`unproven`]).
fn read_accounts(rh: &Rh, access_token: &str) -> Result<Value, ReadFailure> {
    rh.probe(
        access_token,
        &rh.url(crate::commands::accounts::PATH),
        &crate::commands::accounts::all_accounts_query(),
    )
}

/// A failed sign-in, saying that the kept profile stays with whatever the
/// sign-in got as far as, which can be a live session: the owner may move on and
/// never log out. A `--fresh-profile` sign-in has already removed its scratch one,
/// and the crate keeps a profile only on unix. The exit code does not change.
fn failed_sign_in(error: CliError, profile: &str, fresh_profile: bool) -> CliError {
    if fresh_profile || !cfg!(unix) {
        return error;
    }
    reworded(error, |m| {
        format!(
            "{}. The browser profile stays on disk with what that window left in it, which can \
             be a live session; once no window is using it, `rhd auth logout --profile \
             {profile}` removes it and clears any stored session with it, and `--fresh-profile` \
             signs in without it.",
            m.trim_end_matches('.')
        )
    })
}

/// The same failure, with the same exit code, saying something else.
fn reworded(error: CliError, say: impl FnOnce(String) -> String) -> CliError {
    match error {
        CliError::Usage(m) => CliError::Usage(say(m)),
        CliError::Auth(m) => CliError::Auth(say(m)),
        CliError::NotFound(m) => CliError::NotFound(say(m)),
        CliError::Upstream(m) => CliError::Upstream(say(m)),
        CliError::ConfirmationRequired(m) => CliError::ConfirmationRequired(say(m)),
        CliError::Keychain(m) => CliError::Keychain(say(m)),
        CliError::Other(m) => CliError::Other(say(m)),
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
    // Before the read: a session piped in once cannot be read again. It does not
    // wait on a busy lock, so bad input still fails at once; the store waits.
    RefreshLock::for_binary(config::BIN)?.try_hold(|| Ok(()))?;
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
    let page = read_accounts(&rh, &tokens.access_token)
        .map_err(|failure| unproven(failure, shape, source))?;
    let (visible, more) =
        accounts_page(&page).ok_or_else(|| unproven(no_accounts_list(), shape, source))?;

    let creds = CredentialStore::for_binary(config::BIN);
    store_session(&creds, profile, &tokens)?;
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
            // The window closed on capture, and its profile stays.
            Source::Browser => "the sign-in window is closed, so no browser is renewing this \
                                session; its Chrome profile, with Robinhood's cookies in it, stays \
                                on disk for the next sign-in until `rhd auth logout` removes it"
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

/// A proving read that succeeded and still proves nothing.
fn no_accounts_list() -> ReadFailure {
    ReadFailure::Upstream(
        "the accounts read answered without a `results` list, so the session is unproven".into(),
    )
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

    s.browser_profile = browser_profile_status(common.quiet, || {
        pk_cli_browser::named_profile_exists(config::BIN, profile)
    });
    s.emit(common.json);
    Ok(())
}

/// `auth status`'s browser field, for the login it reports on: whether a `--browser`
/// sign-in keeps a profile for that login here. A kept profile, not a signed-in one.
/// A name no Chrome profile can carry never had one. `auth status` works whatever
/// state the CLI is in, so a profile that needs repair is a warning and leaves the
/// field out. The check is passed in: the binary binds `named_profile_exists`, the
/// tests `named_profile_exists_in` under a temp dir.
fn browser_profile_status(
    quiet: bool,
    exists: impl FnOnce() -> Result<bool, BrowserError>,
) -> Option<bool> {
    match exists() {
        Ok(kept) => Some(kept),
        Err(BrowserError::Invalid(_)) => Some(false),
        Err(e) => {
            if !quiet {
                eprintln!("warning: {e}");
            }
            None
        }
    }
}

/// Store a session a login obtained, under the lock a renewal holds, so a
/// renewal in flight cannot overwrite it with the old session's tokens.
fn store_session(creds: &CredentialStore, profile: &str, tokens: &Tokens) -> Result<(), CliError> {
    RefreshLock::for_binary(config::BIN)?
        .store_signin(|| creds.set(&config::token_key(profile), &tokens.to_secret()))
}

/// Delete a profile's session, under the lock a renewal holds if it can be had,
/// so a renewal in flight cannot store it again after. The delete runs either
/// way: the lock must not keep a credential on the machine.
pub(crate) fn forget_session(creds: &CredentialStore, profile: &str) -> Result<(), CliError> {
    RefreshLock::forget_for_binary(config::BIN, || creds.delete(&config::token_key(profile)))
        .map(|_| ())
}

/// One keychain item of a logout or a removal. The session goes under the lock a
/// renewal holds ([`forget_session`]), the rest directly.
pub(crate) fn delete_item(
    creds: &CredentialStore,
    profile: &str,
    key: &str,
) -> Result<(), CliError> {
    if key == config::token_key(profile) {
        forget_session(creds, profile)
    } else {
        creds.delete(key).map(|_| ())
    }
}

pub fn logout(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: Result<Config, CliError>,
    profile: &str,
    forget: bool,
) -> Result<(), CliError> {
    let creds = CredentialStore::for_binary(config::BIN);
    let browser = finish_logout(
        store,
        cfg,
        profile,
        forget,
        |key| delete_item(&creds, profile, key),
        || pk_cli_browser::forget_named_profile(config::BIN, profile),
    )?;

    if !common.quiet {
        eprintln!("{}", logged_out(profile, forget, browser));
    }
    Ok(())
}

/// A logout's steps, each attempted whatever an earlier one did: one that fails
/// must not leave a session behind in the others. `true` when there was a browser
/// profile to remove. The keychain and the profile's removal are passed in, so a
/// test can fail any step and reach neither the keychain nor the owner's real
/// profile.
///
/// The one exception is the config entry with `--forget`. It goes last, and only
/// once everything else is clear: [`Config::require_profile`] refuses an unconfigured
/// name once other logins exist, so without it the retry the error asks for could
/// not find what remains. A config that cannot be parsed is passed in as the
/// failure it is: it stops no other step, and only that entry stays.
fn finish_logout(
    store: &ConfigStore,
    cfg: Result<Config, CliError>,
    profile: &str,
    forget: bool,
    mut delete: impl FnMut(&str) -> Result<(), CliError>,
    forget_browser: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<bool, CliError> {
    let mut steps = TeardownSteps::default();
    // The cached session and any half-finished login always go; `logout`
    // that leaves a resumable attempt behind isn't a logout.
    steps.session(delete(&config::token_key(profile)));
    if let Err(e) = delete(&config::pending_key(profile)) {
        steps.failed("a half-finished login", e);
    }
    if forget {
        steps.step(
            "the stored password",
            delete(&config::password_key(profile)),
        );
        steps.step("the device token", delete(&config::device_key(profile)));
    }
    let browser = steps.browser(forget_browser);
    if forget {
        const ENTRY: &str = "this login's config entry";
        match cfg {
            Err(e) => steps.failed(ENTRY, e),
            Ok(mut cfg) if steps.is_clean() => {
                cfg.profiles.remove(profile);
                if cfg.default_profile.as_deref() == Some(profile) {
                    cfg.default_profile = None;
                }
                if let Err(e) = store.save(&cfg) {
                    steps.failed(ENTRY, e);
                }
            }
            Ok(_) => steps.remains(ENTRY),
        }
    }
    let finish = format!(
        "rhd auth logout{} --profile {profile}",
        if forget { " --forget" } else { "" }
    );
    steps.report(&format!("partly logged out of `{profile}`"), &finish)?;
    Ok(browser)
}

/// What a logout or a `profiles remove` got done so far. Its steps run to the end
/// whatever fails, then [`report`](Self::report) says what is cleared and what
/// remains, with the first failure's exit code.
#[derive(Default)]
pub(crate) struct TeardownSteps {
    cleared: Vec<String>,
    remains: Vec<String>,
    reasons: Vec<String>,
    first: Option<CliError>,
    finish_when: Option<&'static str>,
}

impl TeardownSteps {
    /// The session's removal. `Upstream` is the refresh lock's: the delete has run,
    /// and what remains is a renewal in flight that can store the session again.
    pub(crate) fn session(&mut self, result: Result<(), CliError>) {
        let what = match &result {
            Err(CliError::Upstream(_)) => {
                self.finish_when = Some("In a minute, run");
                "a renewal that can store the session again"
            }
            _ => "the session",
        };
        self.step(what, result);
    }

    pub(crate) fn step(&mut self, what: &str, result: Result<(), CliError>) {
        match result {
            Ok(()) => self.cleared.push(what.to_string()),
            Err(e) => self.failed(what, e),
        }
    }

    pub(crate) fn failed(&mut self, what: &str, error: CliError) {
        self.remains(what);
        self.reasons
            .push(inner_message(&error).trim_end_matches('.').to_string());
        self.first.get_or_insert(error);
    }

    /// Something left on purpose, which fails nothing.
    pub(crate) fn remains(&mut self, what: &str) {
        self.remains.push(what.to_string());
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.first.is_none()
    }

    /// The profile's removal ([`logout_browser`]); `true` when there was one.
    pub(crate) fn browser(&mut self, forget: impl FnOnce() -> Result<bool, BrowserError>) -> bool {
        match logout_browser(forget) {
            Ok(removed) => {
                if removed {
                    self.cleared.push("the browser profile".to_string());
                }
                removed
            }
            Err(e) => {
                self.finish_when = Some(match e {
                    BrowserError::ProfileInUse(_) => "Once that window is closed, run",
                    _ => "Repair or delete that path, then run",
                });
                self.failed("the browser profile", e.into());
                false
            }
        }
    }

    pub(crate) fn report(self, title: &str, finish: &str) -> Result<(), CliError> {
        let Some(first) = self.first else {
            return Ok(());
        };
        let cleared = match self.cleared.len() {
            0 => "nothing is cleared".to_string(),
            1 => format!("{} is cleared", self.cleared[0]),
            _ => format!("{} are cleared", listed(&self.cleared)),
        };
        let remains = match self.remains.len() {
            1 => format!("only {} remains", self.remains[0]),
            _ => format!("{} remain", listed(&self.remains)),
        };
        let when = match self.reasons.len() {
            1 => self.finish_when.unwrap_or("Fix that, then run"),
            _ => "Fix those, then run",
        };
        let reasons = self.reasons.join(". ");
        let message = format!(
            "{title}: {cleared} and {remains}. {reasons}. {when} `{finish}` again to finish."
        );
        // The exit code is the first failure's. `Keychain` and `Other` share theirs,
        // and `Other` puts no "keychain error:" in front of the whole report. A held
        // refresh lock is `Upstream`: exit 5 comes only with that variant's prefix.
        Err(match first {
            CliError::Keychain(_) => CliError::Other(message),
            first => reworded(first, |_| message),
        })
    }
}

/// A failure's own message, without the prefix its `Display` puts on.
fn inner_message(error: &CliError) -> &str {
    match error {
        CliError::Usage(m)
        | CliError::Auth(m)
        | CliError::NotFound(m)
        | CliError::Upstream(m)
        | CliError::ConfirmationRequired(m)
        | CliError::Keychain(m)
        | CliError::Other(m) => m,
    }
}

fn listed(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn logged_out(profile: &str, forget: bool, browser: bool) -> String {
    format!(
        "logged out of profile `{profile}`{}{}",
        if forget {
            " and forgot its stored credentials"
        } else {
            ""
        },
        if browser {
            "; browser profile removed"
        } else {
            ""
        }
    )
}

/// The browser step of `auth logout` and `profiles remove`: `true` when there
/// was a kept profile to remove. That profile holds Robinhood's own cookies, its
/// browsing history and cache, so a logout removes it too and the next sign-in starts
/// signed out. The removal is passed in: the
/// binary binds it to
/// `forget_named_profile(BIN, name)`, the tests to `forget_named_profile_in`
/// under a temp dir, so a test never removes the owner's real profile.
///
/// A name no Chrome profile can carry is not a failure here: a launch refuses
/// it too ([`browser_launch`]), so it never had a kept profile to remove, and
/// its logout is done. Busy (`ProfileInUse`) or in need of repair (`Profile`) is
/// the caller's to report ([`TeardownSteps::browser`]).
pub(crate) fn logout_browser(
    forget: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<bool, BrowserError> {
    match forget() {
        Err(BrowserError::Invalid(_)) => Ok(false),
        other => other,
    }
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

    /// A browser sign-in's report says the window is closed (there is no tab
    /// left to log out of), what removes the kept profile, and its no-device
    /// remedy is the browser again.
    #[test]
    fn the_browser_report_says_the_window_is_closed() {
        let mut r = report(capture::Shape::WebAuthState, true, false);
        r.source = Source::Browser;
        let text = r.lines().join("\n");
        assert!(
            text.contains("stored the browser sign-in's session"),
            "{text}"
        );
        assert!(text.contains("renews unattended"), "{text}");
        assert!(text.contains("rhd auth login --browser"), "{text}");
        assert!(text.contains("window is closed"), "{text}");
        assert!(text.contains("rhd auth logout"), "{text}");
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

    /// No Chrome is the one browser failure with a fallback to name, and the
    /// others that end the sign-in before Chrome runs in the profile do not
    /// mention it staying.
    #[test]
    fn a_failure_before_chrome_runs_does_not_mention_the_profile_staying() {
        let err = through_the_window(
            "primary",
            false,
            || {
                Err(BrowserError::ChromeNotFound(
                    "no Chrome found — install Google Chrome, or set RHD_CHROME to a Chrome binary"
                        .into(),
                ))
            },
            |_| panic!("no session to store"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let msg = err.to_string();
        assert!(msg.contains("RHD_CHROME"), "{msg}");
        assert!(msg.contains("--session-stdin"), "{msg}");
        assert!(!msg.contains("stays on disk"), "{msg}");

        for error in [
            BrowserError::Invalid("dummy".into()),
            BrowserError::Profile("dummy".into()),
            BrowserError::ProfileInUse("dummy".into()),
        ] {
            let err = through_the_window(
                "primary",
                false,
                || Err(error),
                |_| panic!("no session to store"),
            )
            .unwrap_err();
            assert_eq!(err.exit_code(), 1, "{err}");
            assert_eq!(err.to_string(), "dummy");
        }
    }

    /// The failures a sign-in can end in once Chrome has run in the profile,
    /// with the exit code each must keep.
    fn window_failures() -> Vec<(BrowserError, i32)> {
        vec![
            (BrowserError::TimedOut("dummy.".into()), 3),
            (BrowserError::WindowClosed("dummy.".into()), 3),
            (BrowserError::Canceled, 1),
            (BrowserError::Launch("dummy.".into()), 1),
            (
                BrowserError::Handler(CliError::Upstream("dummy.".into())),
                5,
            ),
            (BrowserError::Handler(CliError::Auth("dummy.".into())), 3),
        ]
    }

    fn assert_says_it_stays(err: &CliError) {
        if cfg!(unix) {
            let message = err.to_string();
            assert!(
                message.contains("browser profile stays on disk"),
                "{message}"
            );
            assert!(
                message.contains("`rhd auth logout --profile dummy-one`"),
                "{message}"
            );
        }
    }

    /// Every way a sign-in can fail with Chrome in the kept profile says so,
    /// whichever step failed, and keeps its exit code. A scratch profile is
    /// already gone, so it says nothing.
    #[test]
    fn every_failed_sign_in_says_the_kept_profile_stays() {
        for (error, code) in window_failures() {
            let err = through_the_window(
                "dummy-one",
                false,
                || Err(error),
                |_| panic!("no session to store"),
            )
            .unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
        }
        for (error, code) in window_failures() {
            let err = through_the_window(
                "dummy-one",
                true,
                || Err(error),
                |_| panic!("no session to store"),
            )
            .unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert!(!err.to_string().contains("stays on disk"), "{err}");
        }
    }

    /// After the capture the session is read and stored, and a live session can
    /// be left in the profile if that fails.
    #[test]
    fn a_failure_after_the_capture_says_the_kept_profile_stays() {
        for (failure, code) in [
            (CliError::Keychain("dummy: could not write".into()), 1),
            (CliError::Upstream("dummy outage".into()), 5),
            (CliError::Auth("dummy refusal".into()), 3),
        ] {
            let captured = held(&token_until(NOW + 3600));
            let err = through_the_window("dummy-one", false, || Ok(captured), |_| Err(failure))
                .unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
        }
        let empty = pk_cli_browser::Captured::for_test("Robinhood", capture::WEB_HOST).build();
        let err = through_the_window(
            "dummy-one",
            false,
            || Ok(empty),
            |_| panic!("nothing was read"),
        )
        .unwrap_err();
        assert_says_it_stays(&err);

        let captured = held(&token_until(NOW + 3600));
        let err = through_the_window(
            "dummy-one",
            true,
            || Ok(captured),
            |_| Err(CliError::Keychain("dummy: could not write".into())),
        )
        .unwrap_err();
        assert!(!err.to_string().contains("stays on disk"), "{err}");

        let captured = held(&token_until(NOW + 3600));
        through_the_window("dummy-one", false, || Ok(captured), |_| Ok(())).unwrap();
    }

    /// The note changes the message and never the exit code.
    #[test]
    fn the_note_keeps_every_exit_code() {
        for (error, code) in [
            (CliError::Usage("dummy.".into()), 2),
            (CliError::Auth("dummy.".into()), 3),
            (CliError::NotFound("dummy.".into()), 4),
            (CliError::Upstream("dummy.".into()), 5),
            (CliError::ConfirmationRequired("dummy.".into()), 6),
            (CliError::Keychain("dummy.".into()), 1),
            (CliError::Other("dummy.".into()), 1),
        ] {
            let err = failed_sign_in(error, "dummy-one", false);
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
            if cfg!(unix) {
                assert!(err.to_string().contains("dummy. The browser"), "{err}");
            }
        }
    }

    /// The hook against real answers: a throttle or an outage ends the wait
    /// rather than loop on it, a refusal keeps the tab open, and only an accounts
    /// list closes it. Neither of the first two is remembered as a refused token.
    #[test]
    fn a_read_that_cannot_decide_ends_the_wait_and_accepts_nothing() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        const URL: &str = "https://api.robinhood.com/accounts/";
        let read = |status: u16, body: &str| crate::client::classify(status, URL, None, body);
        let list = r#"{"results":[]}"#;
        let token = token_until(NOW + 3600);

        for (status, body) in [
            (429, PAGE),
            (429, "{}"),
            (429, list),
            (500, "{}"),
            (502, "bad gateway"),
            (503, PAGE),
            (503, list),
            (200, ""),
            (200, "null"),
            (200, "{}"),
            (200, "{nope"),
            (200, r#"{"results":null}"#),
        ] {
            let refused = Mutex::new(None);
            let answer = confirm_candidate(&held(&token), NOW, &refused, |_| read(status, body));
            match answer {
                Confirm::Fail(e) => assert_eq!(e.exit_code(), 5, "{status} {body}: {e}"),
                other => panic!("{status} {body} must end the wait: {other:?}"),
            }
            assert!(refused.lock().unwrap().is_none(), "{status} {body}");
        }

        for (status, body) in [(401, "{}"), (403, "{}"), (403, PAGE), (200, PAGE)] {
            let refused = Mutex::new(None);
            let answer = confirm_candidate(&held(&token), NOW, &refused, |_| read(status, body));
            assert!(
                matches!(answer, Confirm::NotYet(_)),
                "{status} {body}: {answer:?}"
            );
            assert!(refused.lock().unwrap().is_some(), "{status} {body}");
        }

        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token), NOW, &refused, |_| read(200, list));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
    }

    const NOW: u64 = 1_800_000_000;

    /// A session the kept profile holds, as the capture would read it.
    fn held(access_token: &str) -> pk_cli_browser::Captured {
        let mut session: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/web_auth_state.json")).unwrap();
        session["access_token"] = json!(access_token);
        pk_cli_browser::Captured::for_test("Robinhood", capture::WEB_HOST)
            .value(session.to_string())
            .build()
    }

    fn token_until(exp: u64) -> String {
        capture::tests::jwt(&json!({ "exp": exp }))
    }

    /// What the kept profile changes: a session can still be there as the page
    /// opens. `capture::parse` would refuse an expired one, but only after the
    /// tab had closed, on every later run. It keeps the tab open now, with no
    /// read.
    #[test]
    fn an_expired_session_in_the_kept_profile_keeps_the_tab_open() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token_until(NOW - 1)), NOW, &refused, |_| {
            panic!("an expired session must not reach Robinhood")
        });
        match answer {
            Confirm::NotYet(reason) => assert!(reason.contains("expired"), "{reason}"),
            other => panic!("must keep waiting: {other:?}"),
        }
    }

    /// Inside the minute before expiry `rhd` would renew it at once, so such a
    /// token is never read, let alone taken.
    #[test]
    fn a_token_due_for_renewal_is_not_taken() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token_until(NOW + 60)), NOW, &refused, |_| {
            panic!("a token inside the renewal window must not reach Robinhood")
        });
        assert!(matches!(answer, Confirm::NotYet(_)), "{answer:?}");
    }

    #[test]
    fn a_session_robinhood_accepts_closes_the_tab() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token_until(NOW + 3600)), NOW, &refused, |_| {
            Ok(json!({ "results": [] }))
        });
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
    }

    /// A live-looking session Robinhood refuses keeps the tab open for the
    /// owner to sign in, and is read once however many polls see it. The
    /// session that replaces it is read.
    #[test]
    fn a_refused_session_waits_and_is_not_sent_again() {
        use std::cell::Cell;
        let reads = Cell::new(0);
        let refused = Mutex::new(None);
        let dead = token_until(NOW + 3600);
        for _ in 0..3 {
            let answer = confirm_candidate(&held(&dead), NOW, &refused, |_| {
                reads.set(reads.get() + 1);
                Err(ReadFailure::Rejected {
                    status: 401,
                    detail: None,
                })
            });
            match answer {
                Confirm::NotYet(reason) => assert!(reason.contains("refused"), "{reason}"),
                other => panic!("must keep waiting: {other:?}"),
            }
        }
        assert_eq!(reads.get(), 1, "the dead token was sent again");

        let answer = confirm_candidate(&held(&token_until(NOW + 3601)), NOW, &refused, |_| {
            reads.set(reads.get() + 1);
            Ok(json!({ "results": [] }))
        });
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn a_failure_waiting_will_not_fix_ends_the_wait() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token_until(NOW + 3600)), NOW, &refused, |_| {
            Err(ReadFailure::Throttled { retry_after: None })
        });
        match answer {
            Confirm::Fail(e) => assert_eq!(e.exit_code(), 5),
            other => panic!("must end the wait: {other:?}"),
        }
    }

    #[test]
    fn a_window_with_nothing_readable_keeps_waiting() {
        let refused = Mutex::new(None);
        let none = pk_cli_browser::Captured::for_test("Robinhood", capture::WEB_HOST).build();
        let junk = pk_cli_browser::Captured::for_test("Robinhood", capture::WEB_HOST)
            .value("not a session")
            .build();
        for candidate in [none, junk] {
            let answer =
                confirm_candidate(&candidate, NOW, &refused, |_| panic!("nothing to read yet"));
            assert!(matches!(answer, Confirm::NotYet(_)), "{answer:?}");
        }
    }

    fn kept_dir(root: &std::path::Path, name: &str) -> std::path::PathBuf {
        root.join(format!("piekstra.{}", config::BIN))
            .join(format!("browser-profile-{name}"))
    }

    /// A script that stands in for Chrome: it reports a debug port, marks the
    /// profile it was given, writes to its site storage as a page would and sleeps
    /// until stopped. It is what a launch runs in these tests, so the real profile
    /// selection, lock and removals are exercised and no Chrome starts.
    #[cfg(unix)]
    fn stand_in_chrome(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("stand-in-chrome");
        std::fs::write(
            &path,
            "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --user-data-dir=*) \
             d=\"${a#--user-data-dir=}\";; esac; done\n: > \"$d/stand-in-ran\"\n\
             mkdir -p \"$d/Default/Local Storage\"\n\
             : > \"$d/Default/Local Storage/from-this-run\"\n\
             printf '1\\n/devtools/browser/dummy\\n' > \"$d/DevToolsActivePort\"\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// What `rhd` builds for a sign-in, held open under `root`.
    #[cfg(unix)]
    fn signing_in(
        root: &std::path::Path,
        chrome: &std::path::Path,
        name: &str,
        fresh: bool,
    ) -> Result<pk_cli_browser::Browser, BrowserError> {
        browser_launch(name, fresh, true)
            .unwrap()
            .profile_root(root)
            .chrome(chrome)
            .ctrl_c(false)
            .spawn()
    }

    /// The reason the named API exists: two logins run in two profiles, and
    /// logging out of one leaves the other, with what it holds.
    #[cfg(unix)]
    #[test]
    fn two_logins_keep_separate_profiles_and_logout_leaves_the_other() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        for name in ["dummy-one", "dummy-two"] {
            drop(signing_in(root.path(), &chrome, name, false).unwrap());
        }
        let one = kept_dir(root.path(), "dummy-one");
        let two = kept_dir(root.path(), "dummy-two");
        assert!(one.join("stand-in-ran").exists());
        assert!(two.join("stand-in-ran").exists());
        assert_ne!(one, two);
        assert!(
            !root.path().join("piekstra.rhd/browser-profile").exists(),
            "a named login must not use the unnamed profile"
        );

        let forget =
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "dummy-one");
        assert!(logout_browser(forget).unwrap());
        assert!(!one.exists());
        assert!(
            two.join("stand-in-ran").exists(),
            "the other login's profile must stay"
        );
        // Nothing left to remove is still a logout.
        assert!(!logout_browser(forget).unwrap());
    }

    /// Names that differ only in case are separate logins, and keep separate
    /// profiles where the filesystem folds case.
    #[cfg(unix)]
    #[test]
    fn names_that_differ_only_in_case_keep_separate_profiles() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        for name in ["Dummy", "dummy"] {
            drop(signing_in(root.path(), &chrome, name, false).unwrap());
        }
        let parent = root.path().join("piekstra.rhd");
        assert!(parent.join("browser-profile-+dummy/stand-in-ran").exists());
        assert!(parent.join("browser-profile-dummy/stand-in-ran").exists());
        let forget = || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "Dummy");
        assert!(logout_browser(forget).unwrap());
        assert!(!parent.join("browser-profile-+dummy").exists());
        assert!(parent.join("browser-profile-dummy/stand-in-ran").exists());
    }

    /// What an earlier run left in this login's site storage is gone before Chrome
    /// starts, what this run wrote is gone once it has stopped, and its cookies stay.
    /// Another login's profile is not touched.
    #[cfg(unix)]
    #[test]
    fn a_kept_profile_keeps_its_cookies_and_never_its_site_storage() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        drop(signing_in(root.path(), &chrome, "dummy-one", false).unwrap());
        let default = kept_dir(root.path(), "dummy-one").join("Default");
        let left_behind = default.join("Local Storage/leveldb");
        std::fs::create_dir_all(&left_behind).unwrap();
        std::fs::write(left_behind.join("000003.log"), "dummy").unwrap();
        std::fs::write(default.join("Cookies"), "dummy").unwrap();
        let other = kept_dir(root.path(), "dummy-two").join("Default/Local Storage");
        std::fs::create_dir_all(&other).unwrap();

        let running = signing_in(root.path(), &chrome, "dummy-one", false).unwrap();
        assert!(!left_behind.exists(), "cleared before Chrome starts");
        assert!(default.join("Local Storage/from-this-run").exists());
        drop(running);
        assert!(!default.join("Local Storage").exists(), "and once it stops");
        assert!(default.join("Cookies").exists());
        assert!(other.exists());
    }

    /// `auth status` reports on the login it was asked about, not on any other's. A
    /// path that needs repair is a warning that leaves the field out, never a failed
    /// status, and a name that cannot carry a profile never had one.
    #[cfg(unix)]
    #[test]
    fn auth_status_reports_the_active_logins_kept_profile() {
        let root = tempfile::tempdir().unwrap();
        let field = |name: &str| {
            browser_profile_status(true, || {
                pk_cli_browser::named_profile_exists_in(root.path(), config::BIN, name)
            })
        };
        assert_eq!(field("dummy-one"), Some(false));

        std::fs::create_dir_all(kept_dir(root.path(), "dummy-one")).unwrap();
        assert_eq!(field("dummy-one"), Some(true));
        assert_eq!(field("dummy-two"), Some(false));
        assert_eq!(field("has.dot"), Some(false));
        let mut status = AuthStatus::new(true, false, AuthMethod::BrowserSession);
        status.browser_profile = field("dummy-one");
        assert_eq!(status.to_json()["browser_profile"], true);

        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), kept_dir(root.path(), "dummy-two")).unwrap();
        assert_eq!(field("dummy-two"), None);
        status.browser_profile = field("dummy-two");
        assert!(status.to_json().get("browser_profile").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_fresh_profile_leaves_the_kept_one_alone() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        drop(signing_in(root.path(), &chrome, "dummy-one", true).unwrap());
        assert!(!kept_dir(root.path(), "dummy-one").exists());
    }

    /// A profile a sign-in is using is refused with the crate's message, exit
    /// 1, and left alone, while another login's is not held up by it.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_profile_a_sign_in_is_using() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        let holding = signing_in(root.path(), &chrome, "dummy-one", false).unwrap();
        drop(signing_in(root.path(), &chrome, "dummy-two", false).unwrap());

        let again = signing_in(root.path(), &chrome, "dummy-one", false).unwrap_err();
        assert!(matches!(again, BrowserError::ProfileInUse(_)), "{again}");

        let forget = |name| pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, name);
        let err = logout_browser(|| forget("dummy-one")).unwrap_err();
        assert!(matches!(err, BrowserError::ProfileInUse(_)), "{err}");
        assert!(err.to_string().contains("log out again"), "{err}");
        assert!(kept_dir(root.path(), "dummy-one").exists());
        assert!(logout_browser(|| forget("dummy-two")).unwrap());

        drop(holding);
        assert!(logout_browser(|| forget("dummy-one")).unwrap());
        assert!(!kept_dir(root.path(), "dummy-one").exists());
    }

    /// A profile that needs repair is refused, not followed: a symlink's
    /// target survives the logout's refusal.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_profile_that_needs_repair() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let profile = kept_dir(root.path(), "dummy-one");
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), &profile).unwrap();
        let forget =
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "dummy-one");
        let err = logout_browser(forget).unwrap_err();
        assert!(matches!(err, BrowserError::Profile(_)), "{err}");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(elsewhere.path().exists());
    }

    /// A name a Chrome profile cannot carry is refused by the login, exit 2
    /// naming the rule and the way round it, and is never mapped onto another
    /// login's profile. `--fresh-profile` needs no name, so it still gets in.
    #[test]
    fn a_name_no_browser_profile_can_carry_is_refused_not_mapped() {
        for name in ["has.dot", "has space", "a/b", "", &"a".repeat(65)] {
            let err = browser_launch(name, false, true).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{name:?}: {err}");
            let msg = err.to_string();
            assert!(msg.contains("1 to 64"), "{msg}");
            assert!(msg.contains("--fresh-profile"), "{msg}");
            assert!(browser_launch(name, true, true).is_ok(), "{name:?}");
        }
    }

    /// Such a name never had a kept profile, so its logout finishes, and
    /// another login's profile is not touched.
    #[test]
    fn logging_out_of_such_a_name_finishes_and_touches_no_other_profile() {
        let root = tempfile::tempdir().unwrap();
        let other = kept_dir(root.path(), "has-dot");
        std::fs::create_dir_all(&other).unwrap();
        let forget =
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "has.dot");
        assert!(!logout_browser(forget).unwrap());
        assert!(other.exists());
    }

    /// `rhd`'s rule and the crate's must agree, or a name `profiles add` takes
    /// could fail at the sign-in. The crate's check is not public; a removal
    /// under a temp dir answers for it.
    #[test]
    fn the_name_rule_is_the_browser_crates() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "dummy",
            "Dummy-2_x",
            "a",
            &"a".repeat(64),
            &"a".repeat(65),
            "",
            "has.dot",
            "has space",
            "a/b",
            "ünicode",
            "..",
        ] {
            let crate_refuses = matches!(
                pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, name),
                Err(BrowserError::Invalid(_))
            );
            assert_eq!(config::profile_name_ok(name), !crate_refuses, "{name:?}");
        }
    }

    /// A logout that exits 1 says what is already gone, what remains and how to
    /// finish, with and without `--forget`.
    #[test]
    fn a_refused_logout_says_what_is_cleared_and_how_to_finish() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let mut cfg = Config::default();
        cfg.profiles.insert("dummy-one".into(), Default::default());

        let in_use = || {
            Err(BrowserError::ProfileInUse(
                "dummy: close that window, then log out again.".into(),
            ))
        };
        let err = finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            false,
            |_| Ok(()),
            in_use,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in [
            "partly logged out of `dummy-one`",
            "the session is cleared",
            "only the browser profile remains",
            "close that window",
            "Once that window is closed",
            "`rhd auth logout --profile dummy-one` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }

        let needs_repair = || Err(BrowserError::Profile("dummy: is a symlink".into()));
        let err = finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            true,
            |_| Ok(()),
            needs_repair,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in [
            "the session, the stored password and the device token are cleared",
            "the browser profile and this login's config entry remain",
            "symlink",
            "Repair or delete that path",
            "`rhd auth logout --forget --profile dummy-one` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
    }

    /// Without its config entry, `--profile` could not find the login again
    /// once other logins exist, so the entry stays until the retry finishes.
    #[test]
    fn a_refused_forget_leaves_the_login_configured_for_the_retry() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let mut cfg = Config {
            default_profile: Some("dummy-one".into()),
            ..Config::default()
        };
        cfg.profiles.insert("dummy-one".into(), Default::default());
        store.save(&cfg).unwrap();

        let err = finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            true,
            |_| Ok(()),
            || {
                Err(BrowserError::ProfileInUse(
                    "dummy: close that window".into(),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let saved: Config = store.load().unwrap();
        assert!(saved.profiles.contains_key("dummy-one"));

        assert!(!finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            true,
            |_| Ok(()),
            || Ok(false)
        )
        .unwrap());
        let saved: Config = store.load().unwrap();
        assert!(!saved.profiles.contains_key("dummy-one"));
        assert_eq!(saved.default_profile, None);
    }

    /// A keychain step that fails stops nothing: every later item is still
    /// tried, the browser profile is still removed, and the error says what is
    /// cleared and what remains. The config entry stays for the retry.
    #[test]
    fn a_failed_keychain_step_stops_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let mut cfg = Config::default();
        cfg.profiles.insert("dummy-one".into(), Default::default());
        store.save(&cfg).unwrap();

        let root = tempfile::tempdir().unwrap();
        let kept = kept_dir(root.path(), "dummy-one");
        std::fs::create_dir_all(&kept).unwrap();
        let session = config::token_key("dummy-one");
        let mut tried = Vec::new();
        let err = finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            true,
            |key| {
                tried.push(key.to_string());
                if key == session {
                    Err(CliError::Keychain("dummy: could not delete".into()))
                } else {
                    Ok(())
                }
            },
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "dummy-one"),
        )
        .unwrap_err();

        assert_eq!(
            tried,
            [
                config::token_key("dummy-one"),
                config::pending_key("dummy-one"),
                config::password_key("dummy-one"),
                config::device_key("dummy-one"),
            ]
        );
        assert!(!kept.exists(), "the profile must be removed all the same");
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in [
            "the stored password, the device token and the browser profile are cleared",
            "the session and this login's config entry remain",
            "dummy: could not delete",
            "Fix that, then run",
            "`rhd auth logout --forget --profile dummy-one` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
        let saved: Config = store.load().unwrap();
        assert!(saved.profiles.contains_key("dummy-one"));
    }

    /// A config entry that cannot be written comes last, so everything else is
    /// already gone, and the error says only it remains.
    #[test]
    fn a_failed_config_write_leaves_only_the_config_entry() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("a-file");
        std::fs::write(&blocked, "").unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(blocked.join("c.json")));
        let mut cfg = Config::default();
        cfg.profiles.insert("dummy-one".into(), Default::default());

        let err = finish_logout(
            &store,
            Ok(cfg.clone()),
            "dummy-one",
            true,
            |_| Ok(()),
            || Ok(true),
        )
        .unwrap_err();
        let message = err.to_string();
        for needle in [
            "the browser profile are cleared",
            "only this login's config entry remains",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
    }

    /// The exit code is the first failure's, and every failure is named.
    #[test]
    fn a_failed_logout_exits_with_the_first_failures_code() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let err = finish_logout(
            &store,
            Ok(Config::default()),
            "dummy-one",
            false,
            |_| Err(CliError::Auth("dummy first".into())),
            || Err(BrowserError::ProfileInUse("dummy second".into())),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
        let message = err.to_string();
        assert!(message.starts_with("partly logged out of "), "{message}");
        for needle in [
            "nothing is cleared",
            "the session, a half-finished login and the browser profile remain",
            "dummy first",
            "dummy second",
            "Fix those, then run",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
    }

    /// A config that cannot be parsed stops no other step. Only with `--forget`
    /// does logout need it, and then only the config entry stays.
    #[test]
    fn a_config_that_cannot_be_parsed_stops_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let broken = || Err(CliError::Other("parsing dummy: bad".into()));
        let root = tempfile::tempdir().unwrap();
        let kept = kept_dir(root.path(), "dummy-one");

        std::fs::create_dir_all(&kept).unwrap();
        let mut tried = 0;
        let err = finish_logout(
            &store,
            broken(),
            "dummy-one",
            true,
            |_| {
                tried += 1;
                Ok(())
            },
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "dummy-one"),
        )
        .unwrap_err();
        assert_eq!(tried, 4);
        assert!(!kept.exists(), "the profile must be removed all the same");
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in ["only this login's config entry remains", "parsing dummy"] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }

        std::fs::create_dir_all(&kept).unwrap();
        let removed = finish_logout(
            &store,
            broken(),
            "dummy-one",
            false,
            |_| Ok(()),
            || pk_cli_browser::forget_named_profile_in(root.path(), config::BIN, "dummy-one"),
        )
        .unwrap();
        assert!(removed);
        assert!(!kept.exists());
    }

    /// Built from the inner messages: no prefix in front of the report or inside
    /// it, with the same exit code.
    #[test]
    fn a_keychain_failure_does_not_prefix_the_report() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let err = finish_logout(
            &store,
            Ok(Config::default()),
            "dummy-one",
            false,
            |_| Err(CliError::Keychain("dummy: could not delete".into())),
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        assert!(message.starts_with("partly logged out of "), "{message}");
        assert!(!message.contains("keychain error"), "{message}");

        // A refresh lock held past the wait: the prefix once, and not inside.
        let err = finish_logout(
            &store,
            Ok(Config::default()),
            "dummy-one",
            false,
            |key| {
                if key == config::token_key("dummy-one") {
                    Err(CliError::Upstream("dummy: lock held".into()))
                } else {
                    Ok(())
                }
            },
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        let message = err.to_string();
        assert_eq!(
            message.matches("network/upstream error").count(),
            1,
            "{message}"
        );
        // The tokens are gone, so the report does not say they remain.
        assert!(
            message.contains("only a renewal that can store the session again remains"),
            "{message}"
        );
        assert!(
            message.contains("In a minute, run `rhd auth logout"),
            "{message}"
        );
    }

    #[test]
    fn the_logout_line_says_what_went() {
        assert_eq!(
            logged_out("dummy", false, false),
            "logged out of profile `dummy`"
        );
        assert_eq!(
            logged_out("dummy", true, true),
            "logged out of profile `dummy` and forgot its stored credentials; browser profile removed"
        );
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
