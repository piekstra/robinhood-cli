//! HTTP against `api.robinhood.com`, the OAuth/device-approval login dance,
//! cursor pagination, and verified document downloads.
//!
//! Robinhood publishes no public retail API. Every constant and path here
//! comes from community reverse-engineering; `docs/api.md` carries the
//! citations and marks what has never been confirmed against the live
//! service.
//!
//! # Rules this module enforces
//!
//! - **One attempt.** Nothing here retries a failed login. Community reports
//!   put lockout at 2-3 failed attempts, and an IP-level block at ~12 hours.
//! - **Polite pacing.** Reads are spaced by [`MIN_REQUEST_GAP`], and the
//!   device-approval poll is slow and bounded — polling it hard is a
//!   documented way to earn a 429 and a half-day block.
//! - **A status code is not success.** [`json_response`] treats
//!   HTML-where-JSON-was-expected as an auth failure, because that is what a
//!   bounced session actually looks like.
//! - **A download is not a document until it matches its declared
//!   `filetype`** — `%PDF` magic for a PDF, non-markup text for a CSV. The
//!   mechanism lives in `pk_cli_documents::verify`.

use std::cell::Cell;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pk_cli_core::CliError;
use pk_cli_documents::verify_download;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::API_BASE;

/// OAuth client id used by Robinhood's own clients. Public — it identifies the
/// app, not the user — and is the value every community client sends.
/// docs/api.md §2.
pub const CLIENT_ID: &str = "c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS";

/// Requested access-token lifetime. The server **ignores** this — observed
/// lifetimes are ~5-8 days — but every community client sends it, so we match.
const EXPIRES_IN: &str = "86400";

/// API version header the community clients send.
const API_VERSION: &str = "1.431.4";

/// The literal User-Agent the community settled on.
///
/// Counter-intuitive and load-bearing: sending a *browser-like* UA from a
/// non-browser TLS stack gets the request flagged as impersonation, and
/// Robinhood answers with a **counterfeit** `400 "Unable to log in with
/// provided credentials."` — i.e. a bot block that is indistinguishable from a
/// wrong password. `*` is what robin_stocks, pyhood, and rhood-rs all send.
const USER_AGENT: &str = "*";

/// Minimum spacing between requests. pyhood enforces 250ms; observed-safe read
/// rates are ~5/s. Cheap insurance against a throttle that costs hours.
const MIN_REQUEST_GAP: Duration = Duration::from_millis(250);

/// How long to wait between device-approval polls. Community reports tie fast
/// polling of this endpoint to a 429 and a ~12-hour block, so it is
/// deliberately slow.
const PUSH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Bounded, not infinite: roughly two minutes of waiting for a phone tap.
const PUSH_POLL_ATTEMPTS: u32 = 12;

/// Where a verification code should be sent, when the provider lets us choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Channel {
    Sms,
    Email,
}

impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Channel::Sms => "sms",
            Channel::Email => "email",
        }
    }
}

/// What a redacted credential prints as in `Debug` output — the same marker
/// `pk_cli_secrets::Secret` uses.
const REDACTED: &str = "***redacted***";

/// The cached OAuth session, stored as JSON in the keychain.
///
/// `Debug` is written by hand so a stray `{:?}` (a log line, a panic, a test
/// failure) can never print a token.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Absolute expiry in Unix seconds, computed from `expires_in` at issue
    /// time. Stored absolute because a relative lifetime is meaningless once
    /// it has been sitting in the keychain for a day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The community record says Robinhood mints this alongside the main
    /// token when the login body sets `create_read_only_secondary_token` —
    /// but the live login of 2026-08-12 (sheriff-workflow path, flag sent)
    /// returned **no** `read_only_secondary_access_token`. The web app, by
    /// contrast, treats a token response without one as a failed login, so
    /// an imported `web:auth_state` should carry it (docs/api.md §2.8).
    /// Kept because a read-only CLI presenting a read-only token would be a
    /// genuine hardening step. See docs/api.md §2.7 and §7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_token: Option<String>,
    /// How the session was obtained. A bundle without the field — every one
    /// a password login writes, and every one written before 0.2.0 — is a
    /// password session.
    #[serde(default, skip_serializing_if = "Origin::is_password")]
    pub origin: Origin,
    /// The device this session was issued to, when that is not the profile's
    /// own `<profile>/device`: a session imported from a browser belongs to
    /// the web app's `device_id` cookie (docs/api.md §2.8). Kept inside the
    /// bundle so the token and the device it renews with stay one keychain
    /// item, and so an import never overwrites the profile's device token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| REDACTED);
        f.debug_struct("Tokens")
            .field("access_token", &REDACTED)
            .field("refresh_token", &redact(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("read_only_token", &redact(&self.read_only_token))
            .field("origin", &self.origin)
            .field("device_token", &redact(&self.device_token))
            .finish()
    }
}

/// Where a stored session came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// `rhd auth login` with the password (and any device approval).
    #[default]
    Password,
    /// The web app's `web:auth_state`, from `--browser` or `--session-stdin`
    /// (the two store the same bundle) — carries a refresh token.
    WebAuthState,
    /// `--session-stdin` with a bare bearer token — no refresh token.
    Bearer,
}

impl Origin {
    pub fn is_password(&self) -> bool {
        *self == Origin::Password
    }

    pub fn is_browser(&self) -> bool {
        !self.is_password()
    }
}

impl Tokens {
    /// Build from an `/oauth2/token/` response body.
    pub fn from_response(v: &Value) -> Result<Self, CliError> {
        let access_token = v
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Upstream(
                    "login response carried no access_token — the auth flow has probably \
                     changed shape; see docs/api.md"
                        .into(),
                )
            })?
            .to_string();
        Ok(Tokens {
            access_token,
            refresh_token: v
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_string),
            expires_at: v
                .get("expires_in")
                .and_then(Value::as_u64)
                .map(|secs| now_unix() + secs),
            read_only_token: v
                .get("read_only_secondary_access_token")
                .and_then(Value::as_str)
                .map(str::to_string),
            origin: Origin::Password,
            device_token: None,
        })
    }

    /// A refresh response, carrying over what the refresh does not return:
    /// where the session came from and the device it belongs to. Without
    /// this, the first renewal of an imported session would forget its
    /// device and present the wrong one on the next.
    pub fn renewed(mut self, previous: &Tokens) -> Tokens {
        self.origin = previous.origin;
        self.device_token = previous.device_token.clone();
        self
    }

    /// The device token a refresh presents: the one this session was issued
    /// to. A password session belongs to the profile's device; an imported
    /// session presents the browser's, or none — it never borrows the
    /// profile's, which would claim a device the session was not issued to.
    pub fn refresh_device<'a>(&'a self, profile_device: Option<&'a str>) -> Option<&'a str> {
        match self.origin {
            Origin::Password => self.device_token.as_deref().or(profile_device),
            Origin::WebAuthState | Origin::Bearer => self.device_token.as_deref(),
        }
    }

    pub fn from_json(raw: &str) -> Result<Self, CliError> {
        serde_json::from_str(raw).map_err(|e| {
            CliError::Auth(format!(
                "the cached session could not be read ({e}) — run `rhd auth login --browser \
                 --overwrite` again"
            ))
        })
    }

    pub fn to_secret(&self) -> pk_cli_secrets::Secret {
        pk_cli_secrets::Secret::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Whether the access token is past (or within a minute of) its expiry.
    /// A session with no known expiry is reported usable — the server stays
    /// the authority, and guessing "expired" would force a needless login.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(now_unix())
    }

    /// [`Tokens::is_expired`] at `now`: the rule a renewal goes by, so a caller
    /// checking whether a token may already have been renewed asks the same
    /// question.
    pub fn is_expired_at(&self, now: u64) -> bool {
        match self.expires_at {
            Some(exp) => exp.saturating_sub(60) <= now,
            None => false,
        }
    }

    pub fn expires_at_rfc3339(&self) -> Option<String> {
        self.expires_at
            .map(|e| pk_cli_core::dates::fmt_rfc3339(e as i64))
    }
}

/// Which second-factor mechanism the provider raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    /// Newer device-approval ("sheriff"/SUV) verification workflow. Dominant
    /// since late 2024.
    Workflow,
    /// Legacy top-level `challenge` object.
    Challenge,
    /// `mfa_required` on the token response itself.
    Mfa,
}

/// How the user is expected to satisfy a device-approval challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// Approve in the Robinhood phone app — no code to type.
    Prompt,
    /// A numeric code delivered by SMS or email.
    Code,
}

/// A login that stopped partway and can be resumed.
///
/// Persisted (JSON) in the keychain under `<profile>/pending`. Carries no
/// secret: the password it will re-present comes from the keychain, and these
/// ids are meaningless without it. The device token still carries device
/// trust (SECURITY.md), so `Debug` redacts it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Parked {
    pub flow: Flow,
    pub kind: ChallengeKind,
    /// `verification_workflow.id` from the token response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    /// The pathfinder inquiry ("user machine") driving the workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// The sheriff challenge (or legacy challenge) to answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    /// The device token this attempt presented. Reusing it on resume matters:
    /// a different one is a different device to the provider.
    pub device_token: String,
}

impl fmt::Debug for Parked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parked")
            .field("flow", &self.flow)
            .field("kind", &self.kind)
            .field("workflow_id", &self.workflow_id)
            .field("machine_id", &self.machine_id)
            .field("challenge_id", &self.challenge_id)
            .field("device_token", &REDACTED)
            .finish()
    }
}

/// What one login attempt produced.
#[derive(Debug)]
pub enum LoginOutcome {
    /// Authenticated outright (a trusted device, or a resumed attempt).
    Session(Box<Tokens>),
    /// Stopped on a second factor.
    NeedsApproval { parked: Box<Parked>, hint: String },
}

/// Client for the Robinhood private API.
pub struct Rh {
    http: reqwest::blocking::Client,
    base: String,
    last_request: Cell<Option<Instant>>,
}

impl Rh {
    pub fn new() -> Result<Self, CliError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert("Accept-Language", "en-US,en;q=1".parse().unwrap());
        headers.insert("X-Robinhood-API-Version", API_VERSION.parse().unwrap());

        let http = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| CliError::Other(format!("failed to build HTTP client: {e}")))?;
        Ok(Rh {
            http,
            base: API_BASE.to_string(),
            last_request: Cell::new(None),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Space requests out, so a burst of pagination can't trip a throttle.
    fn pace(&self) {
        if let Some(last) = self.last_request.get() {
            let elapsed = last.elapsed();
            if elapsed < MIN_REQUEST_GAP {
                std::thread::sleep(MIN_REQUEST_GAP - elapsed);
            }
        }
        self.last_request.set(Some(Instant::now()));
    }

    /// Mint a device token.
    ///
    /// Robinhood's own clients build this from 16 random bytes hyphenated
    /// 8-4-4-4-12 — the UUID *shape* without the version/variant bits. A v4
    /// UUID is the same shape and is what several community clients send.
    /// Generated once per profile and then persisted forever: regenerating it
    /// presents as a brand-new device and re-raises the approval challenge.
    pub fn new_device_token() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Attempt a password login. **One** request; never loops.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        device_token: &str,
        channel: Channel,
    ) -> Result<LoginOutcome, CliError> {
        let v = self.post_token(
            &self.token_form(username, password, device_token, channel),
            None,
        )?;
        self.interpret_login(&v, device_token)
    }

    /// Turn a token-endpoint response into an outcome.
    ///
    /// Split out from [`Rh::login`] so the branch logic — the part that
    /// changes when Robinhood reshapes its auth — is unit-testable offline
    /// against fixtures, with no network involved.
    pub fn interpret_login(&self, v: &Value, device_token: &str) -> Result<LoginOutcome, CliError> {
        // 1. Authenticated.
        if v.get("access_token").is_some() {
            return Ok(LoginOutcome::Session(Box::new(Tokens::from_response(v)?)));
        }

        // 2. Device-approval ("sheriff") workflow — the dominant path today.
        if let Some(id) = v
            .get("verification_workflow")
            .and_then(|w| w.get("id"))
            .and_then(Value::as_str)
        {
            return self.open_workflow(id, device_token);
        }

        // 3. Legacy challenge object.
        if let Some(ch) = v.get("challenge") {
            let id = ch
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::Upstream("challenge response carried no id; see docs/api.md".into())
                })?
                .to_string();
            let kind = match ch.get("type").and_then(Value::as_str) {
                Some("prompt") | Some("app") => ChallengeKind::Prompt,
                _ => ChallengeKind::Code,
            };
            return Ok(LoginOutcome::NeedsApproval {
                parked: Box::new(Parked {
                    flow: Flow::Challenge,
                    kind,
                    workflow_id: None,
                    machine_id: None,
                    challenge_id: Some(id),
                    device_token: device_token.to_string(),
                }),
                hint: hint_for(kind),
            });
        }

        // 4. Second factor on the token request itself.
        if v.get("mfa_required").and_then(Value::as_bool) == Some(true) {
            let kind = v.get("mfa_type").and_then(Value::as_str).unwrap_or("app");
            return Ok(LoginOutcome::NeedsApproval {
                parked: Box::new(Parked {
                    flow: Flow::Mfa,
                    kind: ChallengeKind::Code,
                    workflow_id: None,
                    machine_id: None,
                    challenge_id: None,
                    device_token: device_token.to_string(),
                }),
                hint: format!("Robinhood requires a two-factor code ({kind})"),
            });
        }

        Err(CliError::Upstream(
            "Robinhood's login response matched none of the known shapes — the auth flow has \
             probably changed; see docs/api.md"
                .into(),
        ))
    }

    /// Open a pathfinder machine for a verification workflow and discover what
    /// kind of challenge it wants. UNVERIFIED-LIVE — see docs/api.md §2.
    fn open_workflow(
        &self,
        workflow_id: &str,
        device_token: &str,
    ) -> Result<LoginOutcome, CliError> {
        let machine = self.post_json(
            &format!("{}/pathfinder/user_machine/", self.base),
            &json!({
                "device_id": device_token,
                "flow": "suv",
                "input": { "workflow_id": workflow_id },
            }),
        )?;
        let machine_id = machine
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Upstream(
                    "device-approval workflow returned no inquiry id — the flow has changed \
                     shape; see docs/api.md"
                        .into(),
                )
            })?
            .to_string();

        let view = self.get_json(
            None,
            &format!("{}/pathfinder/inquiries/{machine_id}/user_view/", self.base),
            &[],
        )?;
        let challenge = sheriff_challenge(&view).ok_or_else(|| {
            CliError::Upstream(
                "device-approval workflow exposed no challenge — the flow has changed shape; \
                 see docs/api.md"
                    .into(),
            )
        })?;

        let challenge_id = challenge
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let kind = match challenge.get("type").and_then(Value::as_str) {
            Some("sms") | Some("email") => ChallengeKind::Code,
            // `prompt` and `app` both mean "tap approve on the phone".
            _ => ChallengeKind::Prompt,
        };

        Ok(LoginOutcome::NeedsApproval {
            parked: Box::new(Parked {
                flow: Flow::Workflow,
                kind,
                workflow_id: Some(workflow_id.to_string()),
                machine_id: Some(machine_id),
                challenge_id,
                device_token: device_token.to_string(),
            }),
            hint: hint_for(kind),
        })
    }

    /// Resume a parked attempt. `code` is `None` for the phone-approval kind.
    ///
    /// Exactly one pass; if it fails, it fails. The caller discards the parked
    /// attempt either way rather than retrying.
    pub fn resume(
        &self,
        parked: &Parked,
        code: Option<&str>,
        username: &str,
        password: &str,
        channel: Channel,
    ) -> Result<Tokens, CliError> {
        match parked.flow {
            Flow::Mfa => {
                let code = code.ok_or_else(|| {
                    CliError::Usage("this login needs a code — pass `--code <CODE>`".into())
                })?;
                let mut form = self.token_form(username, password, &parked.device_token, channel);
                form.push(("mfa_code", code.to_string()));
                let v = self.post_token(&form, None)?;
                Tokens::from_response(&v)
            }
            Flow::Challenge => {
                let id = parked
                    .challenge_id
                    .as_deref()
                    .ok_or_else(|| CliError::Other("parked challenge is missing its id".into()))?;
                match (parked.kind, code) {
                    (ChallengeKind::Code, Some(c)) => self.respond_challenge(id, c)?,
                    (ChallengeKind::Code, None) => {
                        return Err(CliError::Usage(
                            "this login needs a code — pass `--code <CODE>`".into(),
                        ))
                    }
                    (ChallengeKind::Prompt, _) => self.await_prompt(id)?,
                }
                let form = self.token_form(username, password, &parked.device_token, channel);
                let v = self.post_token(&form, Some(id))?;
                Tokens::from_response(&v)
            }
            Flow::Workflow => {
                let machine_id = parked.machine_id.as_deref().ok_or_else(|| {
                    CliError::Other("parked workflow is missing its inquiry id".into())
                })?;
                match (parked.kind, code) {
                    (ChallengeKind::Code, Some(c)) => {
                        let id = parked.challenge_id.as_deref().ok_or_else(|| {
                            CliError::Other("parked workflow is missing its challenge id".into())
                        })?;
                        self.respond_challenge(id, c)?;
                    }
                    (ChallengeKind::Code, None) => {
                        return Err(CliError::Usage(
                            "this login needs a code — pass `--code <CODE>`".into(),
                        ))
                    }
                    (ChallengeKind::Prompt, _) => {
                        let id = parked.challenge_id.as_deref().ok_or_else(|| {
                            CliError::Other("parked workflow is missing its challenge id".into())
                        })?;
                        self.await_prompt(id)?;
                    }
                }
                self.finish_workflow(machine_id)?;
                let form = self.token_form(username, password, &parked.device_token, channel);
                let v = self.post_token(&form, None)?;
                Tokens::from_response(&v)
            }
        }
    }

    /// Exchange a refresh token for a fresh access token.
    ///
    /// This is the one part of the flow done implicitly, because it raises no
    /// challenge. If the response comes back carrying a `verification_workflow`
    /// the refresh token itself is dead and a full login is required.
    pub fn refresh(
        &self,
        refresh_token: &str,
        device_token: Option<&str>,
    ) -> Result<Tokens, CliError> {
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("scope", "internal".to_string()),
            ("client_id", CLIENT_ID.to_string()),
            ("expires_in", EXPIRES_IN.to_string()),
        ];
        if let Some(d) = device_token {
            form.push(("device_token", d.to_string()));
        }
        let v = self.post_token_with(&form, None, html_at_renewal)?;
        if v.get("verification_workflow").is_some() {
            return Err(CliError::Auth(
                "the stored session can no longer be refreshed (Robinhood wants device \
                 approval again) — run `rhd auth login --browser --overwrite`"
                    .into(),
            ));
        }
        Tokens::from_response(&v)
    }

    fn token_form(
        &self,
        username: &str,
        password: &str,
        device_token: &str,
        channel: Channel,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("client_id", CLIENT_ID.to_string()),
            ("expires_in", EXPIRES_IN.to_string()),
            ("grant_type", "password".to_string()),
            ("scope", "internal".to_string()),
            ("username", username.to_string()),
            ("password", password.to_string()),
            ("device_token", device_token.to_string()),
            ("challenge_type", channel.as_str().to_string()),
            ("try_passkeys", "false".to_string()),
            ("token_request_path", "/login".to_string()),
            ("create_read_only_secondary_token", "true".to_string()),
        ]
    }

    /// The token endpoint takes **form-encoded** bodies, not JSON.
    fn post_token(
        &self,
        form: &[(&str, String)],
        challenge_id: Option<&str>,
    ) -> Result<Value, CliError> {
        self.post_token_with(form, challenge_id, html_at_login)
    }

    /// [`post_token`](Self::post_token), with what an HTML answer means to the caller.
    fn post_token_with(
        &self,
        form: &[(&str, String)],
        challenge_id: Option<&str>,
        on_html: fn(u16) -> CliError,
    ) -> Result<Value, CliError> {
        self.pace();
        let mut req = self
            .http
            .post(format!("{}/oauth2/token/", self.base))
            .form(form);
        if let Some(id) = challenge_id {
            req = req.header("X-ROBINHOOD-CHALLENGE-RESPONSE-ID", id);
        }
        let resp = req
            .send()
            .map_err(|e| CliError::Upstream(format!("contacting Robinhood: {e}")))?;

        let status = resp.status().as_u16();
        let retry_after = header_value(&resp, "retry-after");
        let text = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading login response: {e}")))?;

        if status == 429 {
            return Err(throttled(retry_after.as_deref()));
        }
        let v = parse_json(&text, status, on_html)?;
        // A 4xx that still carries a challenge/workflow is the flow working as
        // designed, so those are handed back rather than raised as errors.
        if (200..300).contains(&status)
            || v.get("challenge").is_some()
            || v.get("verification_workflow").is_some()
            || v.get("mfa_required").is_some()
        {
            return Ok(v);
        }
        Err(login_error(&v, status))
    }

    /// Answer an SMS/email challenge. Positive confirmation only.
    fn respond_challenge(&self, id: &str, code: &str) -> Result<(), CliError> {
        let v = self.post_json(
            &format!("{}/challenge/{id}/respond/", self.base),
            &json!({ "response": code }),
        )?;
        // The provider answers 200 for a rejected code too, carrying the real
        // outcome in the body — so the body is what decides.
        match challenge_status(&v) {
            Some("validated") => Ok(()),
            _ => Err(CliError::Auth(format!(
                "Robinhood rejected the verification code{}",
                detail_suffix(&v)
            ))),
        }
    }

    /// Wait for the user to tap "approve" in the Robinhood app.
    ///
    /// Slow and bounded on purpose: hammering this endpoint is a documented
    /// route to a 429 and a ~12-hour block.
    fn await_prompt(&self, challenge_id: &str) -> Result<(), CliError> {
        let url = format!("{}/push/{challenge_id}/get_prompts_status/", self.base);
        for attempt in 0..PUSH_POLL_ATTEMPTS {
            let v = self.get_json(None, &url, &[])?;
            if v.get("challenge_status").and_then(Value::as_str) == Some("validated") {
                return Ok(());
            }
            if attempt + 1 < PUSH_POLL_ATTEMPTS {
                std::thread::sleep(PUSH_POLL_INTERVAL);
            }
        }
        Err(CliError::Auth(
            "timed out waiting for the approval in the Robinhood app — approve it, then re-run \
             `rhd auth login --resume`"
                .into(),
        ))
    }

    /// Drive the workflow to its approved terminal state.
    fn finish_workflow(&self, machine_id: &str) -> Result<(), CliError> {
        let v = self.post_json(
            &format!("{}/pathfinder/inquiries/{machine_id}/user_view/", self.base),
            &json!({ "sequence": 0, "user_input": { "status": "continue" } }),
        )?;
        if workflow_approved(&v) {
            return Ok(());
        }
        Err(CliError::Auth(format!(
            "Robinhood did not approve this device{}",
            detail_suffix(&v)
        )))
    }

    fn post_json(&self, url: &str, body: &Value) -> Result<Value, CliError> {
        self.pace();
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .map_err(|e| CliError::Upstream(format!("calling {url}: {e}")))?;
        json_response(resp)
    }

    fn get_json(
        &self,
        token: Option<&str>,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Value, CliError> {
        self.get_raw(token, url, query)
            .map_err(ReadFailure::into_cli_error)
    }

    fn get_raw(
        &self,
        token: Option<&str>,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Value, ReadFailure> {
        self.pace();
        let mut req = self.http.get(url).query(query);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .map_err(|e| ReadFailure::Upstream(format!("calling {url}: {e}")))?;
        read_json(resp)
    }

    /// Authenticated GET returning parsed JSON.
    pub fn get(&self, token: &str, url: &str, query: &[(&str, String)]) -> Result<Value, CliError> {
        self.get_json(Some(token), url, query)
    }

    /// [`Rh::get`] that reports *why* it failed, with no advice attached —
    /// for a caller whose remedy is not "run `rhd auth login --browser`"
    /// (the browser-session import's proving read).
    pub fn probe(
        &self,
        token: &str,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Value, ReadFailure> {
        self.get_raw(Some(token), url, query)
    }

    /// Whether an absolute URL stays on the configured API origin.
    ///
    /// Provider-supplied links — the `next` pagination cursor, an account
    /// row's `portfolio` link — are dereferenced with the bearer token
    /// attached, so a link that leaves the origin must never be followed:
    /// that would hand the session token to whatever host the payload named.
    /// The boundary check matters: `api.robinhood.com.evil.example` must not
    /// pass as a prefix match.
    pub fn same_origin(&self, url: &str) -> bool {
        same_origin_of(&self.base, url)
    }

    /// Resolve a path against the API base (absolute URLs pass through).
    pub fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{}", self.base.trim_end_matches('/'), path)
        }
    }

    /// Follow the cursor until `limit` records are collected or the pages run
    /// out. Robinhood pages with `{"next": <url|null>, "results": [...]}`.
    ///
    /// `next` is an absolute URL and is followed verbatim — the cursor is
    /// opaque, and rebuilding the request drops fields.
    pub fn paginate(
        &self,
        token: &str,
        path: &str,
        query: &[(&str, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>, CliError> {
        self.paginate_on(&self.base, token, &self.url(path), query, limit)
    }

    /// [`Rh::paginate`] against another Robinhood origin — the `bonfire`
    /// host serves the ACATS listing (docs/api.md §3.13). The cursor may only
    /// stay on **that** origin: the bearer token goes with every request.
    pub fn paginate_at(
        &self,
        origin: &str,
        token: &str,
        path: &str,
        query: &[(&str, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>, CliError> {
        let url = format!("{}{}", origin.trim_end_matches('/'), path);
        self.paginate_on(origin, token, &url, query, limit)
    }

    fn paginate_on(
        &self,
        origin: &str,
        token: &str,
        first_url: &str,
        query: &[(&str, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>, CliError> {
        let cap = limit.map(|l| l as usize).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let mut url = first_url.to_string();
        let mut first = true;
        // A hard ceiling: an unbounded `next` chain is how a read turns into
        // thousands of requests against a rate-limited API.
        for _ in 0..200 {
            let v = self.get(token, &url, if first { query } else { &[] })?;
            first = false;
            match v.get("results").and_then(Value::as_array) {
                Some(rows) => out.extend(rows.iter().cloned()),
                // A bare object (not a collection) is a single record.
                None => {
                    out.push(v);
                    break;
                }
            }
            if out.len() >= cap {
                out.truncate(cap);
                break;
            }
            match v.get("next").and_then(Value::as_str) {
                Some(n) if !n.is_empty() => {
                    // The cursor is followed verbatim (§3.1), but never off
                    // the API origin — the request carries the bearer token.
                    if !same_origin_of(origin, n) {
                        return Err(CliError::Upstream(format!(
                            "refusing to follow a pagination cursor off the API origin: {n}"
                        )));
                    }
                    url = n.to_string();
                }
                _ => break,
            }
        }
        Ok(out)
    }

    /// Download a document, refusing anything that doesn't match the
    /// `filetype` the listing declared for it (LIVE-VERIFIED values: `pdf`,
    /// `csv`, `html` — docs/api.md §3.5).
    pub fn download_document(
        &self,
        token: &str,
        url: &str,
        filetype: Option<&str>,
    ) -> Result<Vec<u8>, CliError> {
        self.pace();
        let resp = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .map_err(|e| CliError::Upstream(format!("downloading {url}: {e}")))?;
        let status = resp.status().as_u16();
        let retry_after = header_value(&resp, "retry-after");
        if status == 429 {
            return Err(throttled(retry_after.as_deref()));
        }
        if status == 401 || status == 403 {
            return Err(CliError::Auth(format!(
                "Robinhood refused the document download (HTTP {status}) — run `rhd auth login \
                 --browser --overwrite`"
            )));
        }
        if status == 404 {
            return Err(CliError::NotFound("document not found".into()));
        }
        if !(200..300).contains(&status) {
            return Err(CliError::Upstream(format!(
                "document download returned HTTP {status}"
            )));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| CliError::Upstream(format!("reading document body: {e}")))?
            .to_vec();
        verify_download(&bytes, filetype)?;
        Ok(bytes)
    }
}

/// The sheriff challenge object, which the provider duplicates at two paths.
///
/// Different community clients read different ones, and both are present in
/// real captures, so look in both rather than betting on either.
fn sheriff_challenge(view: &Value) -> Option<&Value> {
    view.pointer("/context/sheriff_challenge")
        .or_else(|| view.pointer("/type_context/context/sheriff_challenge"))
}

fn challenge_status(v: &Value) -> Option<&str> {
    v.get("status")
        .and_then(Value::as_str)
        .or_else(|| v.pointer("/challenge/status").and_then(Value::as_str))
}

/// Whether a workflow response says the device was approved.
fn workflow_approved(v: &Value) -> bool {
    let approved = |s: &str| s == "workflow_status_approved";
    v.pointer("/type_context/result")
        .and_then(Value::as_str)
        .map(approved)
        .or_else(|| {
            v.pointer("/verification_workflow/workflow_status")
                .and_then(Value::as_str)
                .map(approved)
        })
        .unwrap_or(false)
}

fn hint_for(kind: ChallengeKind) -> String {
    match kind {
        ChallengeKind::Prompt => "Robinhood wants this device approved — open the Robinhood app \
             on your phone and tap approve"
            .into(),
        ChallengeKind::Code => "Robinhood sent a verification code".into(),
    }
}

/// Whether an absolute URL stays on `base`'s origin. The boundary check
/// matters: `api.robinhood.com.evil.example` must not pass as a prefix
/// match.
pub fn same_origin_of(base: &str, url: &str) -> bool {
    let base = base.trim_end_matches('/');
    url == base
        || url
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('?'))
}

/// Why a JSON read failed: the cause alone, before any advice is attached.
///
/// An ordinary read turns the auth-class failures into "run `rhd auth
/// login`" ([`ReadFailure::into_cli_error`]). The browser-session import's
/// proving read must not — for it that advice sends the owner back to the
/// password login they are routing around — so it takes the cause and says
/// its own thing. Keeping the advice out of the cause is what lets each
/// caller do that without editing another layer's message.
#[derive(Debug)]
pub enum ReadFailure {
    /// 401/403: the provider refused the token. `detail` is the provider's
    /// own message, when it gave one. `json_body` says whether the body was JSON:
    /// a bare 403 can come from an edge in front of the provider.
    Rejected {
        status: u16,
        detail: Option<String>,
        json_body: bool,
    },
    /// HTML where JSON was expected — how a bounced session usually answers,
    /// often with a 200.
    Html { status: u16, url: String },
    /// 429.
    Throttled { retry_after: Option<String> },
    /// 404.
    NotFound { url: String },
    /// Any other non-2xx, a transport failure, or a body that is not JSON.
    Upstream(String),
}

impl ReadFailure {
    /// Whether the provider refused the credential (exit 3), as opposed to
    /// failing for some other reason.
    pub fn is_auth(&self) -> bool {
        matches!(
            self,
            ReadFailure::Rejected { .. } | ReadFailure::Html { .. }
        )
    }

    /// What the answer says, if it refuses the token for certain: a 401, or
    /// Robinhood's own JSON on a 403. An HTML page or a bare 403 can come from an edge
    /// in front of Robinhood, so it says nothing certain about the token, though an
    /// ordinary read treats it as [`is_auth`](Self::is_auth).
    pub fn definite_refusal(&self) -> Option<String> {
        match self {
            ReadFailure::Rejected {
                status, json_body, ..
            } if *status == 401 || *json_body => Some(self.cause()),
            ReadFailure::Html { status: 401, .. } => {
                Some("Robinhood rejected the request (HTTP 401)".into())
            }
            _ => None,
        }
    }

    /// Whether the answer is shaped like a block at the edge: an HTML page or a 403 with
    /// no JSON, and no definite refusal. A throttle or an outage is read by its status
    /// first, whatever its body, so it is never this.
    pub fn is_edge_shaped(&self) -> bool {
        matches!(
            self,
            ReadFailure::Html { .. } | ReadFailure::Rejected { .. }
        ) && self.definite_refusal().is_none()
    }

    /// What an answer that is no [`definite_refusal`](Self::definite_refusal) said,
    /// for a session stored unverified. Unlike [`cause`](Self::cause), it does not
    /// suggest the session has lapsed: this one was written moments ago.
    pub fn inconclusive_cause(&self) -> String {
        match self {
            ReadFailure::Html { status, url } => format!(
                "{url} answered with an HTML page (HTTP {status}), most likely a bot check and \
                 no verdict on the session"
            ),
            ReadFailure::Rejected { status, .. } => format!(
                "Robinhood's accounts read answered HTTP {status} with no JSON, most likely a \
                 block at the edge and no verdict on the session"
            ),
            other => other.cause(),
        }
    }

    /// What went wrong, with no remediation attached.
    pub fn cause(&self) -> String {
        match self {
            ReadFailure::Rejected { status, detail, .. } => format!(
                "Robinhood rejected the request (HTTP {status}){}",
                detail
                    .as_deref()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default()
            ),
            ReadFailure::Html { status, url } => format!(
                "expected JSON from {url} but got an HTML page (HTTP {status}) — a bot check \
                 intervened or the session has lapsed"
            ),
            ReadFailure::Throttled { retry_after } => throttled_message(retry_after.as_deref()),
            ReadFailure::NotFound { url } => format!("HTTP 404 from {url}"),
            ReadFailure::Upstream(msg) => msg.clone(),
        }
    }

    /// The error an ordinary read reports: the cause, plus the login advice
    /// for the auth-class failures. An answer shaped like a block at the edge stays
    /// exit 3 and puts the sign-in last ([`edge_block_advice`]).
    pub fn into_cli_error(self) -> CliError {
        let cause = self.cause();
        if self.is_edge_shaped() {
            return CliError::Auth(format!("{cause}. {}", edge_block_advice(RELOGIN)));
        }
        match self {
            ReadFailure::Rejected { .. } => CliError::Auth(format!("{cause} — run `{RELOGIN}`")),
            ReadFailure::Html { .. } => CliError::Auth(format!("{cause}; run `{RELOGIN}`")),
            ReadFailure::NotFound { .. } => CliError::NotFound(cause),
            ReadFailure::Throttled { .. } | ReadFailure::Upstream(_) => CliError::Upstream(cause),
        }
    }
}

/// The login that replaces a stored session.
const RELOGIN: &str = "rhd auth login --browser --overwrite";

/// How [`edge_block_advice`] opens, so a caller can tell that this advice is already in
/// an error and not ask for a sign-in beside it.
pub const SIGN_IN_MAY_NOT_HELP: &str =
    "A new sign-in may not help, because a block like this is on the client rather than the \
     session";

/// What to do about an answer shaped like a block at the edge. Signing in does not clear
/// a block on this client, and each attempt spends a sign-in and replaces the stored
/// session, so the sign-in comes last. One text, so a sign-in's warning and a later
/// read's error send the owner the same way. `login` is the command, with `--profile`
/// where the caller knows it.
pub fn edge_block_advice(login: &str) -> String {
    format!(
        "{SIGN_IN_MAY_NOT_HELP}: wait or try another network, and only if reads still fail \
         after that, run `{login}`."
    )
}

/// Map a response onto the exit-code contract, treating HTML as an auth
/// failure rather than trusting the status code.
pub fn json_response(resp: reqwest::blocking::Response) -> Result<Value, CliError> {
    read_json(resp).map_err(ReadFailure::into_cli_error)
}

/// [`json_response`] without the advice: the typed cause of a failure.
fn read_json(resp: reqwest::blocking::Response) -> Result<Value, ReadFailure> {
    let status = resp.status().as_u16();
    let url = resp.url().to_string();
    let retry_after = header_value(&resp, "retry-after");
    let text = resp
        .text()
        .map_err(|e| ReadFailure::Upstream(format!("reading response body: {e}")))?;
    classify(status, &url, retry_after, &text)
}

/// Classify a response from its parts. Pure, so the mapping is testable
/// without a network.
pub(crate) fn classify(
    status: u16,
    url: &str,
    retry_after: Option<String>,
    text: &str,
) -> Result<Value, ReadFailure> {
    let body = || serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
    // A throttle or an outage says nothing about the session, whatever its body,
    // and an edge answers both with HTML. Read as a refusal, it would renew the
    // session for nothing, and leave a browser sign-in waiting out its timeout on
    // a session that may be live.
    if status == 429 {
        return Err(ReadFailure::Throttled { retry_after });
    }
    if (500..600).contains(&status) {
        return Err(ReadFailure::Upstream(format!(
            "Robinhood returned HTTP {status}{}",
            detail_suffix(&body())
        )));
    }
    // A lapsed session frequently comes back as a login page with a 200, not a
    // 401 — so from here shape, not status, decides.
    if looks_like_html(text) {
        return Err(ReadFailure::Html {
            status,
            url: url.to_string(),
        });
    }
    if status == 401 || status == 403 {
        return Err(ReadFailure::Rejected {
            status,
            detail: provider_detail(&body()).map(str::to_string),
            json_body: serde_json::from_str::<Value>(text).is_ok(),
        });
    }
    if status == 404 {
        return Err(ReadFailure::NotFound {
            url: url.to_string(),
        });
    }
    if !(200..300).contains(&status) {
        return Err(ReadFailure::Upstream(format!(
            "Robinhood returned HTTP {status}{}",
            detail_suffix(&body())
        )));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text)
        .map_err(|e| ReadFailure::Upstream(format!("parsing Robinhood JSON (HTTP {status}): {e}")))
}

fn header_value(resp: &reqwest::blocking::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// A throttle is upstream (exit 5), and the wait is the actionable part.
fn throttled(retry_after: Option<&str>) -> CliError {
    CliError::Upstream(throttled_message(retry_after))
}

fn throttled_message(retry_after: Option<&str>) -> String {
    match retry_after {
        Some(secs) => {
            format!("Robinhood is rate limiting this client (HTTP 429) — retry in {secs}s")
        }
        None => "Robinhood is rate limiting this client (HTTP 429) — wait before retrying".into(),
    }
}

/// An HTML answer to a password login. The browser sign-in is the way around it, since
/// it does not go through this client.
fn html_at_login(status: u16) -> CliError {
    CliError::Auth(format!(
        "expected JSON but got an HTML page (HTTP {status}) — run `{RELOGIN}`"
    ))
}

/// An HTML answer to a renewal, which is a read of the token endpoint: a block on this
/// client outlasts a new sign-in ([`edge_block_advice`]), so it comes last unless the
/// status says otherwise.
fn html_at_renewal(status: u16) -> CliError {
    if status == 401 || (500..600).contains(&status) {
        return html_at_login(status);
    }
    CliError::Auth(format!(
        "expected JSON from the session renewal but got an HTML page (HTTP {status}), most \
         likely a bot check. {}",
        edge_block_advice(RELOGIN)
    ))
}

fn parse_json(text: &str, status: u16, on_html: fn(u16) -> CliError) -> Result<Value, CliError> {
    if looks_like_html(text) {
        return Err(on_html(status));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text)
        .map_err(|e| CliError::Upstream(format!("parsing Robinhood JSON (HTTP {status}): {e}")))
}

fn looks_like_html(text: &str) -> bool {
    // Slice as bytes: a byte-index slice of the &str itself panics when 256
    // lands inside a multi-byte character. Lossy is fine here — the input is
    // already valid UTF-8, and the markers are ASCII.
    let head = text.trim_start().as_bytes();
    let lower = String::from_utf8_lossy(&head[..head.len().min(256)]).to_lowercase();
    lower.starts_with("<!doctype html") || lower.starts_with("<html") || lower.starts_with("<?xml")
}

/// Build the error for a failed login from the provider's own body.
///
/// The "Unable to log in with provided credentials" case is deliberately not
/// reported as a flat "wrong password": Robinhood returns that **same** body
/// when it blocks a client it thinks is impersonating a browser. Telling the
/// user only "wrong password" there sends them to reset a password that works.
fn login_error(v: &Value, status: u16) -> CliError {
    if (500..600).contains(&status) {
        return CliError::Upstream(format!(
            "Robinhood returned HTTP {status}{}",
            detail_suffix(v)
        ));
    }
    let detail = v.get("detail").and_then(Value::as_str).unwrap_or_default();
    if detail.starts_with("Unable to log in with provided credentials") {
        return CliError::Auth(
            "Robinhood said: \"Unable to log in with provided credentials.\" — usually a wrong \
             username or password, but Robinhood returns this same message when it blocks a \
             client it believes is impersonating a browser. Check the credential first; if it \
             is definitely right, see docs/api.md."
                .into(),
        );
    }
    CliError::Auth(format!(
        "Robinhood did not complete the login (HTTP {status}){}",
        detail_suffix(v)
    ))
}

/// The provider's own message, as a `": …"` suffix, when it gave one. Never
/// includes the request body (which holds the password).
fn detail_suffix(v: &Value) -> String {
    provider_detail(v)
        .map(|s| format!(": {s}"))
        .unwrap_or_default()
}

/// The provider's own message, when it gave one.
fn provider_detail(v: &Value) -> Option<&str> {
    ["detail", "error_description", "message", "error"]
        .into_iter()
        .find_map(|key| v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rh() -> Rh {
        Rh::new().expect("client builds")
    }

    #[test]
    fn a_token_response_becomes_a_session() {
        let v = json!({
            "access_token": "dummy-access",
            "refresh_token": "dummy-refresh",
            "expires_in": 86400,
            "token_type": "Bearer",
            "read_only_secondary_access_token": "dummy-readonly",
        });
        let t = Tokens::from_response(&v).unwrap();
        assert_eq!(t.access_token, "dummy-access");
        assert_eq!(t.refresh_token.as_deref(), Some("dummy-refresh"));
        assert_eq!(t.read_only_token.as_deref(), Some("dummy-readonly"));
        assert!(!t.is_expired());
        assert!(t.expires_at_rfc3339().is_some());
    }

    #[test]
    fn a_response_without_a_token_is_an_upstream_error() {
        // Not an auth error: the credentials may have been fine and the shape
        // changed underneath us. "Wrong password" there sends the user to
        // reset a password that works.
        let err = Tokens::from_response(&json!({"token_type": "Bearer"})).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn an_expiry_in_the_past_is_expired_and_an_unknown_one_is_not() {
        let mut t = Tokens::from_response(&json!({"access_token": "x"})).unwrap();
        assert!(!t.is_expired(), "unknown expiry must defer to the server");
        t.expires_at = Some(now_unix() - 1);
        assert!(t.is_expired());
        t.expires_at = Some(now_unix() + 3600);
        assert!(!t.is_expired());
    }

    #[test]
    fn tokens_round_trip_through_the_keychain_encoding() {
        let t = Tokens::from_response(&json!({
            "access_token": "a", "refresh_token": "r", "expires_in": 10
        }))
        .unwrap();
        let back = Tokens::from_json(t.to_secret().expose()).unwrap();
        assert_eq!(back.access_token, "a");
        assert_eq!(back.refresh_token.as_deref(), Some("r"));
        assert_eq!(back.expires_at, t.expires_at);
    }

    #[test]
    fn unreadable_cached_session_is_an_auth_error_not_a_crash() {
        assert_eq!(Tokens::from_json("not json").unwrap_err().exit_code(), 3);
    }

    /// Every bundle stored before 0.2.0 has neither field; it must keep
    /// reading as a password session, and a password bundle must keep
    /// serializing without them.
    #[test]
    fn a_bundle_without_an_origin_is_a_password_session() {
        let t = Tokens::from_json(r#"{"access_token":"a","refresh_token":"r"}"#).unwrap();
        assert_eq!(t.origin, Origin::Password);
        assert_eq!(t.device_token, None);
        let raw = t.to_secret().expose().to_string();
        assert!(!raw.contains("origin"), "{raw}");
        assert!(!raw.contains("device_token"), "{raw}");
    }

    #[test]
    fn an_imported_bundle_round_trips_its_origin_and_device() {
        let mut t = Tokens::from_response(&json!({"access_token": "a"})).unwrap();
        t.origin = Origin::WebAuthState;
        t.device_token = Some("00000000-0000-4000-8000-000000000001".into());
        let back = Tokens::from_json(t.to_secret().expose()).unwrap();
        assert_eq!(back.origin, Origin::WebAuthState);
        assert_eq!(back.device_token, t.device_token);
    }

    /// A refresh response carries neither field, so renewal has to carry
    /// them, or the second renewal of an imported session presents the
    /// wrong device.
    #[test]
    fn renewal_keeps_the_origin_and_the_device() {
        let mut old = Tokens::from_response(&json!({"access_token": "old"})).unwrap();
        old.origin = Origin::WebAuthState;
        old.device_token = Some("browser-device".into());
        let fresh = Tokens::from_response(&json!({"access_token": "new", "refresh_token": "r2"}))
            .unwrap()
            .renewed(&old);
        assert_eq!(fresh.access_token, "new");
        assert_eq!(fresh.refresh_token.as_deref(), Some("r2"));
        assert_eq!(fresh.origin, Origin::WebAuthState);
        assert_eq!(fresh.device_token.as_deref(), Some("browser-device"));
    }

    /// An imported session renews with the browser's device or none, never
    /// with the profile's own device token; a password session keeps using
    /// the profile's.
    #[test]
    fn refresh_presents_the_device_the_session_belongs_to() {
        let mut t = Tokens::from_response(&json!({"access_token": "a"})).unwrap();
        assert_eq!(
            t.refresh_device(Some("profile-device")),
            Some("profile-device")
        );

        t.origin = Origin::WebAuthState;
        assert_eq!(t.refresh_device(Some("profile-device")), None);
        t.device_token = Some("browser-device".into());
        assert_eq!(
            t.refresh_device(Some("profile-device")),
            Some("browser-device")
        );

        t.origin = Origin::Bearer;
        t.device_token = None;
        assert_eq!(t.refresh_device(Some("profile-device")), None);
    }

    #[test]
    fn a_successful_login_is_a_session() {
        let v = json!({ "access_token": "t", "expires_in": 100 });
        assert!(matches!(
            rh().interpret_login(&v, "d").unwrap(),
            LoginOutcome::Session(_)
        ));
    }

    #[test]
    fn the_legacy_challenge_object_is_recognized() {
        let v = json!({
            "detail": "Request blocked, prompt challenge issued.",
            "challenge": {
                "id": "00000000-0000-4000-8000-000000000002",
                "type": "sms",
                "status": "issued",
                "remaining_attempts": 3
            }
        });
        match rh().interpret_login(&v, "dev-token").unwrap() {
            LoginOutcome::NeedsApproval { parked, .. } => {
                assert_eq!(parked.flow, Flow::Challenge);
                assert_eq!(parked.kind, ChallengeKind::Code);
                assert_eq!(parked.device_token, "dev-token");
            }
            _ => panic!("expected a challenge"),
        }
    }

    /// A `prompt` challenge has no code to type — misclassifying it as a code
    /// challenge would leave the user waiting for an SMS that never arrives.
    #[test]
    fn a_prompt_challenge_is_not_a_code_challenge() {
        let v = json!({
            "challenge": { "id": "x", "type": "prompt", "status": "issued" }
        });
        match rh().interpret_login(&v, "d").unwrap() {
            LoginOutcome::NeedsApproval { parked, hint } => {
                assert_eq!(parked.kind, ChallengeKind::Prompt);
                assert!(hint.contains("app"), "{hint}");
            }
            _ => panic!("expected a challenge"),
        }
    }

    #[test]
    fn mfa_required_is_recognized() {
        let v = json!({ "mfa_required": true, "mfa_type": "sms" });
        match rh().interpret_login(&v, "dev-token").unwrap() {
            LoginOutcome::NeedsApproval { parked, hint } => {
                assert_eq!(parked.flow, Flow::Mfa);
                assert!(hint.contains("sms"));
            }
            _ => panic!("expected an MFA prompt"),
        }
    }

    #[test]
    fn an_unrecognized_login_shape_is_upstream_not_auth() {
        // Saying "bad password" for a shape change would be a lie, and would
        // send the user to rotate a working credential.
        let err = rh()
            .interpret_login(&json!({"something": "new"}), "d")
            .unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    /// The sheriff challenge appears at two different paths in real captures;
    /// reading only one of them breaks against half the responses.
    #[test]
    fn the_sheriff_challenge_is_found_at_either_path() {
        let a = json!({ "context": { "sheriff_challenge": { "id": "1", "type": "app" } } });
        assert_eq!(sheriff_challenge(&a).unwrap()["id"], "1");

        let b = json!({
            "type_context": { "context": { "sheriff_challenge": { "id": "2", "type": "sms" } } }
        });
        assert_eq!(sheriff_challenge(&b).unwrap()["id"], "2");

        assert!(sheriff_challenge(&json!({"context": null})).is_none());
    }

    #[test]
    fn workflow_approval_requires_the_approved_status() {
        assert!(workflow_approved(&json!({
            "type_context": { "result": "workflow_status_approved" }
        })));
        assert!(workflow_approved(&json!({
            "verification_workflow": { "workflow_status": "workflow_status_approved" }
        })));
        // Anything else is not approval — pending must never read as success.
        assert!(!workflow_approved(&json!({
            "verification_workflow": { "workflow_status": "workflow_status_internal_pending" }
        })));
        assert!(!workflow_approved(&json!({})));
    }

    #[test]
    fn challenge_status_is_read_from_either_shape() {
        assert_eq!(
            challenge_status(&json!({"status": "validated"})),
            Some("validated")
        );
        assert_eq!(
            challenge_status(&json!({"challenge": {"status": "validated"}})),
            Some("validated")
        );
        assert_eq!(challenge_status(&json!({})), None);
    }

    /// The bot-block trap: this exact message is also what a UA-impersonation
    /// block returns, so the error must not assert "wrong password".
    #[test]
    fn a_credentials_rejection_mentions_both_causes() {
        let err = login_error(
            &json!({"detail": "Unable to log in with provided credentials."}),
            400,
        );
        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(msg.contains("Unable to log in"));
        assert!(
            msg.contains("impersonating"),
            "must not claim only a bad password"
        );
    }

    #[test]
    fn a_server_error_during_login_is_upstream_not_auth() {
        assert_eq!(login_error(&json!({}), 503).exit_code(), 5);
    }

    #[test]
    fn a_throttle_surfaces_the_retry_delay() {
        let err = throttled(Some("51"));
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("51"));
        assert_eq!(throttled(None).exit_code(), 5);
    }

    /// The full accept/reject matrix for download verification lives with
    /// the mechanism in `pk_cli_documents::verify`. This pins only what is
    /// rhd's to promise — the honesty rule's boundary, checked here so a
    /// loosened cli-common re-pin fails this repo rather than arriving
    /// silently: the CSV-1099 head observed live passes as csv and fails the
    /// default rule; a real PDF passes as pdf; an expired-link error body
    /// declared as pdf never counts as a document.
    #[test]
    fn the_live_csv_1099_finding_stays_pinned() {
        assert!(verify_download(b"1099-DIV,ACCOUNT NUMBER,TAX YEAR\n", Some("csv")).is_ok());
        assert!(verify_download(b"1099-DIV,ACCOUNT NUMBER,TAX YEAR\n", None).is_err());
        assert!(verify_download(b"%PDF-1.7\n...", Some("pdf")).is_ok());
        assert!(verify_download(b"<!DOCTYPE html><html>Sign in</html>", Some("pdf")).is_err());
    }

    #[test]
    fn html_is_treated_as_a_lapsed_session_not_as_data() {
        let err = parse_json("<!DOCTYPE html><html>login</html>", 200, html_at_login).unwrap_err();
        assert_eq!(err.exit_code(), 3, "200-with-HTML is an auth failure");
    }

    #[test]
    fn an_empty_body_parses_as_null_rather_than_failing() {
        assert_eq!(parse_json("", 200, html_at_login).unwrap(), Value::Null);
    }

    #[test]
    fn html_detection_tolerates_leading_whitespace_and_short_bodies() {
        assert!(looks_like_html("   \n<html>"));
        assert!(looks_like_html("<!DOCTYPE HTML PUBLIC"));
        assert!(!looks_like_html("{\"results\": []}"));
        assert!(!looks_like_html(""));
        // A multi-byte character straddling the 256-byte window must not
        // panic the slice (review finding, PR #1).
        let mut long = "<html>".to_string();
        long.push_str(&"a".repeat(249));
        long.push_str("é and more");
        assert!(looks_like_html(&long));
    }

    #[test]
    fn detail_suffix_prefers_the_providers_own_fields() {
        assert_eq!(detail_suffix(&json!({"detail": "nope"})), ": nope");
        assert_eq!(
            detail_suffix(&json!({"error_description": "bad grant"})),
            ": bad grant"
        );
        assert_eq!(detail_suffix(&json!({})), "");
        assert_eq!(detail_suffix(&Value::Null), "");
        // An empty string must not produce a dangling colon.
        assert_eq!(detail_suffix(&json!({"detail": ""})), "");
    }

    #[test]
    fn device_tokens_are_unique_and_uuid_shaped() {
        let a = Rh::new_device_token();
        assert_ne!(a, Rh::new_device_token());
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
    }

    #[test]
    fn parked_state_round_trips_and_carries_no_secret() {
        let p = Parked {
            flow: Flow::Workflow,
            kind: ChallengeKind::Prompt,
            workflow_id: Some("wf".into()),
            machine_id: Some("m".into()),
            challenge_id: Some("c".into()),
            device_token: "dev".into(),
        };
        let raw = serde_json::to_string(&p).unwrap();
        assert!(!raw.to_lowercase().contains("password"));
        let back: Parked = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.flow, Flow::Workflow);
        assert_eq!(back.kind, ChallengeKind::Prompt);
        assert_eq!(back.machine_id.as_deref(), Some("m"));
    }

    /// The origin gate for provider-supplied links: anything that would send
    /// the bearer token off the API host is refused, including the classic
    /// prefix-confusion host.
    #[test]
    fn same_origin_accepts_the_api_host_and_nothing_else() {
        let c = rh();
        assert!(c.same_origin("https://api.robinhood.com"));
        assert!(c.same_origin("https://api.robinhood.com/"));
        assert!(c.same_origin("https://api.robinhood.com/orders/?cursor=x"));
        assert!(c.same_origin("https://api.robinhood.com?cursor=x"));

        assert!(!c.same_origin("https://api.robinhood.com.evil.example/"));
        assert!(!c.same_origin("https://api.robinhood.com:8443/"));
        assert!(!c.same_origin("https://evil.example/api.robinhood.com/"));
        assert!(!c.same_origin("http://api.robinhood.com/"));
        assert!(!c.same_origin("/accounts/"));
        assert!(!c.same_origin(""));
    }

    /// The bonfire listing's cursor stays on bonfire: the API host does not
    /// count as "its" origin, and neither does a prefix-confusion host.
    #[test]
    fn another_origin_is_held_to_itself() {
        let b = crate::config::BONFIRE_BASE;
        assert!(same_origin_of(
            b,
            "https://bonfire.robinhood.com/acats/?cursor=x"
        ));
        assert!(!same_origin_of(b, "https://api.robinhood.com/acats/"));
        assert!(!same_origin_of(
            b,
            "https://bonfire.robinhood.com.evil.example/"
        ));
    }

    #[test]
    fn urls_resolve_against_the_base_and_pass_absolutes_through() {
        let c = rh();
        assert_eq!(c.url("/accounts/"), "https://api.robinhood.com/accounts/");
        assert_eq!(
            c.url("https://api.robinhood.com/orders/?cursor=x"),
            "https://api.robinhood.com/orders/?cursor=x"
        );
    }

    /// `{:?}` on a session — in a log line, a panic, a failed assertion —
    /// must never print a credential.
    #[test]
    fn debug_output_redacts_every_credential() {
        let t = Tokens {
            access_token: "SAMPLE-ACCESS-SECRET".into(),
            refresh_token: Some("SAMPLE-REFRESH-SECRET".into()),
            expires_at: Some(1),
            read_only_token: Some("SAMPLE-READONLY-SECRET".into()),
            origin: Origin::WebAuthState,
            device_token: Some("00000000-0000-4000-8000-00000000d0d0".into()),
        };
        let p = Parked {
            flow: Flow::Workflow,
            kind: ChallengeKind::Prompt,
            workflow_id: Some("wf".into()),
            machine_id: None,
            challenge_id: None,
            device_token: "00000000-0000-4000-8000-00000000d0d0".into(),
        };
        let shown = format!(
            "{t:?} {:?} {p:?}",
            LoginOutcome::Session(Box::new(t.clone()))
        );
        for secret in [
            "SAMPLE-ACCESS-SECRET",
            "SAMPLE-REFRESH-SECRET",
            "SAMPLE-READONLY-SECRET",
            "d0d0",
        ] {
            assert!(!shown.contains(secret), "Debug printed {secret}: {shown}");
        }
        // Still useful for debugging: the non-secret fields show.
        assert!(shown.contains("WebAuthState"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
        // An absent token stays visibly absent rather than "redacted".
        let bare = Tokens::from_response(&json!({"access_token": "x"})).unwrap();
        assert!(format!("{bare:?}").contains("refresh_token: None"));
    }

    /// The classification behind every read: the cause carries no advice,
    /// and an ordinary read's error adds the login advice to the auth class
    /// only.
    #[test]
    fn a_failed_read_keeps_its_cause_apart_from_the_advice() {
        let url = "https://api.robinhood.com/accounts/";
        let rejected = classify(
            401,
            url,
            None,
            r#"{"detail":"Incorrect authentication credentials."}"#,
        )
        .unwrap_err();
        assert!(rejected.is_auth());
        assert_eq!(
            rejected.cause(),
            "Robinhood rejected the request (HTTP 401): Incorrect authentication credentials."
        );
        let err = rejected.into_cli_error();
        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string()
                .contains("run `rhd auth login --browser --overwrite`"),
            "{err}"
        );

        let html = classify(200, url, None, "<!DOCTYPE html><html>").unwrap_err();
        assert!(html.is_auth());
        assert!(!html.cause().contains("rhd auth login"));
        assert_eq!(html.into_cli_error().exit_code(), 3);

        let throttled = classify(429, url, Some("51".into()), "{}").unwrap_err();
        assert!(!throttled.is_auth());
        assert!(throttled.cause().contains("51"));
        assert_eq!(throttled.into_cli_error().exit_code(), 5);

        let missing = classify(404, url, None, "{}").unwrap_err();
        assert_eq!(missing.into_cli_error().exit_code(), 4);

        let down = classify(503, url, None, r#"{"detail":"maintenance"}"#).unwrap_err();
        assert_eq!(down.cause(), "Robinhood returned HTTP 503: maintenance");
        assert_eq!(down.into_cli_error().exit_code(), 5);

        // A throttle or an outage is no verdict on the session, whatever its
        // body. On an ordinary read, HTML on any other status still reads as a
        // refusal.
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        let throttled = classify(429, url, Some("51".into()), PAGE).unwrap_err();
        assert!(matches!(throttled, ReadFailure::Throttled { .. }));
        for status in [500, 502, 503, 504] {
            let down = classify(status, url, None, PAGE).unwrap_err();
            assert!(!down.is_auth(), "{status}");
            assert_eq!(down.into_cli_error().exit_code(), 5, "{status}");
        }
        assert!(classify(403, url, None, PAGE).unwrap_err().is_auth());

        assert_eq!(
            classify(200, url, None, r#"{"results":[]}"#).unwrap(),
            json!({"results": []})
        );
        assert_eq!(classify(200, url, None, "").unwrap(), Value::Null);
        assert!(!classify(200, url, None, "{nope").unwrap_err().is_auth());
    }

    /// Only a 401 or Robinhood's own JSON refuses a token for certain. What an ordinary
    /// read takes as an auth failure can still be no verdict.
    #[test]
    fn only_a_401_or_the_providers_json_is_a_definite_refusal() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        let url = "https://api.robinhood.com/accounts/";
        for (status, body) in [
            (401, "{}"),
            (401, ""),
            (401, "Unauthorized"),
            (401, PAGE),
            (403, "{}"),
            (403, r#"{"detail":"dummy refusal"}"#),
        ] {
            let failure = classify(status, url, None, body).unwrap_err();
            assert!(failure.is_auth(), "{status} {body}");
            assert!(failure.definite_refusal().is_some(), "{status} {body}");
        }
        for (status, body) in [(200, PAGE), (403, PAGE), (403, ""), (403, "Forbidden")] {
            let failure = classify(status, url, None, body).unwrap_err();
            assert!(failure.is_auth(), "{status} {body}");
            assert_eq!(failure.definite_refusal(), None, "{status} {body}");
            let why = failure.inconclusive_cause();
            assert!(why.contains(&format!("HTTP {status}")), "{why}");
            assert!(why.contains("no verdict"), "{why}");
            assert!(!why.contains("lapsed"), "{why}");
        }
    }

    /// An ordinary read's error for an answer shaped like a block at the edge says what
    /// a sign-in's warning says, at the same exit code. A definite refusal names the
    /// login at once.
    #[test]
    fn an_edge_shaped_read_puts_the_sign_in_last_unless_it_was_refused() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        let url = "https://example.test/dummy";
        for (status, body) in [
            (200, PAGE),
            (403, PAGE),
            (404, PAGE),
            (403, ""),
            (403, "Forbidden"),
        ] {
            let failure = classify(status, url, None, body).unwrap_err();
            assert!(failure.is_edge_shaped(), "{status} {body}");
            let err = failure.into_cli_error();
            assert_eq!(err.exit_code(), 3, "{status} {body}: {err}");
            let text = err.to_string();
            assert!(text.contains(&edge_block_advice(RELOGIN)), "{text}");
            let wait = text.find("wait or try another network").unwrap();
            let login = text.find(&format!("`{RELOGIN}`")).unwrap();
            assert!(wait < login, "{text}");
        }
        for (status, body) in [
            (401, PAGE),
            (401, ""),
            (403, "{}"),
            (403, r#"{"detail":"dummy refusal"}"#),
        ] {
            let failure = classify(status, url, None, body).unwrap_err();
            assert!(!failure.is_edge_shaped(), "{status} {body}");
            let err = failure.into_cli_error();
            assert_eq!(err.exit_code(), 3, "{status} {body}: {err}");
            let text = err.to_string();
            assert!(text.contains(&format!("run `{RELOGIN}`")), "{text}");
            assert!(!text.contains(SIGN_IN_MAY_NOT_HELP), "{text}");
        }
        for failure in [
            classify(429, url, None, PAGE).unwrap_err(),
            classify(503, url, None, PAGE).unwrap_err(),
            classify(200, url, None, "{nope").unwrap_err(),
            classify(404, url, None, "{}").unwrap_err(),
        ] {
            assert!(!failure.is_edge_shaped(), "{failure:?}");
        }
    }

    /// A renewal is a read of the token endpoint, so an HTML page there puts the sign-in
    /// last too. The password login's remedy is the browser sign-in, so it keeps naming it.
    #[test]
    fn html_at_a_renewal_puts_the_sign_in_last() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        for status in [200, 403] {
            let err = parse_json(PAGE, status, html_at_renewal).unwrap_err();
            assert_eq!(err.exit_code(), 3, "{err}");
            assert!(
                err.to_string().contains(&edge_block_advice(RELOGIN)),
                "{err}"
            );
        }
        for err in [
            parse_json(PAGE, 401, html_at_renewal).unwrap_err(),
            parse_json(PAGE, 503, html_at_renewal).unwrap_err(),
            parse_json(PAGE, 403, html_at_login).unwrap_err(),
        ] {
            assert_eq!(err.exit_code(), 3, "{err}");
            assert!(
                err.to_string().ends_with(&format!("run `{RELOGIN}`")),
                "{err}"
            );
        }
    }

    /// The pacing rail: two back-to-back calls must be spaced, or a paginated
    /// read can trip a throttle that costs hours.
    #[test]
    fn requests_are_paced() {
        let c = rh();
        let start = Instant::now();
        c.pace();
        c.pace();
        assert!(start.elapsed() >= MIN_REQUEST_GAP);
    }
}
