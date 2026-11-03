//! Reading a session captured from a signed-in robinhood.com browser: the
//! one parser behind both `rhd auth login --browser` and `rhd auth login
//! --session-stdin` (docs/api.md §2.8).
//!
//! Two shapes, told apart by the first character:
//!
//! - **The web app's stored session** (`{…}`) — the value of
//!   `localStorage['web:auth_state']`, which the web app writes as the
//!   `/oauth2/token/` response verbatim (§2.7's key set). It carries a refresh
//!   token, so the import renews unattended. The browser's `device_id` cookie
//!   rides along as `device_token`: the device the web app itself presents
//!   when it renews.
//! - **A bearer token** — the `Authorization` header of any request to
//!   api.robinhood.com, with or without its `Bearer ` prefix (a header line
//!   or a "Copy as cURL" paste works too). No refresh token: the session ends
//!   when the token expires. Only `--session-stdin` takes this shape.
//!
//! Two ways in, one parser. `--browser` reads the stored session out of a
//! Chrome the owner signs in through ([`browser_capture`], over the DevTools
//! protocol with `pk-cli-browser`); `--session-stdin` reads what
//! the owner copied out of DevTools. Both hand the text to [`parse`], so they
//! store identical credentials.
//!
//! Pure: no network, no keychain. The caller checks the session with one
//! authenticated read before storing anything. No error here ever quotes the
//! input — it is a credential.

use pk_cli_browser::{Capture, HostRule};
use pk_cli_core::CliError;
use pk_cli_secrets::Secret;
use serde::Serialize;
use serde_json::Value;

use crate::client::{Origin, Tokens};

/// The localStorage key the web app keeps its session under.
pub const AUTH_STATE_KEY: &str = "web:auth_state";

/// Where `--browser` opens the sign-in window.
pub const LOGIN_URL: &str = "https://robinhood.com/login";

/// The only host the session is read from: the web app's own, which also
/// serves the login page. Exact, so no page on another robinhood.com host is
/// ever evaluated or closed.
pub const WEB_HOST: &str = "robinhood.com";

/// The browser's device id: a cookie the web app sets on robinhood.com and
/// presents as `device_token` when it renews (docs/api.md §2.8).
pub const DEVICE_COOKIE: &str = "device_id";

/// The URL the device cookie is read for, as the browser would send it.
const DEVICE_COOKIE_URL: &str = "https://robinhood.com/";

/// Evaluated in robinhood.com pages until the owner is signed in. Answers
/// `null` until `web:auth_state` holds a non-empty `access_token` (so the
/// tab is never closed on a half-written session), then the stored session
/// (accepted double-encoded) as JSON with the `device_id` cookie added as
/// `device_token`, or `device_token: null` when `document.cookie` cannot see
/// it: what the Console snippet in `--session-stdin`'s help copies.
///
/// It only reads: the launch clears the profile's site storage
/// (`commands::auth::browser_launch`). Whether what it reads is worth taking is the
/// confirm hook's call (`commands::auth::confirm_candidate`).
pub const SESSION_EXPRESSION: &str = "(() => { \
    const raw = localStorage['web:auth_state']; \
    if (!raw) return null; \
    let s; \
    try { s = JSON.parse(raw); if (typeof s === 'string') s = JSON.parse(s); } catch { return null; } \
    if (!s || !s.access_token) return null; \
    const d = (document.cookie.match(/(?:^|; )device_id=([^;]+)/) || [])[1]; \
    return JSON.stringify({ ...s, device_token: d || null }); \
})()";

/// What `--browser` reads: [`SESSION_EXPRESSION`] in pages on exactly
/// [`WEB_HOST`], plus the `device_id` cookie from the browser's jar, which
/// is there even if it is `HttpOnly`. The cookie is optional: the capture
/// never waits on it, and a session without it still imports (it renews
/// with no device, as a hand-copied `web:auth_state` does).
pub fn browser_capture() -> Result<Capture, CliError> {
    Ok(Capture::new("Robinhood", HostRule::exact(WEB_HOST)?)
        .expression(SESSION_EXPRESSION)
        .optional_cookie(DEVICE_COOKIE_URL, DEVICE_COOKIE)
        .hint("your password, then any code or approval Robinhood asks for"))
}

/// The expression's answer with `device_token` filled from the jar's
/// `device_id` cookie when the page could not read it (`document.cookie`
/// does not show an `HttpOnly` cookie). A device token the page did read is
/// kept. Anything but a JSON object passes through unchanged for [`parse`]
/// to judge, so this never decides what a session is.
pub fn fill_device_token(value: &str, cookie: Option<&str>) -> Secret {
    let Some(cookie) = cookie.map(str::trim).filter(|c| !c.is_empty()) else {
        return Secret::new(value);
    };
    let Ok(Value::Object(mut session)) = serde_json::from_str::<Value>(value) else {
        return Secret::new(value);
    };
    let missing = match session.get("device_token") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(_) => false,
    };
    if !missing {
        return Secret::new(value);
    }
    session.insert("device_token".into(), Value::String(cookie.to_string()));
    Secret::new(Value::Object(session).to_string())
}

/// How the session reached `rhd`. Serializes as `browser` / `stdin` — the
/// `source` field of `session-import/v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// `--browser`: read out of the sign-in window.
    Browser,
    /// `--session-stdin`: copied out of DevTools and piped in.
    Stdin,
}

impl Source {
    /// For messages: where the session was read from, and as which shape.
    pub fn read_as(self, shape: Shape) -> String {
        match self {
            Source::Browser => format!("read the browser sign-in's session as {}", shape.label()),
            Source::Stdin => format!("read stdin as {}", shape.label()),
        }
    }

    /// A session `rhd` cannot use: `paste` says what is wrong with the
    /// owner's paste and how to redo it (usage, exit 2); `stored` says what
    /// is wrong with what Robinhood's web app stored, which the owner cannot
    /// fix by signing in again (upstream, exit 5).
    fn refused(self, paste: String, stored: &str) -> CliError {
        match self {
            Source::Browser => CliError::Upstream(format!(
                "the session robinhood.com stored is not one rhd can read ({stored}); nothing \
                 was stored — `rhd auth login --help` has the DevTools fallback"
            )),
            Source::Stdin => CliError::Usage(paste),
        }
    }
}

/// Shortest string accepted as a bearer token. Robinhood's are JWTs of a
/// kilobyte or more; this only stops a stray word from being stored.
const MIN_TOKEN_LEN: usize = 20;

/// Which shape stdin held. Serializes as `web_auth_state` / `bearer` — the
/// `shape` field of `session-import/v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    WebAuthState,
    Bearer,
}

impl Shape {
    /// For messages: what the input was read as.
    pub fn label(self) -> &'static str {
        match self {
            Shape::WebAuthState => "the web:auth_state JSON",
            Shape::Bearer => "a bearer token",
        }
    }

    fn origin(self) -> Origin {
        match self {
            Shape::WebAuthState => Origin::WebAuthState,
            Shape::Bearer => Origin::Bearer,
        }
    }
}

/// A parsed capture, ready to be proved and stored.
#[derive(Debug)]
pub struct Captured {
    pub shape: Shape,
    pub tokens: Tokens,
}

/// Parse a captured session: `raw` is what stdin held, or the browser
/// capture's answer. `now` is Unix seconds, for the expiry check; `source`
/// only words the errors and picks their exit code.
pub fn parse(raw: &str, now: u64, source: Source) -> Result<Captured, CliError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(source.refused(
            "stdin was empty — pipe the captured session in: `pbpaste | rhd auth login \
             --session-stdin` (see `rhd auth login --help`)"
                .into(),
            "it was empty",
        ));
    }
    let captured = if raw.starts_with('{') || raw.starts_with('"') {
        from_auth_state(raw, source)?
    } else if source == Source::Browser {
        // The capture's expression answers with the stored session's JSON
        // or nothing; a browser sign-in never stores a bare bearer token.
        return Err(source.refused(String::new(), "it is not the web:auth_state JSON"));
    } else {
        from_bearer(raw, source)?
    };

    // An expired token would only spend the proving read on a certain 401.
    // The web app renews its own session when the page loads, so reloading
    // the tab and capturing again is the remedy. In a sign-in window this is
    // a session a kept profile still held as the page opened, so the capture
    // goes on waiting and this is what its timeout reports.
    if let Some(exp) = captured.tokens.expires_at {
        if exp <= now {
            let again = match source {
                Source::Stdin => {
                    "reload robinhood.com, which renews its session, and capture again"
                }
                Source::Browser => {
                    "the session in the window had expired; sign in again with `rhd auth login \
                     --browser --overwrite`, and check this machine's clock if a new session \
                     looks expired too"
                }
            };
            return Err(CliError::Auth(format!(
                "the captured access token ({}) expired at {} — {again}; nothing was stored",
                captured.shape.label(),
                pk_cli_core::dates::fmt_rfc3339(exp as i64)
            )));
        }
    }
    Ok(captured)
}

fn from_auth_state(raw: &str, source: Source) -> Result<Captured, CliError> {
    let v = auth_state_object(raw, source)?;
    let access_token = non_empty(&v, "access_token").ok_or_else(|| {
        source.refused(
            format!(
            "the pasted JSON has no `access_token` — copy the whole value of the `{AUTH_STATE_KEY}` \
             key (DevTools → Application → Local Storage → https://robinhood.com), or use the \
             Console snippet in `rhd auth login --help`"
            ),
            "it has no `access_token`",
        )
    })?;
    if let Some(kind) = v.get("token_type").and_then(Value::as_str) {
        if !kind.eq_ignore_ascii_case("bearer") {
            return Err(source.refused(
                format!(
                    "the pasted session's token_type is `{kind}`, not `Bearer` — this is not \
                     the `{AUTH_STATE_KEY}` value rhd knows how to use"
                ),
                &format!("its token_type is `{kind}`, not `Bearer`"),
            ));
        }
    }
    let device_token =
        match non_empty(&v, "device_token").or_else(|| non_empty(&v, "device_id")) {
            Some(d) if is_uuid(&d) => Some(d),
            Some(_) => return Err(source.refused(
                "the pasted `device_token` is not a device id (the web app's `device_id` cookie \
                 is a UUID, 8-4-4-4-12 hex) — re-run the Console snippet in `rhd auth login \
                 --help`"
                    .into(),
                "the browser's `device_id` cookie is not a device id (a UUID, 8-4-4-4-12 hex)",
            )),
            None => None,
        };
    Ok(Captured {
        shape: Shape::WebAuthState,
        tokens: Tokens {
            // `expires_in` is relative to when the web app was issued the
            // token, which the paste does not say, so it cannot date the
            // expiry. The JWT's own `exp` can (§2.8); absent that, the
            // expiry stays unknown and the server stays the authority.
            expires_at: pk_cli_auth::token::expiry(&access_token),
            access_token,
            refresh_token: non_empty(&v, "refresh_token"),
            read_only_token: non_empty(&v, "read_only_secondary_access_token"),
            origin: Shape::WebAuthState.origin(),
            device_token,
        },
    })
}

/// The `web:auth_state` object, also accepting it double-encoded (a JSON
/// string holding the JSON, as `JSON.stringify(localStorage[…])` gives) or
/// inside a whole-localStorage dump (`copy(localStorage)`).
fn auth_state_object(
    raw: &str,
    source: Source,
) -> Result<serde_json::Map<String, Value>, CliError> {
    let not_json = || {
        source.refused(
            "stdin starts like JSON but does not parse as JSON — copy the whole value of \
             `web:auth_state`, or use the Console snippet in `rhd auth login --help`"
                .into(),
            "it is not JSON",
        )
    };
    let mut v: Value = serde_json::from_str(raw).map_err(|_| not_json())?;
    if let Value::String(inner) = &v {
        v = serde_json::from_str(inner).map_err(|_| not_json())?;
    }
    if let Some(Value::String(inner)) = v.get(AUTH_STATE_KEY) {
        v = serde_json::from_str(inner).map_err(|_| not_json())?;
    }
    match v {
        Value::Object(map) => Ok(map),
        _ => Err(not_json()),
    }
}

fn from_bearer(raw: &str, source: Source) -> Result<Captured, CliError> {
    let token = bearer_token(raw).ok_or_else(|| {
        source.refused(
            "stdin held neither shape `--session-stdin` reads: the `web:auth_state` JSON (it \
             starts with `{`) or a bearer token (`Bearer …` from a request's Authorization \
             header) — see `rhd auth login --help`"
                .into(),
            "it is neither the web:auth_state JSON nor a bearer token",
        )
    })?;
    Ok(Captured {
        shape: Shape::Bearer,
        tokens: Tokens {
            expires_at: pk_cli_auth::token::expiry(&token),
            access_token: token,
            refresh_token: None,
            read_only_token: None,
            origin: Shape::Bearer.origin(),
            device_token: None,
        },
    })
}

/// The token out of `Bearer <t>`, `authorization: Bearer <t>`, a "Copy as
/// cURL" paste, or a bare token on its own.
fn bearer_token(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let token: String = match lower.find("bearer ") {
        Some(at) => raw[at + "bearer ".len()..]
            .trim_start()
            .chars()
            .take_while(|c| is_token_char(*c))
            .collect(),
        None if raw.chars().all(is_token_char) => raw.to_string(),
        None => return None,
    };
    (token.len() >= MIN_TOKEN_LEN).then_some(token)
}

/// RFC 6750's `b64token` alphabet, which a JWT's three dot-joined segments
/// stay inside.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/' | '=')
}

fn non_empty(v: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;
    const DEVICE: &str = "00000000-0000-4000-8000-000000000001";

    /// The `web:auth_state` value exactly as the web app stores it — the
    /// token response's key set (docs/api.md §2.8).
    fn auth_state() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/web_auth_state.json")).unwrap()
    }

    /// An unsigned JWT carrying `claims`. The header segment is a plain word
    /// rather than base64 JSON: nothing reads it, and a realistic one would
    /// make this file trip secret scanners.
    pub(crate) fn jwt(claims: &Value) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bytes = serde_json::to_vec(claims).unwrap();
        let mut payload = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..chunk.len() + 1 {
                payload.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        format!("header.{payload}.signature")
    }

    #[test]
    fn the_stored_web_session_imports_with_its_refresh_token() {
        let c = parse(&auth_state().to_string(), NOW, Source::Stdin).unwrap();
        assert_eq!(c.shape, Shape::WebAuthState);
        let t = &c.tokens;
        assert!(t.access_token.starts_with("SAMPLE-"));
        assert!(t.refresh_token.as_deref().unwrap().starts_with("SAMPLE-"));
        assert!(t.read_only_token.is_some());
        assert_eq!(t.origin, Origin::WebAuthState);
        // localStorage carries no device id; only the Console snippet adds it.
        assert_eq!(t.device_token, None);
        // Not a JWT, and `expires_in` cannot be dated: unknown, not invented.
        assert_eq!(t.expires_at, None);
    }

    #[test]
    fn the_console_snippets_device_id_travels_with_the_session() {
        let mut v = auth_state();
        v["device_token"] = json!(DEVICE);
        let c = parse(&v.to_string(), NOW, Source::Stdin).unwrap();
        assert_eq!(c.tokens.device_token.as_deref(), Some(DEVICE));

        // The cookie's own name is accepted too.
        let mut v = auth_state();
        v["device_id"] = json!(DEVICE);
        let c = parse(&v.to_string(), NOW, Source::Stdin).unwrap();
        assert_eq!(c.tokens.device_token.as_deref(), Some(DEVICE));
    }

    #[test]
    fn a_device_token_that_is_not_a_uuid_is_refused() {
        let mut v = auth_state();
        v["device_token"] = json!("not-a-device");
        assert_eq!(
            parse(&v.to_string(), NOW, Source::Stdin)
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn the_access_tokens_own_expiry_dates_the_session() {
        let mut v = auth_state();
        v["access_token"] = json!(jwt(&json!({"exp": NOW + 3600})));
        let c = parse(&v.to_string(), NOW, Source::Stdin).unwrap();
        assert_eq!(c.tokens.expires_at, Some(NOW + 3600));
    }

    /// An expired capture fails before the network: the proving read could
    /// only 401.
    #[test]
    fn an_expired_capture_is_refused_before_any_read() {
        let mut v = auth_state();
        v["access_token"] = json!(jwt(&json!({"exp": NOW - 1})));
        let err = parse(&v.to_string(), NOW, Source::Stdin).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("reload"), "{err}");

        let err = parse(
            &format!("Bearer {}", jwt(&json!({"exp": NOW}))),
            NOW,
            Source::Stdin,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn a_double_encoded_or_dumped_auth_state_still_reads() {
        let inner = auth_state().to_string();
        let quoted = serde_json::to_string(&inner).unwrap();
        assert_eq!(
            parse(&quoted, NOW, Source::Stdin).unwrap().shape,
            Shape::WebAuthState
        );

        let dump = json!({ "web:auth_state": inner, "web:auth_last_accessed_time": "1" });
        assert_eq!(
            parse(&dump.to_string(), NOW, Source::Stdin).unwrap().shape,
            Shape::WebAuthState
        );
    }

    #[test]
    fn json_without_an_access_token_is_a_usage_error() {
        let err = parse(
            r#"{"refresh_token":"SAMPLE-REFRESH-TOKEN"}"#,
            NOW,
            Source::Stdin,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("web:auth_state"), "{err}");
    }

    #[test]
    fn a_non_bearer_token_type_is_refused() {
        let mut v = auth_state();
        v["token_type"] = json!("mac");
        assert_eq!(
            parse(&v.to_string(), NOW, Source::Stdin)
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn broken_json_is_a_usage_error() {
        assert_eq!(
            parse("{\"access_token\": ", NOW, Source::Stdin)
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(
            parse("[1, 2]", NOW, Source::Stdin).unwrap_err().exit_code(),
            2
        );
    }

    #[test]
    fn a_bearer_header_value_imports_without_renewal() {
        let token = "SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL";
        for input in [
            format!("Bearer {token}"),
            format!("bearer {token}\n"),
            format!("authorization: Bearer {token}"),
            format!("Authorization: Bearer  {token}"),
            token.to_string(),
            format!(
                "curl 'https://api.robinhood.com/accounts/' -H 'accept: */*' -H \
                 'authorization: Bearer {token}' -H 'x-robinhood-api-version: 1.431.4'"
            ),
        ] {
            let c = parse(&input, NOW, Source::Stdin).unwrap_or_else(|e| panic!("{input:?}: {e}"));
            assert_eq!(c.shape, Shape::Bearer);
            assert_eq!(c.tokens.access_token, token, "{input:?}");
            assert_eq!(c.tokens.refresh_token, None);
            assert_eq!(c.tokens.origin, Origin::Bearer);
        }
    }

    #[test]
    fn a_bearer_jwt_keeps_its_expiry() {
        let token = jwt(&json!({"exp": NOW + 600}));
        let c = parse(&format!("Bearer {token}"), NOW, Source::Stdin).unwrap();
        assert_eq!(c.tokens.access_token, token);
        assert_eq!(c.tokens.expires_at, Some(NOW + 600));
    }

    #[test]
    fn neither_shape_is_a_usage_error() {
        for input in [
            "",
            "   \n",
            "hello there",
            "Bearer short",
            "my password is hunter2",
        ] {
            assert_eq!(
                parse(input, NOW, Source::Stdin).unwrap_err().exit_code(),
                2,
                "{input:?} must be refused"
            );
        }
    }

    /// The input is a credential: no message may quote it.
    #[test]
    fn no_error_quotes_the_input() {
        let secret = "SAMPLE-SECRET-THAT-MUST-NOT-ECHO";
        let mut bad_device = auth_state();
        bad_device["access_token"] = json!(secret);
        bad_device["device_token"] = json!("nope");
        let mut bad_type = auth_state();
        bad_type["access_token"] = json!(secret);
        bad_type["token_type"] = json!("mac");
        for input in [
            bad_device.to_string(),
            bad_type.to_string(),
            format!("{{\"refresh_token\": \"{secret}\"}}"),
            format!("{{\"access_token\": \"{secret}\""),
            format!("{secret} {secret}"),
        ] {
            let err = parse(&input, NOW, Source::Stdin).unwrap_err().to_string();
            assert!(!err.contains(secret), "error echoed the input: {err}");
        }
    }

    #[test]
    fn uuid_shape_check() {
        assert!(is_uuid(DEVICE));
        assert!(!is_uuid("00000000-0000-4000-8000-00000000000"));
        assert!(!is_uuid("0000000g-0000-4000-8000-000000000001"));
        assert!(!is_uuid(""));
    }

    /// A parsed capture holds live credentials; `{:?}` must not show them.
    #[test]
    fn a_capture_never_debug_prints_its_tokens() {
        let mut v = auth_state();
        v["device_token"] = json!(DEVICE);
        let captured = parse(&v.to_string(), NOW, Source::Stdin).unwrap();
        let shown = format!("{captured:?}");
        for secret in [
            v["access_token"].as_str().unwrap(),
            v["refresh_token"].as_str().unwrap(),
            v["read_only_secondary_access_token"].as_str().unwrap(),
            DEVICE,
        ] {
            assert!(!shown.contains(secret), "Debug printed a secret");
        }

        let bearer = parse(
            "Bearer SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL",
            NOW,
            Source::Stdin,
        )
        .unwrap();
        assert!(!format!("{bearer:?}").contains("SAMPLE-ACCESS-TOKEN"));
    }

    #[test]
    fn the_shape_serializes_as_its_dto_value() {
        assert_eq!(json!(Shape::WebAuthState), json!("web_auth_state"));
        assert_eq!(json!(Shape::Bearer), json!("bearer"));
        assert_eq!(json!(Source::Browser), json!("browser"));
        assert_eq!(json!(Source::Stdin), json!("stdin"));
    }

    // ------------------------------------------------ the --browser capture

    /// What the capture's expression answers once the owner is signed in
    /// and `document.cookie` cannot see the `device_id` cookie: the stored
    /// session with `device_token: null`.
    const BROWSER_SESSION: &str = include_str!("../tests/fixtures/browser_session.json");
    const OTHER_DEVICE: &str = "00000000-0000-4000-8000-000000000002";

    /// The definition `pk-cli-browser` checks before Chrome starts, checked
    /// here offline: a label, an expression, and a cookie URL on its host.
    #[test]
    fn the_browser_capture_is_well_formed() {
        let capture = browser_capture().unwrap();
        capture.validate().unwrap();
        assert_eq!(capture.label(), "Robinhood");
    }

    /// The window opens on the host the session is read from, and the rule
    /// is exact: no other robinhood.com host is read or closed.
    #[test]
    fn the_session_is_read_from_robinhood_com_only() {
        let host = HostRule::exact(WEB_HOST).unwrap();
        assert!(host.matches_url(LOGIN_URL));
        assert!(host.matches_url(DEVICE_COOKIE_URL));
        for other in [
            "https://api.robinhood.com/accounts/",
            "https://www.robinhood.com/login",
            "https://robinhood.com.example.invalid/login",
            "http://robinhood.com/login",
        ] {
            assert!(!host.matches_url(other), "{other} must not match");
        }
    }

    /// docs/api.md §2.8 records exactly what the capture runs.
    #[test]
    fn the_documented_expression_is_the_one_that_runs() {
        assert!(include_str!("../docs/api.md").contains(SESSION_EXPRESSION));
    }

    /// The expression reads the key the parser knows, waits for an access
    /// token, and names the cookie the jar is asked for.
    #[test]
    fn the_expression_reads_the_stored_session_and_the_device_cookie() {
        assert!(SESSION_EXPRESSION.contains(&format!("localStorage['{AUTH_STATE_KEY}']")));
        assert!(SESSION_EXPRESSION.contains("!s.access_token) return null"));
        assert!(SESSION_EXPRESSION.contains(&format!("(?:^|; ){DEVICE_COOKIE}=([^;]+)")));
        assert!(SESSION_EXPRESSION.contains("device_token: d || null"));
    }

    /// It only reads: the launch clears the profile's site storage.
    #[test]
    fn the_expression_only_reads() {
        for write in ["removeItem", "setItem", ".clear("] {
            assert!(!SESSION_EXPRESSION.contains(write), "{write}");
        }
    }

    /// The jar's cookie fills the device the page could not read, and the
    /// result is what the existing parser accepts: the same tokens a paste
    /// of that session with its device id gives, so `--browser` and
    /// `--session-stdin` store identical credentials.
    #[test]
    fn a_browser_capture_with_the_cookie_filled_imports_like_a_paste() {
        let filled = fill_device_token(BROWSER_SESSION, Some(DEVICE));
        let browser = parse(filled.expose(), NOW, Source::Browser).unwrap();
        assert_eq!(browser.shape, Shape::WebAuthState);
        let t = &browser.tokens;
        assert_eq!(t.device_token.as_deref(), Some(DEVICE));
        assert_eq!(t.origin, Origin::WebAuthState);
        assert!(t.refresh_token.as_deref().unwrap().starts_with("SAMPLE-"));
        assert!(t.read_only_token.is_some());

        let mut pasted = auth_state();
        pasted["device_token"] = json!(DEVICE);
        let stdin = parse(&pasted.to_string(), NOW, Source::Stdin).unwrap();
        assert_eq!(
            browser.tokens.to_secret().expose(),
            stdin.tokens.to_secret().expose()
        );
    }

    /// A device id the page did read is the one kept.
    #[test]
    fn the_pages_own_device_id_wins_over_the_jar() {
        let mut v: Value = serde_json::from_str(BROWSER_SESSION).unwrap();
        v["device_token"] = json!(DEVICE);
        let filled = fill_device_token(&v.to_string(), Some(OTHER_DEVICE));
        let c = parse(filled.expose(), NOW, Source::Browser).unwrap();
        assert_eq!(c.tokens.device_token.as_deref(), Some(DEVICE));
    }

    /// No cookie anywhere: the session still imports, with no device, as a
    /// hand-copied `web:auth_state` does. An empty cookie counts as none.
    #[test]
    fn without_the_cookie_the_session_imports_without_a_device() {
        for cookie in [None, Some(""), Some("  ")] {
            let filled = fill_device_token(BROWSER_SESSION, cookie);
            let c = parse(filled.expose(), NOW, Source::Browser).unwrap();
            assert_eq!(c.tokens.device_token, None, "{cookie:?}");
        }
    }

    /// An answer that is not a JSON object passes through untouched, for
    /// the parser to judge.
    #[test]
    fn filling_never_rewrites_what_is_not_a_session_object() {
        for value in ["[1, 2]", "not json", "\"quoted\""] {
            assert_eq!(fill_device_token(value, Some(DEVICE)).expose(), value);
        }
    }

    /// What the web app stored and rhd cannot read is Robinhood's shape, not
    /// the owner's mistake: exit 5, worded for the browser, never quoting
    /// the session.
    #[test]
    fn a_browser_session_rhd_cannot_read_is_upstream() {
        let secret = "SAMPLE-SECRET-THAT-MUST-NOT-ECHO";
        let mut bad_type: Value = serde_json::from_str(BROWSER_SESSION).unwrap();
        bad_type["access_token"] = json!(secret);
        bad_type["token_type"] = json!("mac");
        let bad_device = fill_device_token(
            &BROWSER_SESSION.replace("SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL", secret),
            Some("not-a-device"),
        );
        for input in [
            bad_type.to_string(),
            bad_device.expose().to_string(),
            format!("Bearer {secret}"),
            "{}".to_string(),
            String::new(),
        ] {
            let err = parse(&input, NOW, Source::Browser).unwrap_err();
            assert_eq!(err.exit_code(), 5, "{err}");
            let msg = err.to_string();
            assert!(msg.contains("robinhood.com stored"), "{msg}");
            assert!(msg.contains("nothing was stored"), "{msg}");
            assert!(!msg.contains("pasted"), "{msg}");
            assert!(!msg.contains(secret), "error echoed the session: {msg}");
        }
    }

    /// An expired session in the window is an old one the kept profile held;
    /// the remedy is the browser sign-in, not a reload.
    #[test]
    fn an_expired_browser_session_points_at_the_browser_login() {
        let mut v: Value = serde_json::from_str(BROWSER_SESSION).unwrap();
        v["access_token"] = json!(jwt(&json!({"exp": NOW - 1})));
        let err = parse(&v.to_string(), NOW, Source::Browser).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(msg.contains("rhd auth login --browser"), "{msg}");
        assert!(!msg.contains("reload"), "{msg}");
    }
}
