//! `rhd profiles …` — managing the household's several Robinhood logins.
//!
//! See `config.rs` for why a "profile" here is a *login identity* and not a
//! `cli-common` domain profile.

use pk_cli_browser::BrowserError;
use pk_cli_config::ConfigStore;
use pk_cli_core::{CliError, CommonArgs, Paged};
use pk_cli_secrets::CredentialStore;
use serde::Serialize;

use crate::config::{self, Config};

/// One row of `profiles list` (`login-profile/v1`).
#[derive(Debug, Serialize)]
struct LoginProfile {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// Whether this is the profile used when `--profile` is omitted.
    ///
    /// Ordered before `account` deliberately: `account` is optional, so a
    /// profile without one would otherwise push `DEFAULT` ahead of `ACCOUNT`
    /// in the text table (columns are the first-seen union of keys) while JSON
    /// kept the struct order — and §1.4 requires the two to agree.
    default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// Only present with `--check`, which is what spends the keychain read.
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_stored: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_cached: Option<bool>,
}

/// List configured logins.
///
/// `check` is opt-in because reporting credential state means reading two
/// keychain items per profile, and on macOS a freshly-signed binary raises a
/// permission dialog for each one. The common case — "which profiles exist?"
/// — should cost nothing and work on a machine with no keychain at all.
pub fn list(common: &CommonArgs, cfg: &Config, check: bool) -> Result<(), CliError> {
    let default_name = cfg.resolve_profile(None);
    let creds = CredentialStore::for_binary(config::BIN);

    let mut rows = Vec::new();
    for (name, p) in &cfg.profiles {
        let (credential_stored, session_cached) = if check {
            (
                Some(creds.get(&config::password_key(name))?.is_some()),
                Some(creds.get(&config::token_key(name))?.is_some()),
            )
        } else {
            (None, None)
        };
        rows.push(LoginProfile {
            name: name.clone(),
            username: p.username.clone(),
            default: *name == default_name,
            account: p.account.clone(),
            credential_stored,
            session_cached,
        });
    }

    Paged::new("login-profile", rows).emit(common.json);
    Ok(())
}

/// Add a login profile. Idempotent on the name: re-running with new values
/// updates them rather than erroring, so fixing a typo'd username is easy.
pub fn add(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    name: &str,
    username: Option<&str>,
    account: Option<&str>,
) -> Result<(), CliError> {
    validate_name(name)?;
    let entry = cfg.profiles.entry(name.to_string()).or_default();
    if let Some(u) = username {
        entry.username = Some(u.to_string());
    }
    if let Some(a) = account {
        entry.account = Some(a.to_string());
    }
    // The first profile added becomes the default, so a single-login household
    // never has to think about profiles at all.
    if cfg.profiles.len() == 1 {
        cfg.default_profile = Some(name.to_string());
    }
    store.save(&cfg)?;
    if !common.quiet {
        eprintln!(
            "profile `{name}` saved — log in with `rhd auth login --browser --profile {name}`"
        );
    }
    Ok(())
}

/// Remove a profile, every keychain entry belonging to it and the Chrome
/// profile its browser sign-ins keep, so a later login under the same name
/// never opens already signed in as this one.
pub fn remove(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: Config,
    name: &str,
    force: bool,
) -> Result<(), CliError> {
    if !cfg.profiles.contains_key(name) {
        return Err(CliError::NotFound(format!(
            "no login profile named `{name}` (known: {})",
            cfg.profile_names()
        )));
    }
    // Destroys stored credentials, so it follows the family's mutation rule:
    // confirm interactively, exit 6 when there is nobody to ask.
    if !force {
        if !common.interactive() {
            return Err(CliError::ConfirmationRequired(format!(
                "removing profile `{name}` deletes its stored credentials and kept browser \
                 profile — pass --force"
            )));
        }
        eprint!("Remove profile `{name}`, its stored credentials and kept browser profile? [y/N] ");
        if !confirm()? {
            return Err(CliError::Other("aborted".into()));
        }
    }

    let creds = CredentialStore::for_binary(config::BIN);
    let browser = drop_profile(
        store,
        cfg,
        name,
        |key| creds.delete(key).map(|_| ()),
        || pk_cli_browser::forget_named_profile(config::BIN, name),
    )?;
    if !common.quiet {
        eprintln!(
            "profile `{name}` removed{}",
            if browser {
                "; browser profile removed"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// A removal's steps, each attempted whatever an earlier one did; `true` when
/// there was a browser profile to remove. The keychain and the profile's removal
/// are passed in, so a test can fail any step and reach neither the keychain nor
/// the owner's real profile ([`crate::commands::auth::logout_browser`]).
///
/// The one exception is the config entry. It goes last, and only once everything
/// else is clear, so the retry the error asks for can still find the login.
fn drop_profile(
    store: &ConfigStore,
    mut cfg: Config,
    name: &str,
    mut delete: impl FnMut(&str) -> Result<(), CliError>,
    forget_browser: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<bool, CliError> {
    let mut steps = crate::commands::auth::TeardownSteps::default();
    steps.step("the session", delete(&config::token_key(name)));
    if let Err(e) = delete(&config::pending_key(name)) {
        steps.failed("a half-finished login", e);
    }
    steps.step("the stored password", delete(&config::password_key(name)));
    steps.step("the device token", delete(&config::device_key(name)));
    let browser = steps.browser(forget_browser);
    const ENTRY: &str = "this login's config entry";
    if steps.is_clean() {
        cfg.profiles.remove(name);
        if cfg.default_profile.as_deref() == Some(name) {
            // Promote the sole survivor, if there is exactly one; otherwise leave
            // the choice to the user rather than picking arbitrarily.
            cfg.default_profile = (cfg.profiles.len() == 1)
                .then(|| cfg.profiles.keys().next().cloned())
                .flatten();
        }
        if let Err(e) = store.save(&cfg) {
            steps.failed(ENTRY, e);
        }
    } else {
        steps.remains(ENTRY);
    }
    steps.report(
        &format!("partly removed profile `{name}`"),
        &format!("rhd profiles remove {name} --force"),
    )?;
    Ok(browser)
}

/// Make `name` the default profile.
pub fn use_profile(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    name: &str,
) -> Result<(), CliError> {
    if !cfg.profiles.contains_key(name) {
        return Err(CliError::NotFound(format!(
            "no login profile named `{name}` (known: {}) — add it with `rhd profiles add {name}`",
            cfg.profile_names()
        )));
    }
    cfg.default_profile = Some(name.to_string());
    store.save(&cfg)?;
    if !common.quiet {
        eprintln!("default profile is now `{name}`");
    }
    Ok(())
}

/// Profile names become keychain account keys (`<name>/password`), so a name
/// containing `/` would let one profile's entries collide with another's, and
/// they name the Chrome profile a browser sign-in keeps.
fn validate_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(CliError::Usage("profile name must not be empty".into()));
    }
    if !config::profile_name_ok(name) {
        return Err(CliError::Usage(format!(
            "profile name `{name}` must be at most 64 letters, digits, `-`, or `_` \
             (it becomes part of a keychain entry name and a Chrome profile's directory)"
        )));
    }
    Ok(())
}

fn confirm() -> Result<bool, CliError> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("reading confirmation: {e}")))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_would_collide_in_the_keychain_are_rejected() {
        // `/` separates profile from key, so it must not appear in a name.
        assert!(validate_name("a/password").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("spouse joint").is_err());
        assert!(validate_name("primary").is_ok());
        assert!(validate_name("spouse-roth_2").is_ok());
    }

    #[test]
    fn a_name_too_long_for_a_browser_profile_is_rejected() {
        assert!(validate_name(&"a".repeat(64)).is_ok());
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    fn config_with(names: &[&str], default: &str) -> Config {
        let mut cfg = Config {
            default_profile: Some(default.into()),
            ..Config::default()
        };
        for name in names {
            cfg.profiles.insert((*name).into(), Default::default());
        }
        cfg
    }

    /// Removing a profile removes its browser profile only. A refusal (its
    /// window still open) leaves it configured, so the retry the message asks
    /// for finds it.
    #[test]
    fn removing_a_profile_removes_its_browser_profile_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let cfg = config_with(&["dummy-one", "dummy-two"], "dummy-one");
        store.save(&cfg).unwrap();

        let in_use = drop_profile(
            &store,
            cfg,
            "dummy-one",
            |_| Ok(()),
            || {
                Err(BrowserError::ProfileInUse(
                    "dummy: close that window".into(),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(in_use.exit_code(), 1);
        let message = in_use.to_string();
        for needle in [
            "partly removed profile `dummy-one`",
            "the session, the stored password and the device token are cleared",
            "the browser profile and this login's config entry remain",
            "`rhd profiles remove dummy-one --force` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
        let cfg: Config = store.load().unwrap();
        assert!(
            cfg.profiles.contains_key("dummy-one"),
            "must stay for the retry"
        );

        let profiles = dir.path().join("root");
        let one = profiles.join("piekstra.rhd/browser-profile-dummy-one");
        let two = profiles.join("piekstra.rhd/browser-profile-dummy-two");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let forget =
            || pk_cli_browser::forget_named_profile_in(&profiles, config::BIN, "dummy-one");
        assert!(drop_profile(&store, cfg, "dummy-one", |_| Ok(()), forget).unwrap());
        assert!(!one.exists());
        assert!(two.exists());

        let cfg: Config = store.load().unwrap();
        assert!(!cfg.profiles.contains_key("dummy-one"));
        assert_eq!(cfg.default_profile.as_deref(), Some("dummy-two"));
    }

    /// A keychain step that fails stops nothing: every other item is still
    /// tried and the browser profile still removed, and the exit code is that
    /// failure's. The config entry stays for the retry.
    #[test]
    fn a_failed_keychain_step_stops_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(config::BIN).with_override(Some(dir.path().join("c.json")));
        let cfg = config_with(&["dummy-one", "dummy-two"], "dummy-one");
        store.save(&cfg).unwrap();

        let root = dir.path().join("root");
        let kept = root.join("piekstra.rhd/browser-profile-dummy-one");
        std::fs::create_dir_all(&kept).unwrap();
        let password = config::password_key("dummy-one");
        let mut tried = 0;
        let err = drop_profile(
            &store,
            cfg,
            "dummy-one",
            |key| {
                tried += 1;
                if key == password {
                    Err(CliError::Auth("dummy: could not delete".into()))
                } else {
                    Ok(())
                }
            },
            || pk_cli_browser::forget_named_profile_in(&root, config::BIN, "dummy-one"),
        )
        .unwrap_err();
        assert_eq!(tried, 4);
        assert!(!kept.exists(), "the profile must be removed all the same");
        assert_eq!(err.exit_code(), 3, "{err}");
        let message = err.to_string();
        assert!(message.starts_with("partly removed profile "), "{message}");
        for needle in [
            "the stored password and this login's config entry remain",
            "dummy: could not delete",
            "`rhd profiles remove dummy-one --force` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
        let cfg: Config = store.load().unwrap();
        assert!(cfg.profiles.contains_key("dummy-one"));
    }

    #[test]
    fn a_rejected_name_is_a_usage_error() {
        assert_eq!(validate_name("bad/name").unwrap_err().exit_code(), 2);
    }

    /// Assert the DTO name here so a rename shows up as a test failure rather
    /// than a silent schema change for consumers.
    #[test]
    fn profile_rows_tag_the_login_schema() {
        let page = Paged::new(
            "login-profile",
            vec![LoginProfile {
                name: "primary".into(),
                username: None,
                default: true,
                account: None,
                credential_stored: None,
                session_cached: None,
            }],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "login-profile-list/v1");
        assert_eq!(v["items"][0]["name"], "primary");
        assert_eq!(v["items"][0]["default"], true);
        // Unchecked credential state is omitted, not null.
        assert!(v["items"][0].get("credential_stored").is_none());
    }
}
