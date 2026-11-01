//! Non-secret settings, and the multi-login *profile* model that makes this
//! CLI different from its siblings.
//!
//! # Two levels of "multiple accounts"
//!
//! Robinhood stacks two of them, and conflating the two is the mistake this
//! module exists to prevent:
//!
//! 1. **Profiles** — separate *logins*. A household has several Robinhood
//!    accounts belonging to different people; each is its own username,
//!    password, device token, and OAuth session. Selected with
//!    `-p/--profile <NAME>` (env `RHD_PROFILE`).
//! 2. **Accounts** — the brokerage accounts *inside* one login. A single
//!    Robinhood login can hold an individual account, a joint account, an IRA,
//!    and so on, each with its own account number. Selected with the family's
//!    standard `-a/--account <ID>` (env `RHD_ACCOUNT`), per SPEC v1 §1.1.
//!
//! So `rhd -p spouse -a 1234567890 positions list` means "the login named
//! `spouse`, and within it the brokerage account ending 7890".
//!
//! # Naming collision, deliberately accepted
//!
//! `cli-common`'s `PROFILES.md` uses "profile" for a *domain vocabulary*
//! (`documents/v1`), and `info --json` reports those under a `profiles` key.
//! This module's profiles are *login identities* and are reported by `rhd
//! profiles list --json` under the schema `login-profile-list/v1`. The two
//! never appear in the same DTO, and the schema tags tell them apart, but the
//! word is overloaded — hence this note.
//!
//! # What lives where
//!
//! Only non-secret preferences land on disk. Everything that authenticates —
//! password, OAuth access/refresh token, device token, and any parked
//! mid-challenge login state — lives in the OS keychain under
//! `piekstra.rhd`, keyed by profile (see [`password_key`] and friends).

use std::collections::BTreeMap;

use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};

/// Binary name: keychain service (`piekstra.rhd`), config dir, env prefix.
pub const BIN: &str = "rhd";
/// Repo, for `info` and `self-update`.
pub const REPO: &str = "piekstra/robinhood-cli";
/// The community-documented private API root. See `docs/api.md`.
pub const API_BASE: &str = "https://api.robinhood.com";
/// The provider's second API host, which serves the ACATS listing
/// (docs/api.md §3.13). Same bearer token, its own origin.
pub const BONFIRE_BASE: &str = "https://bonfire.robinhood.com";

/// The profile name used when the user has never named one.
pub const DEFAULT_PROFILE: &str = "default";

/// Env var naming the active login profile.
pub const PROFILE_ENV: &str = "RHD_PROFILE";
/// Env var naming the active brokerage account number.
pub const ACCOUNT_ENV: &str = "RHD_ACCOUNT";

/// Keychain account for a profile's password.
pub fn password_key(profile: &str) -> String {
    format!("{profile}/password")
}

/// Keychain account for a profile's OAuth token bundle (JSON: access token,
/// refresh token, expiry).
pub fn token_key(profile: &str) -> String {
    format!("{profile}/token")
}

/// Keychain account for a profile's `device_token`.
///
/// This is the value that buys device trust: Robinhood ties an approved device
/// to it, so reusing the *same* token on later logins is what stops every run
/// from raising a fresh device-approval challenge. It is generated once
/// (a v4 UUID) and then never rotated — regenerating it is indistinguishable,
/// from the provider's side, from logging in on a brand-new device.
pub fn device_key(profile: &str) -> String {
    format!("{profile}/device")
}

/// Keychain account for an in-flight login parked mid-challenge.
///
/// A challenge/verification workflow is bound to the login attempt that
/// started it, so `rhd auth login --code <CODE>` has to resume *that* attempt.
/// Starting a fresh login and presenting the code against it would offer the
/// code to a workflow that never issued one. Single-use: deleted on the next
/// attempt whether it succeeds or fails, so a stale parked workflow can only
/// ever be replayed once and the provider's own rejection is the expiry
/// signal.
pub fn pending_key(profile: &str) -> String {
    format!("{profile}/pending")
}

/// On-disk, non-secret settings.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Profile used when neither `--profile` nor `$RHD_PROFILE` is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Named login profiles. `BTreeMap` so `config show` is deterministic.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, Profile>,
}

/// One named login: whose it is, and which brokerage account to act on by
/// default. No secrets — those are keychain-only.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The Robinhood username (an email address). Stored so `auth status` can
    /// report who a profile is for without a network call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Default brokerage account number within this login, for `-a`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

impl Config {
    /// Resolve the active profile name: flag > env > `default_profile` > the
    /// sole configured profile > [`DEFAULT_PROFILE`].
    ///
    /// The "sole configured profile" step is what keeps the single-account
    /// case ergonomic: a household that has only added one login never has to
    /// type `--profile`, but the moment a second is added the name becomes
    /// load-bearing and [`Config::require_profile`] starts insisting on it.
    pub fn resolve_profile(&self, flag: Option<&str>) -> String {
        if let Some(p) = flag {
            return p.to_string();
        }
        if let Ok(p) = std::env::var(PROFILE_ENV) {
            if !p.is_empty() {
                return p;
            }
        }
        if let Some(p) = &self.default_profile {
            return p.clone();
        }
        if self.profiles.len() == 1 {
            return self.profiles.keys().next().cloned().unwrap();
        }
        DEFAULT_PROFILE.to_string()
    }

    /// Resolve the profile and refuse to guess when the choice is ambiguous.
    ///
    /// With two or more logins configured and no default set, silently picking
    /// one would read the wrong household member's portfolio — so this is a
    /// usage error naming the available profiles instead.
    pub fn require_profile(&self, flag: Option<&str>) -> Result<String, CliError> {
        let name = self.resolve_profile(flag);
        if self.profiles.contains_key(&name) || self.profiles.is_empty() {
            return Ok(name);
        }
        if flag.is_some() || std::env::var(PROFILE_ENV).is_ok() {
            return Err(CliError::NotFound(format!(
                "no login profile named `{name}` (known: {})",
                self.profile_names()
            )));
        }
        Err(CliError::Usage(format!(
            "several login profiles are configured ({}) — choose one with \
             `--profile <NAME>`, or set a default with `rhd profiles use <NAME>`",
            self.profile_names()
        )))
    }

    /// Comma-separated profile names, for error messages.
    pub fn profile_names(&self) -> String {
        if self.profiles.is_empty() {
            return "none configured".into();
        }
        self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
    }

    /// The stored settings for a profile, if it has been added.
    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// Resolve the brokerage account number: flag > env > the profile's
    /// configured default > `None` (meaning "whatever the provider lists").
    pub fn resolve_account(&self, profile: &str, flag: Option<&str>) -> Option<String> {
        if let Some(a) = flag {
            return Some(a.to_string());
        }
        if let Ok(a) = std::env::var(ACCOUNT_ENV) {
            if !a.is_empty() {
                return Some(a);
            }
        }
        self.profile(profile).and_then(|p| p.account.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(names: &[&str]) -> Config {
        let mut c = Config::default();
        for n in names {
            c.profiles.insert((*n).to_string(), Profile::default());
        }
        c
    }

    /// Keychain accounts are namespaced per profile, so two household logins
    /// never share an entry.
    #[test]
    fn keychain_keys_are_profile_scoped() {
        assert_eq!(password_key("spouse"), "spouse/password");
        assert_eq!(token_key("spouse"), "spouse/token");
        assert_eq!(device_key("spouse"), "spouse/device");
        assert_eq!(pending_key("spouse"), "spouse/pending");
        // Different profiles cannot collide.
        assert_ne!(password_key("a"), password_key("b"));
    }

    #[test]
    fn flag_beats_default_beats_sole_profile() {
        let mut c = cfg_with(&["alice"]);
        // Sole configured profile is used when nothing else says otherwise.
        assert_eq!(c.resolve_profile(None), "alice");
        // An explicit default wins over the sole-profile shortcut.
        c.profiles.insert("bob".into(), Profile::default());
        c.default_profile = Some("bob".into());
        assert_eq!(c.resolve_profile(None), "bob");
        // The flag wins over everything.
        assert_eq!(c.resolve_profile(Some("alice")), "alice");
    }

    #[test]
    fn empty_config_falls_back_to_the_default_name() {
        assert_eq!(Config::default().resolve_profile(None), DEFAULT_PROFILE);
    }

    /// The safety rail: never silently read the wrong person's portfolio.
    #[test]
    fn ambiguous_multi_profile_is_a_usage_error() {
        let c = cfg_with(&["alice", "bob"]);
        let err = c.require_profile(None).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
        assert_eq!(err.exit_code(), 2);
        // The message has to name the choices, or it isn't actionable.
        assert!(err.to_string().contains("alice"));
        assert!(err.to_string().contains("bob"));
    }

    #[test]
    fn a_named_but_unknown_profile_is_not_found() {
        let c = cfg_with(&["alice", "bob"]);
        let err = c.require_profile(Some("carol")).unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn one_profile_needs_no_flag() {
        let c = cfg_with(&["alice"]);
        assert_eq!(c.require_profile(None).unwrap(), "alice");
    }

    /// A fresh install has nothing configured; `auth login` must still work
    /// without making the user create a profile first.
    #[test]
    fn a_fresh_install_resolves_without_error() {
        assert_eq!(
            Config::default().require_profile(None).unwrap(),
            DEFAULT_PROFILE
        );
    }

    #[test]
    fn account_falls_back_to_the_profiles_default() {
        let mut c = cfg_with(&["alice"]);
        c.profiles.get_mut("alice").unwrap().account = Some("1010101010".into());
        assert_eq!(
            c.resolve_account("alice", None).as_deref(),
            Some("1010101010")
        );
        // The flag wins.
        assert_eq!(
            c.resolve_account("alice", Some("2020")).as_deref(),
            Some("2020")
        );
        // An unknown profile simply has no default.
        assert_eq!(c.resolve_account("nobody", None), None);
    }

    #[test]
    fn profile_names_render_for_errors() {
        assert_eq!(Config::default().profile_names(), "none configured");
        assert_eq!(cfg_with(&["b", "a"]).profile_names(), "a, b");
    }
}
