# Changelog

## v0.5.0 — 2026-11-03

Moves to cli-common v0.17.0 and Rust 1.89. A browser sign-in now runs in a profile
`rhd` keeps per login, where it used to run in a scratch profile deleted after every
sign-in.

- `rhd auth login --browser` keeps a Chrome profile on disk for each login profile,
  owner-only (`0700`), at
  `~/Library/Application Support/piekstra.rhd/browser-profile-<NAME>` on macOS and
  under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, so Robinhood's own cookies
  carry over and a later sign-in often asks for less, and one household account's
  sign-in never opens signed in as another. Other systems still use a scratch
  profile every time.
- The trade: it is a full Chrome profile, so it also holds a copy of the session's
  access and refresh tokens, browsing history with full URLs, query strings included,
  the HTTP cache and site storage. Chrome's cookie encryption does not cover those;
  `0700` is their only protection, and ordinary backups usually include the directory.
  On Linux with no desktop keyring Chrome encrypts the cookies with a fixed, publicly
  known key, so there the session cookie has only `0700` too. SECURITY.md has the
  details.
- `rhd auth login --browser --fresh-profile` runs one sign-in in a scratch profile,
  and leaves the kept one alone.
- `rhd auth logout` and `rhd profiles remove` also remove that login's kept profile,
  and only that one, and now attempt every step even after one fails. If one fails
  they say what is cleared and what remains, and exit with the first failure's code.
  While a sign-in or a Chrome is using the profile, or when the path is a symlink or
  another user's, that is exit 1. The config entry goes last, only once the rest is
  clear, so the retry can find the login. A config file that cannot be parsed stops no
  step when `--profile` or `RHD_PROFILE` names the login; without a name logout asks
  for one.
- Every failure once the window has opened now says the kept profile stays and that
  `rhd auth logout` removes it: a timeout, a closed window, Ctrl-C, Robinhood
  throttled or down during the check, a keychain write that fails. `rhd auth status`
  does not report the profile: cli-common has no public way to ask whether one
  exists.
- A login whose name a Chrome profile cannot carry (anything but 1 to 64 ASCII
  letters, digits, `-` or `_`) is refused by `--browser`, exit 2, before Chrome
  starts, and never mapped onto another login's profile. `--browser --fresh-profile`
  still signs it in, and reads and logout work as before. `rhd profiles add` now
  also refuses a name over 64 characters.
- The capture only reads, so the copy of the tokens in `web:auth_state` goes stale at
  `rhd`'s next renewal, and the next window can present it. You then sign in again.
  `--fresh-profile` avoids it for one run, and logout removes the copy.
- The capture now takes a session only once it is short of `rhd`'s renewal point and
  Robinhood accepts it. A token Robinhood refused is not sent again. A throttle or an
  outage during that check ends the wait with an error.
- A 429 or a 5xx with an HTML body is now exit 5, like any other 429 or 5xx, and no
  longer reads as a refused session (exit 3) on any command.
