# Changelog

## v0.5.2 — 2026-11-04

- `robinhood_activity` and `robinhood_documents`: a row with no id is an upstream error. It used to be left out of the list with nothing said.
- Those tools stop reading after 90 seconds and name the arguments that shorten the call, if any do, rather than walking on after the server has answered.
- A tool call holds one turn for its whole call and waits at most 45 seconds for it, then says another call has it.
- `auth logout --forget` speaks to a server on `$RHD_MCP_TOKEN` too, which never had a keychain item to remove.
- cli-common v0.29.0, up from v0.27.0.

## v0.5.1 — 2026-11-03

Moves to cli-common v0.27.0.

- `auth logout --forget` removes the connector token `mcp-http-token`, which every login shares,
  and says what that does not end: a running `rhd mcp --http` keeps the token it started with.
- `robinhood_activity` and `robinhood_documents` page by position, so a row that arrives between
  pages repeats nothing and skips nothing. Rows of the same day now run in a fixed order of their
  own. A cursor from an earlier version still works, as the count of rows it holds.
- A password, a code or a refresh token stays on the host it was for. reqwest re-sends a body on a
  307 or 308, so a POST refuses a redirect to another host, and other requests refuse one that
  leaves https.
- An error no longer quotes a URL's query, in reqwest's text or its own. On Windows, a session too
  long for one credential is split and read back as one.

## v0.5.0 — 2026-11-03

A browser sign-in now runs in a profile `rhd` keeps per login, where it used to run
in a scratch profile deleted after every sign-in. Moves to cli-common v0.20.0.

- `rhd auth login` no longer prints the username on stderr, which can end up in a log or an agent's transcript. It still names the profile and the account count.
- `rhd auth login --browser` keeps a Chrome profile on disk for each login profile,
  owner-only (`0700`), at
  `~/Library/Application Support/piekstra.rhd/browser-profile-<NAME>` on macOS and
  under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, so Robinhood's own cookies
  carry over and a later sign-in often asks for less, and one household account's
  sign-in never opens signed in as another. Other systems still use a scratch
  profile every time.
- The trade: it is a full Chrome profile, so it also holds browsing history with full
  URLs, query strings included, and the HTTP cache. Chrome's cookie encryption does
  not cover those; `0700` is their only protection, and ordinary backups usually include the directory.
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
  for one. A named login the config does not know now runs every step too and says so,
  where it used to be exit 4, so what a failed first sign-in left can be removed. Reads
  of that name stay refused.
- Every failure once the window has opened now says the kept profile stays and that
  `rhd auth logout` removes it: a timeout, a closed window, Ctrl-C, Robinhood
  throttled or down during the check, a keychain write that fails.
- `rhd auth status` reports whether the active login keeps a profile (`browser_profile`
  with `--json`, a `Browser:` line otherwise), not whether anything is signed in there.
- A login whose name a Chrome profile cannot carry (anything but 1 to 64 ASCII
  letters, digits, `-` or `_`) is refused by `--browser`, exit 2, before Chrome
  starts, and never mapped onto another login's profile. `--browser --fresh-profile`
  still signs it in, and reads and logout work as before. `rhd profiles add` now
  also refuses a name over 64 characters.
- The profile keeps no tokens between runs. Its site storage, where the web app holds
  them in `web:auth_state`, is removed before Chrome starts and again once Chrome has
  stopped; after a crash or a second Ctrl-C, the next launch removes it. Its cookies
  stay, and Chrome now quits over its debug port, so a fresh one reaches the disk.
- The capture now takes a session only once it is short of `rhd`'s renewal point and
  Robinhood has not refused it. That is its one read: the accounts page it got is the
  proof, and the session goes straight to the keychain. A token Robinhood refused with a
  401 or its own JSON is not sent again, and a timeout says what the read answered.
- If that read cannot decide (a bot check's page, a throttle, an outage, a dropped
  connection, an answer that is not the accounts list), the sign-in is kept: the session
  is stored, the exit is 0, `session-import/v1` says `verified: false` (it always carries
  `verified`, a boolean, `true` when a read accepted the session), and a warning says why,
  even under `-q`, that it is unverified, and that if reads keep failing, `rhd auth login
  --browser --overwrite` is the way out.
- After a bot check's page or a 403 with no JSON, that warning says a new sign-in may not
  help, because the block is on the client rather than the session: wait or try another
  network, and only if reads still fail after that, run `rhd auth login --browser
  --overwrite`. A renewal's error says the same, and so do an ordinary read's error,
  still exit 3, and the MCP tools' fix for an HTML 403 or a 403 with no JSON.
- An HTML page on an ordinary read with any other status, such as a 200, names both
  remedies, still exit 3, because a session logged out or revoked elsewhere answers the
  same way: if that happened, sign in now with `rhd auth login --browser --overwrite`;
  otherwise a bot check may clear after waiting. The MCP tools' fix says the same and
  asks for one more call at most.
- A 5xx from the token endpoint is now exit 5 whatever its body, at a renewal and at a
  password login, with no sign-in advice. An HTML 5xx was exit 3 and asked for a sign-in,
  which during an outage could replace a session whose refresh token still worked.
- A failed renewal of a browser session names `--overwrite`, because the session is still
  stored and `--browser` refuses without the flag.
- `rhd auth login --help` no longer offers `--no-verify`, which no login path reads: the
  password login always reads before it stores. It still parses, so a script that passes
  it keeps working.
- `rhd auth login --browser` now refuses before Chrome opens, exit 2, when this login
  already has a stored session and `--overwrite` was not passed. It used to replace the
  stored session with no flag. Messages that send you back to sign in with a session
  stored now name `--overwrite`.
- Before going back to an older release, run `rhd auth logout --profile <NAME>` for each
  login. An older release does not know the kept profiles and its logout leaves them
  behind; otherwise delete
  `~/Library/Application Support/piekstra.rhd/browser-profile-*` (on Linux, under
  `$XDG_DATA_HOME` or `~/.local/share`) by hand afterwards.
- A 429 or a 5xx with an HTML body is now exit 5, like any other 429 or 5xx, and no
  longer reads as a refused session (exit 3) on any command.
