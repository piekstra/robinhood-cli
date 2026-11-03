# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[security advisories](https://github.com/piekstra/robinhood-cli/security/advisories/new)
rather than a public issue.

## Threat model

`rhd` authenticates to Robinhood's **unofficial, community-documented** API on
behalf of one household and reads their brokerage data. It supports several
independent logins ("profiles"), so a leak affects more than one person's
finances. The things worth protecting, all stored in the OS keychain under
service `piekstra.rhd` and namespaced per profile:

- **The account password** (`<profile>/password`). Read at point of use, never
  logged, never placed on argv, never written to disk.
- **The OAuth token bundle** (`<profile>/token`) — access token, refresh
  token, expiry. The access token is a bearer credential: anyone holding it
  can read the account until it expires. The refresh token is worse, because
  it mints new access tokens without re-authenticating. A session from a
  signed-in browser is stored here too, with the browser's `device_id`. It
  arrives from the sign-in window (`auth login --browser`) or on stdin
  (`--session-stdin`, or a hidden paste on a terminal), is proved with one
  read before it is written, and is never echoed — not in output, not in an
  error message.
- **The sign-in window** (`auth login --browser`), while it is open. Chrome's
  DevTools port on `127.0.0.1` has no authentication, so a local process that
  finds it can read every cookie in the window. `rhd` reads the session from
  robinhood.com pages only, closes the tab the moment it is read, then stops
  Chrome on every exit path, Ctrl-C included. The session never touches argv, a
  log, or the disk outside the window's Chrome profile.
- **The kept browser profile**, on disk between sign-ins. See
  [The kept browser profile](#the-kept-browser-profile).
- **The device token** (`<profile>/device`). Not a secret on its own, but it
  is the value that carries *device trust* — a third party holding both it and
  the password may be able to skip the device-approval challenge that would
  otherwise stop them.
- **A parked mid-challenge login** (`<profile>/pending`). Short-lived and
  single-use: deleted on the next `--code` attempt whether it succeeds or
  fails.

Additionally, **document URLs returned by the API are pre-signed** and grant
access to a tax form or statement without a bearer token. Never paste one into
an issue, a log, or a commit.

## What this tool does not do

- **It never places a trade, moves money, or changes account settings.** There
  is no order-entry, transfer, or profile-edit code path in the binary. `rhd
  api` refuses any method other than `GET` (exit `6`).
- It talks only to `api.robinhood.com`, `bonfire.robinhood.com` (ACATS
  transfers) and the pre-signed document hosts the API returns, plus, during
  `auth login --browser`, the local Chrome it launched (over its loopback
  DevTools port), in which the owner signs in to robinhood.com. No telemetry,
  no third-party services.
- It hardcodes no secrets. `gitleaks` runs in CI over the full history.

## The MCP server

`rhd mcp` serves read-only tools to an MCP client (Claude Code, Claude
Desktop) over stdio, on this machine only; it opens no port unless run with
`--http` (below). It uses the
selected profile's session already in the keychain, exactly as the commands
do, refreshing it in place, and never signs in: a missing or lapsed session
is an error asking the user to run `rhd auth login --browser --profile
<NAME>` in a terminal. No tool downloads a document or emits a download
link. The Claude Desktop extension (`.mcpb`) takes no settings and so holds
no credential of its own; on macOS its bundled binary needs the user's
approval, once, to read the `piekstra.rhd` keychain item.

`rhd mcp --http --port <PORT>` serves the same tools over HTTP for the
user's own Cloudflare Worker, which reaches it through the user's own
Cloudflare Tunnel (cli-common's `connector/`). It binds 127.0.0.1 only, with
no flag for another address, and refuses to start without a bearer token of
32 or more characters, from `RHD_MCP_TOKEN` or the keychain item
`mcp-http-token` (`piekstra.rhd`), which `rhd mcp --new-token` makes from
256 random bits and replaces only with `--overwrite`. Every request must
carry the token (compared in constant time) and a `Host` of `127.0.0.1` or
`localhost`, and must not carry an `Origin`; there are no CORS headers. Only
the read-only tools are served (all three are). The session stays in the
keychain: the Worker sends tool calls and receives results, and never sees
a cookie or a token for Robinhood.

## Unofficial-API risk

Robinhood publishes no public retail API and its terms discourage automated
access. Using this tool carries provider-side risk that a supported API would
not: rate limiting, challenge loops, or account restriction. `docs/api.md`
records the honest failure modes. Two rules follow from that and are enforced
in code:

- **One login attempt, then stop.** There is no retry loop around
  authentication, because a loop against a challenge is how an account gets
  locked.
- **Never claim success without positive confirmation.** A `200` carrying an
  HTML login page is an auth failure, and a "downloaded" file that does not
  begin with `%PDF` is not a document.

## Handling credentials safely

Prefer piping from a password manager over typing:

```console
$ op read 'op://Private/robinhood/password' \
    | rhd auth set-credential --profile primary --stdin --overwrite
```

`rhd auth logout` removes that login's token bundle and any parked login from the
keychain, and its kept browser profile. `--forget` also removes its password and
device token, and drops the login from the config, as `rhd profiles remove` does.
The browser profile is refused while a sign-in or a Chrome is using it, or when the
path is a symlink or another user's. A refusal is exit 1, and its message says what
is already cleared, what remains and how to finish.

## The kept browser profile

`auth login --browser` runs Chrome in a profile of its own, so nothing of your
everyday browser is read, and keeps it so Robinhood remembers this device: a later
sign-in often asks for less. Each login profile keeps its own, so one household
account's sign-in never opens signed in as another:
`~/Library/Application Support/piekstra.rhd/browser-profile-<NAME>` on macOS and
under `$XDG_DATA_HOME` or `~/.local/share` on Linux. A launch is refused if the
path is a symlink, another user's or not `0700`. `--fresh-profile` uses a scratch
`0700` directory in the temp dir instead, created exclusively under an
unpredictable name and deleted when the window closes, Ctrl-C included, and neither
reads nor changes the kept profile.

It is a full Chrome profile, and that is the trade for fewer sign-ins. It holds:

- Robinhood's cookies: the `device_id` that remembers this device, and the
  `__Host-Web-App-Secondary-Access-Token` cookie with the read-only secondary token;
- browsing history with full URLs, query strings included;
- the HTTP cache, for whatever the responses allow: account data among it;
- `localStorage`, IndexedDB and other site storage;
- any password you let Chrome save.

Chrome encrypts its cookies at rest with a key from the system's keyring: on macOS
the "Chrome Safe Storage" key in the login keychain. On Linux with no desktop
keyring it falls back to a fixed, publicly known key, so there the session cookie
has only the directory's `0700` mode protecting it. Everywhere, the encryption does
not cover the history, the HTTP cache or site storage, so `0700` is their only
protection. The directory sits where ordinary user-level backups usually look, so
exclude it from any backup you don't want holding this.

**The session's tokens are taken out of it.** The web app keeps its access and
refresh tokens in `localStorage`'s `web:auth_state`, which Chrome does not encrypt.
The capture removes that entry as it reads it, so after a completed sign-in the
profile holds no copy, and a refresh token that `rhd` later rotates is not left
where the next window would present it. Two cases can still leave it there, until
the next sign-in or logout: a sign-in that ended before the read, and a Chrome
stopped before the removal reached the disk. The capture then refuses anything past
the point `rhd` would renew it, or that Robinhood does not accept. A throttle or an
outage during that check ends the wait with an error, and takes nothing.

**The profile outlives a failed sign-in.** However a sign-in fails once its window
has opened (a timeout, a closed window, Ctrl-C, Robinhood throttled or down during
the check, a keychain write that fails), the profile stays with what the sign-in got
as far as, which can be a live session, and the error says so. `rhd auth status`
reads only the keychain and config, so it does not show the profile.
