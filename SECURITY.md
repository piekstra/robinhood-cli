# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[security advisories](https://github.com/piekstra/robinhood-cli/security/advisories/new)
rather than a public issue.

## Threat model

`rhd` authenticates to Robinhood's **unofficial, community-documented** API on
behalf of one household and reads their brokerage data. It supports several
independent logins ("profiles"), so a leak affects more than one person's
finances. The things worth protecting, stored in the OS keychain under
service `piekstra.rhd` and, except for the `--http` bearer token, namespaced
per profile:

- **The account password** (`<profile>/password`). Read at point of use, never
  logged, never placed on argv, never written to disk.
- **The OAuth token bundle** (`<profile>/token`) — access token, refresh
  token, expiry. The access token is a bearer credential: anyone holding it
  can read the account until it expires. The refresh token is worse, because
  it mints new access tokens without re-authenticating. A session from a
  signed-in browser is stored here too, with the browser's `device_id`. It
  arrives from the sign-in window (`auth login --browser`) or on stdin
  (`--session-stdin`, or a hidden paste on a terminal), gets one read before
  it is written, and is never echoed — not in output, not in an error message.
  A session on stdin is stored only if that read proves it. One from the window
  is stored unless the read refuses it, with a warning if the read could not
  decide (below).
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
- **The `--http` bearer token**, only if you use `rhd mcp --http` (below). It
  is not per profile: the keychain item `mcp-http-token`, or `RHD_MCP_TOKEN`,
  with **a copy in your Cloudflare Worker** as its `HOME_ROBINHOOD_TOKEN`
  secret. It admits a caller to the read-only tools on 127.0.0.1 and signs in
  to nothing at Robinhood.

One file sits beside them and holds nothing: `~/.config/rhd/token-refresh.lock`
is empty, and `rhd` processes hold it while renewing a session, so two never
present one refresh token. That holds once every copy sharing the keychain items
is 0.4.2 or later, including a server not yet restarted and an installed Claude
Desktop extension, which bundles its own binary.

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
  DevTools port), in which the owner signs in to robinhood.com. No telemetry
  and no third-party services, unless you run `rhd mcp --http`, whose tool
  results reach Cloudflare and Claude (below).
- It hardcodes no secrets. `gitleaks` runs in CI over the full history.

## The MCP server

`rhd mcp` serves read-only tools to an MCP client (Claude Code, Claude
Desktop) over stdio, on this machine only; it opens no port unless run with
`--http` (below). It uses the
selected profile's session already in the keychain, exactly as the commands
do, refreshing it in place, and never signs in: a missing or lapsed session
is an error asking the user to run `rhd auth login --browser --overwrite
--profile <NAME>` in a terminal. No tool downloads a document or emits a download
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

**Tool results leave your computer on this path.** They hold your financial
data (balances, positions, trades, dividends, the list of your tax documents).
They cross Cloudflare, through your tunnel and your Worker, and reach Claude,
which shows them in your conversation. Who holds what, and what a leaked token
can do, is in the connector's
[threat model](https://github.com/piekstra/cli-common/blob/main/connector/README.md#threat-model).

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
device token, and the connector token `mcp-http-token` that every login shares, and
drops the login from the config. `rhd profiles remove` does the same but leaves
`mcp-http-token`, so retiring one login does not stop a server for another.
Every step is attempted even after one fails, and the error says what is cleared,
what remains and how to finish, with the first failure's exit code. The config entry
goes last, only once the rest is clear, so the retry can find the login. The browser
profile is refused while a sign-in or a Chrome is using it, or when the path is a
symlink or another user's; on its own that is exit 1.

A logout that names a login with `--profile` or `RHD_PROFILE` runs every step even if
the config does not know that name and says so, because a failed first sign-in leaves
a kept profile under a name the config never recorded. Reads of that name stay
refused.

A release before 0.5.0 does not know the kept profiles, and its `auth logout` leaves
them behind. Run `rhd auth logout --profile <NAME>` for each login before downgrading,
or delete `~/Library/Application Support/piekstra.rhd/browser-profile-*` (on Linux,
under `$XDG_DATA_HOME` or `~/.local/share`) by hand afterwards.

On Windows, whose Credential Manager holds 2,560 bytes per credential, a longer value is stored across several credentials with the suffix `.pk-split-` and read back whole. After a downgrade, run `rhd auth logout --forget` again from a current build: an older build's logout leaves the parts.

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
- any password you let Chrome save.

Chrome encrypts its cookies at rest with a key from the system's keyring: on macOS
the "Chrome Safe Storage" key in the login keychain. On Linux with no desktop
keyring it falls back to a fixed, publicly known key, so there the session cookie
has only the directory's `0700` mode protecting it. Everywhere, the encryption does
not cover the history or the HTTP cache, so `0700` is their only
protection. The directory sits where ordinary user-level backups usually look, so
exclude it from any backup you don't want holding this.

**The session's tokens do not stay in it.** The web app keeps its access and refresh
tokens in `localStorage`'s `web:auth_state`, which Chrome does not encrypt. A refresh
token left there would be retired at `rhd`'s next renewal, and a later window could
present it, which at best signs it out and at worst ends the session in the keychain.
So the profile keeps its cookies and never its site storage: `localStorage`,
`sessionStorage`, IndexedDB, service workers and the rest are removed before Chrome
starts, where a failure refuses the launch, and again once Chrome has stopped. A crash
or a second Ctrl-C skips the second removal, as does a Chrome still running in the
profile. The tokens are then on disk until the next launch or logout, with only `0700`
protecting them. The capture only reads. It refuses anything past the point `rhd`
would renew it, or that Robinhood refuses. A bot check, a throttle or an outage during
that check takes the session unverified, with a warning, as below.

**A session its one read could not decide on is stored unverified.** A bot check, a
throttle or an outage on that read does not discard the sign-in: the page held the only
copy, and a token there can only be this sign-in's, since site storage goes before
Chrome starts. `rhd` warns on stderr, under `-q` too, and `--browser` refuses before
Chrome opens if a session is stored and `--overwrite` was not passed, so such a session
never replaces a stored one without the flag.

**The profile outlives a failed sign-in.** However a sign-in fails once its window
has opened (a timeout, a closed window, Ctrl-C, a keychain write that fails), the
profile stays with what the sign-in got
as far as, which can be a live session in its cookies, and the error says so. `rhd
auth status` says whether that login keeps a profile, not whether anything is signed
in there.

## Revoking access

`rhd auth logout` removes this machine's copy of the session; to end it at
Robinhood, change your password or sign out of other devices in Robinhood's own
app. The delete runs even when the refresh lock is unavailable. If another process
has held the lock past the wait, `rhd auth logout` and `rhd profiles remove` delete
the session and exit 5 saying so, because a renewal in flight can store it again.
Run the command again in a minute to settle it.

`rhd auth logout` does not touch `mcp-http-token` and does not stop `rhd mcp --http`.
`rhd auth logout --forget` removes that token from the keychain too, and says so, but a
running server keeps the token it started with. Every login shares the token, so a server for
another login needs `mcp --new-token` at its next start. Either way the server stays up, its
callers get auth errors, and **a later login silently restores the token holder's access**.
Revoke that access separately:

- **Invalidate the token:** `rhd mcp --new-token --overwrite`, then restart the
  server (`launchctl kickstart -k gui/$(id -u)/com.piekstra.rhd-mcp-http`). The
  old token works until the restart. A server that takes its token from
  `RHD_MCP_TOKEN` needs the variable changed instead. To keep using the
  connector, put the new value in the Worker's `HOME_ROBINHOOD_TOKEN`.
- **Remove the path:** stop the launchd agent
  (`launchctl bootout gui/$(id -u)/com.piekstra.rhd-mcp-http`) and the tunnel,
  and delete the tunnel and VPC service
  ([removing it](https://github.com/piekstra/cli-common/blob/main/connector/README.md#updating-rotating-and-removing)).
