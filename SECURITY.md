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
  finds it can read every cookie in the window. The window runs in a
  throwaway profile created `0700` under an unpredictable name; `rhd` reads
  the session from robinhood.com pages only, closes the tab the moment it is
  read, then stops Chrome and deletes the profile on every exit path, Ctrl-C
  included. The session never touches argv, a log, or the disk outside that
  profile.
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

`rhd auth logout --forget` removes that profile's password, token bundle,
device token, and any parked login from the keychain, and drops the profile
from the config.
