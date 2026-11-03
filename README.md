# robinhood-cli (`rhd`)

Read-only command-line access to **Robinhood** brokerage accounts, for tax
work: realized gains during the year, the consolidated 1099 at season, and
enumeration across a household's several logins and accounts.

Conforms to `piekstra-cli` spec v1 (see
[cli-common](https://github.com/piekstra/cli-common)), so `--json`, exit
codes, `auth`, `config`, `self-update`, `completions`, and `info` all behave
the way the rest of the family does.

Unofficial; not affiliated with or endorsed by Robinhood Markets, Inc.

> [!IMPORTANT]
> **Robinhood publishes no public retail API.** Everything here is built on
> community reverse-engineering, so it can break without notice, and using it
> carries provider-side risk (rate limiting, challenges, account
> restrictions). Read [`docs/api.md`](docs/api.md) before first use — it
> records the auth flow, the endpoints, the honest failure modes, and which
> commands are still **UNVERIFIED-LIVE**.

> [!NOTE]
> **Read-only, enforced in code.** `rhd` never places a trade, moves money, or
> changes account settings; `rhd api` accepts `GET` only.

## Install

```console
$ make install          # builds, installs to ~/.cargo/bin, re-signs for keychain
$ rhd --help
```

## The two kinds of "account"

Robinhood stacks two, and `rhd` keeps them separate:

| Concept | Flag | What it selects |
| --- | --- | --- |
| **Profile** | `-p/--profile <NAME>` (`$RHD_PROFILE`) | Which *login* — one per household member, each with its own password, device token, and session |
| **Account** | `-a/--account <ID>` (`$RHD_ACCOUNT`) | Which *brokerage account inside that login* — individual, joint, IRA, … |

```console
$ rhd -p spouse -a 1234567890 positions list
```

With one profile configured you never have to type `--profile`. With two or
more and no default set, `rhd` refuses to guess and names the choices — it
will not silently read the wrong person's portfolio.

## Getting started

```console
# 1. Name the logins (no secrets here — this is just config).
$ rhd profiles add primary --username you@example.com
$ rhd profiles add spouse  --username partner@example.com

# 2. Sign in through a Chrome window (see "Signing in" below).
$ rhd auth login --browser --profile primary

# 3. Confirm, and see what the login contains.
$ rhd auth status --profile primary --verify
$ rhd accounts list --profile primary
```

## Signing in

`rhd auth login --browser` opens Chrome at <https://robinhood.com/login> with
a throwaway profile. Sign in there: your password and any code or approval
Robinhood asks for go into Robinhood's own page, never into `rhd`.

```console
$ rhd auth login --browser --profile primary
A Chrome window opened at the Robinhood sign-in. Sign in there (your password, then any code or approval Robinhood asks for); this waits for the session and captures it (up to 10 minutes; Ctrl-C cancels).
Robinhood: session captured, tab closed.
stored the browser sign-in's session (web:auth_state) into profile `primary` — 4 accounts visible
renews unattended: the refresh token is stored; the access token is good until …
```

As soon as the robinhood.com page holds a session, `rhd` reads it (the web
app's `web:auth_state` and its `device_id` cookie, from robinhood.com only),
closes the tab, quits Chrome and deletes the profile. It then reads your
accounts once with the session and stores it in the OS keychain only if that
read succeeds; it never prints the token. Closing the tab at once matters:
the web app and `rhd` would otherwise share one refresh token that rotates on
every renewal, and a later Log out in that window would revoke it. The
session lands where a password login's would, so every command works
unchanged and `auth status` reports `browser-session`.

Chrome, Chromium or Edge is found at the standard install paths; set
`RHD_CHROME` to use another binary. `rhd auth login --help` has the details,
and docs/api.md §2.8 records exactly what is read, from where, and what is
still unverified.

### Without Chrome: a session copied out of DevTools

When Chrome is not installed or the `--browser` capture fails, log in at
<https://robinhood.com> in your own desktop browser and hand `rhd` that
session. Open DevTools and capture **one** of:

1. **The stored session** — renews itself, so prefer it. In the **Console**
   tab (Chrome may first ask you to type `allow pasting`), run:

   ```js
   copy(JSON.stringify({...JSON.parse(localStorage['web:auth_state']), device_token: (document.cookie.match(/(?:^|; )device_id=([^;]+)/) || [])[1]}))
   ```

   That copies the value at **Application → Local Storage →
   https://robinhood.com → `web:auth_state`**, plus the browser's `device_id`
   cookie, which renewal presents.
2. **A bearer token** — cannot renew; lasts until it expires. In the
   **Network** tab, reload, click any request to `api.robinhood.com`, and copy
   the `authorization` request header (`Bearer …`).

Then pipe the clipboard in:

```console
$ pbpaste | rhd auth login --profile primary --session-stdin
imported a browser session (web:auth_state) into profile `primary` — 4 accounts visible
renews unattended: the refresh token is stored; the access token is good until …
```

It goes through the same parser, proving read and keychain item as
`--browser`. Afterwards close the robinhood.com tab, but **do not click Log
out** — logging out revokes the session `rhd` just stored. If you later use
the site and it renews its session first, `rhd` will say its copy can no
longer renew; sign in again.

### The password login

`rhd auth login` without either flag logs in with the password. Robinhood
challenges a login from an unrecognized device, and since 2025 that is mostly
an in-app approval prompt; for this project's owner it has stopped reaching
the phone at all (docs/api.md §6), which is why `--browser` is the way in.
`rhd` does **one** attempt and then stops — there is no retry loop anywhere
in the auth path, because looping against a challenge is how an account gets
locked.

On a terminal, `rhd` prompts for the code. Without a TTY (a script, CI, an
agent), it **parks** the in-flight challenge and tells you to resume it:

```console
$ rhd auth login --profile primary
error: a verification code was sent — re-run with `rhd auth login --code <CODE>`

$ rhd auth login --profile primary --code 123456
```

The resume matters: a code is bound to the login attempt that requested it, so
starting a fresh login and presenting the code against *that* would fail. The
parked attempt is single-use and is discarded either way.

After a successful login the profile's `device_token` is kept, which is meant
to stop later logins re-challenging. Live, it has not (docs/api.md §2.2): a
later login can raise the approval prompt again, and that prompt may never
reach the phone.

## Commands

```
rhd auth login [--browser|--session-stdin]|status|logout|set-credential
rhd profiles list|add|remove|use          # the household's logins
rhd config path|show|set|unset
rhd accounts list|get [ID]
rhd positions list [--all] [--all-accounts]
rhd options positions [--all-accounts]    # open option positions at the mark, with unrealized P/L
rhd net-worth                             # cash + equities at last trade, per account (net-worth/v1)
rhd transactions list [--since D] [--until D] [--limit N] [--executions] [--all-accounts]
rhd transactions options [--since D] [--until D] [--limit N] [--executions] [--all-accounts]
                                          # options orders: legs + signed premium
rhd transactions option-events [--since D] [--until D] [--limit N] [--all-accounts]
                                          # exercises, assignments, expirations
rhd transfers acats [--since D] [--until D] [--limit N]
                                          # ACATS transfers in and out (no cost basis)
rhd dividends list [--since D] [--until D]     # 1099-DIV raw material
rhd interest list [--since D] [--until D]      # 1099-INT raw material
rhd documents list|download               # tax forms & statements
rhd api GET <PATH|URL>                    # raw read-only passthrough (a full
                                          # https://bonfire.robinhood.com/... URL reaches the second host)
rhd mcp                                   # serve read-only tools to Claude (see Use with Claude)
rhd mcp --http --port 8732                # the same, on 127.0.0.1 for your own Cloudflare Worker
rhd self-update | completions <shell> | info
```

Every command takes `--json`, `-v/--verbose`, `-q/--quiet`, and `--no-color`.

### Tax use

```console
# Every account at once. Without --all-accounts an order read answers for the
# login's DEFAULT account only — an IRA, a joint account or an additional
# individual account is silently absent. --all-accounts reads each account
# with its own scoping, verifies every row names that account, and tags each
# row with account_number, account_kind (individual, ira_roth, …) and, for
# the default account, account_default: true (docs/api.md §3.14).
# UNVERIFIED-LIVE: --all-accounts and `transfers acats` have not yet been run
# end to end against the live service (docs/api.md §3.13/§3.14 say which
# parts were).
$ rhd transactions list --all-accounts --since 2026-01-01 --json

# Shares that arrive by ACATS arrive without an order. The transfer listing
# names the account, the other broker, the date and the shares — but no cost
# basis (docs/api.md §3.13).
$ rhd transfers acats --json

# Realized-gains raw material for a year, as JSON for downstream tooling:
# equity orders (price, executed notional, fees; --executions adds per-fill
# settlement detail). Each row carries its instrument_id; a symbol the
# instrument lookup cannot resolve is left out, never guessed ...
$ rhd transactions list --since 2026-01-01 --until 2026-12-31 --json

# ... and options orders — a separate feed because the provider splits them.
# Legs carry side/effect/type/strike/expiry; processed_premium is signed by
# cash flow (credit +, debit -). See docs/api.md §3.4.1.
$ rhd transactions options --since 2026-01-01 --until 2026-12-31 --json

# Both feeds include cancelled and resting (`confirmed`) orders. Most carry
# no executed figures, but a `cancelled` row can hold a partial fill: count a
# row when it is `filled` OR its executed quantity is above zero
# (docs/api.md §3.4) before computing anything. A full-year options pull pages at the polite
# request rate and can take minutes; narrow --since/--until where you can.

# Exercises, assignments and expirations — the option activity neither
# order feed records. Each event names its contract, the contracts it
# closed, the shares it moved at the strike, and its signed cash (an
# assignment's is net of the sale's fees). See docs/api.md §3.10.
$ rhd transactions option-events --since 2026-01-01 --until 2026-12-31 --json

# Open option positions valued at the mark — strike/expiry/type, FIFO
# cost basis, market value, unrealized P/L (shorts signed negative). The
# loss-harvest raw material for options. See docs/api.md §3.9.
$ rhd options positions --json

# The consolidated 1099 at season.
$ rhd documents list --json
$ rhd documents download <ID> -o ~/tax/2026/robinhood-1099.pdf

# Point-in-time position for the money map: every brokerage account's cash
# plus its stock/ETF holdings valued at last trade, rolled up. Computed
# client-side — no Robinhood endpoint truthfully answers per-account totals
# (docs/api.md §3.8). Scope is cash + equities (no options/crypto yet); the
# DTO's `covers` field says so.
$ rhd net-worth --json
```

Downloads are verified by magic bytes: if the payload does not begin with
`%PDF`, `rhd` fails rather than writing a file and claiming success.

## Use with Claude

`rhd mcp` serves three read-only tools over MCP, so Claude can answer
questions about your own Robinhood accounts. There is no hosted service: the
tools run on your computer, in your copy of `rhd`, and call Robinhood's API
directly with the session `rhd auth login --browser` stored in your OS
keychain.

| Tool | Answers |
| --- | --- |
| `robinhood_portfolio` | What am I worth at Robinhood, and what do I hold? The `net-worth` valuation (cash plus stocks/ETFs at last trade), each account's total, and the positions, narrowed by `account` (its name) or `symbol` |
| `robinhood_activity` | What happened over a period? Executed stock trades (partial fills on cancelled orders included), dividends and cash-sweep interest by `since`/`until` dates (year to date by default), `account`, `type` (`trade`, `dividend`, `interest`) and `symbol` |
| `robinhood_documents` | Which tax forms and statements exist? Listed by `type` (`1099`, `account_statement`, `trade_confirm`) and `since`/`until`; never downloaded (`rhd documents download` does that) |

Options, crypto and realized gains are not served: `rhd` values neither
options nor crypto in its net worth, and Robinhood has no realized-gain
endpoint (the order history is the raw material; see [Tax use](#tax-use)).

Results are concise by default (`response_format: "detailed"` adds ids,
prices and fees), 25 records a page with a cursor for more, and never larger
than about 32,000 characters. Accounts are named by nickname or kind
(`ira_roth`), with the number's last four characters when two would share a
name. Descriptions come from Robinhood and other parties; the server tells
Claude to treat them as data, not instructions.

**Sign in first.** Robinhood sign-in is through a browser, so no settings
form can hold it. Install `rhd` and run `rhd auth login --browser` in a
terminal (see [Getting started](#getting-started)). Both ways of connecting
Claude below then use that session from the OS keychain (service
`piekstra.rhd`), and refresh it in place as the commands do. If the session
is missing or has lapsed, the tools say so and ask you to run
`rhd auth login --browser --profile <NAME>` in a terminal; they never sign in
by themselves. With several login profiles the server uses the default one
(`rhd profiles use <NAME>`), or the one named by `rhd mcp --profile <NAME>`.

**Claude Code.** Add the `robinhood-cli` plugin from the
[piekstra plugin marketplace](https://github.com/piekstra/claude-plugins):

```console
$ claude plugin marketplace add piekstra/claude-plugins
$ claude plugin install robinhood-cli@piekstra-plugins
```

or register the server yourself:

```console
$ claude mcp add robinhood -- rhd mcp
```

**Claude Desktop.** Download `rhd-<version>.mcpb` from the
[latest release](https://github.com/piekstra/robinhood-cli/releases/latest)
and open it. It asks for nothing: the bundled `rhd` reads the session your
installed `rhd` stored, for the default profile. On macOS the bundled binary
is a different program to the keychain, so its first call raises a keychain
prompt for the `piekstra.rhd` item; choose **Always Allow**, or every call
will ask again.

Any other MCP client that launches a local server can run `rhd mcp`.

**Claude on the web and mobile.** claude.ai reaches tools through a remote
connector, and Robinhood sign-in stays on your computer, so `rhd` serves the
same tools from your computer to a connector you deploy into your own
Cloudflare account:

```console
$ rhd mcp --new-token            # once: a bearer token, saved in the keychain and printed for the Worker
$ rhd mcp --http --port 8732     # serve on 127.0.0.1 only (add --profile <NAME> for another profile)
```

The connector, [cli-common's `connector/`](https://github.com/piekstra/cli-common/tree/main/connector#tools-from-your-computer-home-modules),
reaches that port through a Cloudflare Tunnel in your account; its README
walks through the tunnel, the VPC service, a launchd agent that keeps the
server running, and the `HOME_ROBINHOOD_TOKEN` secret, with the threat
model. `--http` binds 127.0.0.1 only, refuses to start without the token,
refuses any request whose `Host` is not loopback or that carries an
`Origin`, and serves the read-only tools only. The session never leaves your
computer, but tool results do: your balances, positions and activity pass
through Cloudflare and reach Claude ([`SECURITY.md`](SECURITY.md)). While the
computer sleeps, the tools answer that it is offline.

After `rhd self-update`, restart the server: a running one keeps the old code,
and its launchd agent restarts it only when it exits. Its start line names the
version.

```console
$ launchctl kickstart -k gui/$(id -u)/com.piekstra.rhd-mcp-http
```

`self-update` does not reach a Claude Desktop extension, which runs its own copy.
Install the new release's `.mcpb` too. A server or extension on an older version
renews without the lock the others use, which can cost a sign-in.

## Security

Passwords, OAuth tokens (including a session from a browser), and device
tokens live only in the OS keychain (`piekstra.rhd`), namespaced per profile.
Nothing sensitive is ever accepted on argv or written to disk. With `rhd mcp
--http`, its bearer token also lives in your Cloudflare Worker. A browser
session arrives from the sign-in window over Chrome's DevTools protocol
(`--browser`, whose throwaway profile is deleted afterwards) or on stdin
(`--session-stdin`). See [`SECURITY.md`](SECURITY.md).

```console
$ op read 'op://Private/robinhood/password' \
    | rhd auth set-credential --profile primary --stdin --overwrite
```

## Development

```console
$ make verify     # fmt-check + clippy -D warnings + test + smoke — the CI gate
```

The test suite is **fully offline** — no network, no keychain, no credentials
— because testing against the live service costs the account owner a phone
interaction. Fixtures are synthetic, built from public community documentation
with citations in [`tests/fixtures/README.md`](tests/fixtures/README.md).

See [`AGENTS.md`](AGENTS.md) for the full working agreement and
[`CONTRIBUTING.md`](CONTRIBUTING.md) to contribute.

## License

MIT or Apache-2.0, at your option.
