# AGENTS.md — working agreement for `robinhood-cli`

Canonical agent guide for this repo. `CLAUDE.md` is a thin pointer here.

## What this is

`rhd` is a **read-only** CLI over Robinhood's **unofficial, community-
documented** API (`api.robinhood.com`). It exists to feed tax work:

- **realized gains during the year** — `transactions list --since --until`
  (equity orders, with executed notional/fees/per-fill detail) and
  `transactions options` (options orders with legs and signed premium —
  docs/api.md §3.4.1), plus `transactions option-events` (exercises,
  assignments and expirations with their share deliveries — §3.10, the
  activity neither order feed records), so an estimate can be trued up
  before year end.
  Executed figures live on `filled` rows **and** on rows that stopped after
  a partial fill (a `cancelled` row with an executed quantity) —
  downstream consumers gate on the executed quantity, not the state alone
  (§3.4's consumer contract);
- **1099-DIV/INT reconciliation** — `dividends list` and `interest list`
  (cash-sweep interest);
- **the consolidated 1099 at season** — `documents list` / `documents
  download` (`--all --type 1099` grabs a season's PDFs and CSV exports);
- **open option positions at the mark** — `options positions` (strike,
  expiry, call/put, FIFO cost basis, market value, unrealized P/L —
  docs/api.md §3.9), the loss-harvest raw material for options;
- **multi-account enumeration** — a household with several Robinhood logins,
  each holding several brokerage accounts, including managed and additional
  individual accounts the listing hides unless asked (docs/api.md §3.2).
  An unscoped order read covers the default account only; `--all-accounts`
  reads every account, verifies each row's account and tags it (§3.14);
- **transferred-in shares** — `transfers acats` lists ACATS transfers
  (shares arrive with no order and no basis; docs/api.md §3.13);
- **point-in-time balances for the money map** — `net-worth` emits the
  family's `net-worth/v1` DTO, one equity per brokerage account (cash +
  verified stock/ETF holdings at last trade — computed, because no
  Robinhood endpoint truthfully answers per-account totals; docs/api.md
  §3.8 is the truth table). The scope is cash + equities, declared in-band
  via the DTO's `covers` field (options/crypto are not yet valued). Note:
  `covers` makes rhd's DTO a **superset of `m1f net-worth`'s shape,
  pending family ratification** in cli-common (raised as a cli gap in the
  tax-cli tracker); consumers should treat an *absent* `covers` as "scope
  unknown", never as "complete". One registry row for an asset-capturing
  consumer, not per-provider glue.

Conforms to `piekstra-cli/1` (see `~/Dev/cli-common/DESIGN.md` and
`conformance.md`). Shared behavior comes from the `pk-cli-*` crates, every one
pinned to the same cli-common tag (`tag = "v0.9.0"`) — reuse before writing (dates,
output, `RangeArgs`, `Paged`, keychain, config, self-update, the
`documents/v1` DTOs and its `verify`/`fs_safe` download hygiene, and the
browser sign-in behind `auth login --browser`).

## Build / test / lint

```console
$ make verify     # fmt-check + clippy -D warnings + test + smoke — the CI gate
$ make dev        # debug build, re-signed for stable keychain grants
$ make install    # installs to ~/.cargo/bin and re-signs
```

Tests are **fully offline**: no network, no keychain, no credentials, and no
Chrome. Keep them that way (see "Costing the credential loop" below). The
`--browser` tests stop at clap's flag conflicts or at an `RHD_CHROME` that
does not exist; the capture itself is checked with `Capture::validate` and a
scrubbed fixture of the expression's answer.

## Layout

| Path | Owns |
| --- | --- |
| `src/main.rs` | clap tree, dispatch, exit-code mapping |
| `src/config.rs` | non-secret settings + the multi-login **profile** model |
| `src/client.rs` | HTTP, the OAuth/challenge dance, pagination, downloads |
| `src/capture.rs` | the one parser for a session from a signed-in browser — the `web:auth_state` JSON or a bearer token — behind both `auth login --browser` and `--session-stdin`, plus the `--browser` capture itself: host, launch URL, expression and `device_id` cookie (docs/api.md §2.8); pure, no network or keychain |
| `src/commands/*.rs` | one module per command group; a group's subcommand may take its own module once the group's file grows large (`option_events.rs` serves `transactions option-events`), and readers several groups share sit in their own module (`instruments.rs`, `option_instruments.rs`) rather than inside one group |
| `src/commands/fanout.rs` | the `--all-accounts` per-account read shared by positions, options and transactions: one scoped read per account, every row verified against it (exit 5 on a misattributed or unattributable row), and the account tagging (docs/api.md §3.14) |
| `src/commands/transfers.rs` | `rhd transfers acats` — the bonfire ACATS listing, joined to accounts through `rhs_account_number` (docs/api.md §3.13) |
| `src/fixed.rs` | decimal amounts without floats: display trimming and 8-digit fixed-point arithmetic |
| `tests/cli_surface.rs` | black-box `assert_cmd` surface tests |
| `tests/fixture_shapes.rs` | contract tests over `tests/fixtures/` |
| `docs/api.md` | the API as we understand it, **and the traps** |

## The two kinds of "account" — do not conflate

1. **Profile** = a *login*. Household members have separate Robinhood
   accounts. Selected with `-p/--profile` (env `RHD_PROFILE`). Each profile
   has its own keychain entries, namespaced `<profile>/password`,
   `<profile>/token`, `<profile>/device`, `<profile>/pending`.
2. **Account** = a *brokerage account inside one login* (individual, joint,
   IRA…). Selected with the family-standard `-a/--account` (env
   `RHD_ACCOUNT`).

Note the word "profile" is overloaded: `cli-common` uses it for domain
vocabularies (`documents/v1`), which `info --json` reports under `profiles`.
This repo's login profiles are reported by `rhd profiles list --json` under
`login-profile-list/v1`. Different DTOs; keep them straight.

## Non-negotiables

- **Read-only, enforced in code.** No order entry, no transfers, no settings
  changes. `rhd api` accepts `GET` only and exits 6 otherwise. If a write is
  ever added, the README's read-only claim changes in the *same* commit.
- **`--json` on every command**, exactly one DTO per invocation, `schema`
  tagged. Human output to stdout, diagnostics to stderr.
- **Exit codes**: 0 ok · 2 usage · 3 auth · 4 not found · 5 upstream ·
  6 confirmation required.
- **Validate args before touching keychain or network**, so `--help` and bad
  input never prompt, hang, or hit the provider.
- **Secrets only** from the OS keychain (`piekstra.rhd`), stdin, or a named
  env var — never argv, never a file, never a log.
- **ISO `YYYY-MM-DD`** on every date flag.

## Honesty rules (this is an unofficial API; it lies)

These are the ones that cost real debugging time elsewhere in the family:

- **Never report success from a status code alone.** A `200` carrying an HTML
  login page is an auth failure. Treat "HTML where JSON was expected" and
  "landed on a login URL" as `CliError::Auth`, not success.
- **A download is not a document until it matches its declared `filetype`.**
  `%PDF` magic for a PDF; for text filetypes (`csv`, `html` exist live), none
  of the known failure shapes — a DRF JSON error, an S3 XML error, HTML where
  it wasn't promised. Check before writing and before reporting bytes
  written: an expired pre-signed URL answers `200` with XML or HTML.
- **Chase the small anomaly.** A blank field in an otherwise-working response
  is usually the failure reporting itself.
- **One login attempt, then stop.** No retry loop around authentication ever.
  A loop against a device-approval challenge is how an account gets locked.
  The one implicit re-authentication is a *token refresh*, in
  `Ctx::access_token`, when the stored expiry has passed (docs/api.md §2.5,
  §4.2); nothing ever re-runs a password login.

## Costing the credential loop

A first login on an unrecognized device raises a **device-approval
challenge** that needs the account owner's phone. That is a human interruption
and a rate-limited one.

- The `device_token` is persisted per profile so later logins have the best
  chance of not re-challenging. Never regenerate it casually — from the
  provider's side that is indistinguishable from a brand-new device. **But do
  not promise it works**: live (2026-08-12), a re-login with the same token
  re-challenged anyway, with a prompt that never surfaced in the phone app.
  Treat `auth login` as owner-present-only; unattended re-auth is *token
  refresh*, which raises no challenge.
- Non-TTY logins **park** the in-flight challenge in the keychain and tell the
  user to re-run with `--code <CODE>`; that resumes *that* attempt, because a
  code is bound to the workflow that issued it.
- The parked entry is single-use: deleted on the next attempt whether it
  succeeds or fails.
- **Sign in through the browser** (`auth login --browser`, docs/api.md §2.8)
  rather than retrying the password login. Live on 2026-10-27 the password
  login re-challenged on every attempt and no prompt reached the phone.
  `--browser` opens Chrome at robinhood.com/login with a throwaway profile,
  the owner signs in on Robinhood's page, and `rhd` reads the stored session,
  closes the tab at once (so the web app cannot rotate the refresh token it
  shares with `rhd`, or log it out), and spends one ordinary read proving it.
  It needs the owner at the window: never run it unattended or from a test.
  `--session-stdin` is the fallback (a session copied out of DevTools), and
  goes through the same parser, proof and keychain item. Either bundle
  carries its own `origin` and the browser's `device_token`, and renews with
  that device — never with the profile's `<profile>/device`, which it leaves
  untouched.
- **Ask before spending a live login.** Prefer the offline fixtures.

## Fixtures

`tests/fixtures/` is **synthetic** — every value is a dummy, and no captured
file is ever committed. Structure provenance varies by file and is recorded
in `tests/fixtures/README.md`: most model public community documentation,
cross-checked live; a few model endpoints no community client documents, so
their key sets were transcribed from a live capture (values replaced,
capture discarded). If you
ever capture a real response to check a shape, scrub it before it reaches the
working tree and never commit the raw file (a document `url` is a live
pre-signed credential). A test enforces the scrubbing policy positively:
identity-bearing fields must match a known dummy shape.

## Definition of done

`make verify` green, CI green, `docs/api.md` matching reality (including what
is still **UNVERIFIED-LIVE**), `--json` and human output in sync, and no
secrets or personal data anywhere in the diff — fixtures included.
