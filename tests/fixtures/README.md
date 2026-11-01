# Fixtures

**These are NOT captures.** Every file here is **synthetic**: every value is a
dummy per the policy below, and no raw capture has ever entered the repo.
Structure provenance varies by file (see the table): most were hand-written
on 2026-08-12 from public community documentation and then cross-checked
against live responses during the owner's first-login session; a few newer
ones (e.g. `sweeps.json`) model endpoints no community client documents, so
their *structure* — key sets, types, null-vs-absent — comes directly from a
live capture, hand-copied with every value replaced.

That matters twice over: this repo is written as if it were public, and a real
capture from a brokerage account carries account numbers, balances, holdings,
and cost basis — plus a `download_url` that is a **live pre-signed credential**
for a tax document.

`tests/fixture_shapes.rs` asserts that the fields the table views read still
exist, so an upstream rename fails the build instead of silently emptying a
column. It also enforces the synthetic-value policy below.

## Provenance

Structure — key names, nesting, types, null-vs-absent — is modelled on these
sources. Where they disagree, the newest was preferred.

| File | Modelled on |
| --- | --- |
| `accounts.json` | [rhood-rs `models/account.rs`](https://github.com/seferino-fernandez/rhood-rs/blob/main/crates/rhood-core/src/models/account.rs), [sanko `Account.md`](https://github.com/sanko/Robinhood/blob/master/Account.md); corrected against live 2026-08-21 — `portfolio` is **null** on the wire, and the four `brokerage_account_type` spellings mirror a real multi-account login (docs/api.md §3.2/§3.8). Extended 2026-10-05 from the live `include_managed`/`include_multiple_individual` read: every row carries `nickname` (`""` when unset), `management_type` and an **integer** `rhs_account_number` (dummy series `1000000NN`; the legacy default account's differs from its alphanumeric `account_number`, as live), plus a `managed` individual account and a nicknamed additional individual account |
| `acats_transfers.json` | **Live capture 2026-10-05** of `bonfire.robinhood.com/acats/?both_directions=true` (docs/api.md §3.13) — no community client documents the row shape, so the key set, types and null-vs-absent were copied from one read and every value replaced (dummy brokers `Example …`, DTCC/control numbers all zeros, contra owner `Sample Owner`, account references from the `1000000NN`/`9000000NN` series). Models a settled full transfer with equity and long/short cash legs, a residual cash sweep with a null broker name, and a rejected transfer into an account the login does not list. Keeps the live traps: `prev` (not `previous`) in the envelope, and a support-link `reject_reason` on settled rows |
| `positions.json` | [robin_stocks `account.py`](https://github.com/jmfernandes/robin_stocks/blob/master/robin_stocks/robinhood/account.py), rhood-rs position model; cross-checked live 2026-08-21 — `?account_number=` scopes truthfully and every row names its own `account`/`account_number`, so the fixture spans two accounts (docs/api.md §3.3/§3.8) |
| `quotes.json` | robin_stocks `get_quotes`/`get_stock_quote_by_id`, rhood-rs quote model — the **UNVERIFIED-LIVE** batch form (`/marketdata/quotes/?instruments=`, docs/api.md §3.8). Models the community-documented `null` entry for an unquotable instrument, and a null `last_trade_price` with the extended-hours print standing in. (A `portfolios.json` once sat here; it was removed with the endpoint — the §3.8 truth table records why no portfolio endpoint can be trusted) |
| `instruments.json` | [robin_stocks `urls.py`](https://github.com/jmfernandes/robin_stocks/blob/master/robin_stocks/robinhood/urls.py), rhood-rs instrument model |
| `instrument.json` | The single-instrument read `/instruments/<id>/` (robin_stocks `get_instrument_by_url`): one record, `instruments.json`'s key set, no envelope. Models an instrument the batched `?ids=` read leaves out (docs/api.md §3.3, live 2026-10-02); its `state: inactive` / `tradeable: false` is the likeliest reading of why, **UNVERIFIED-LIVE** |
| `orders.json` | robin_stocks `orders.py`, rhood-rs order model; `fees`/`executions` per [sanko `Order.md`](https://github.com/sanko/Robinhood/blob/master/Order.md); `total_notional`/`executed_notional` (nested `amount`/`currency_code`/`currency_id` objects) per a public example capture in [vovanmix/robinhood-nodets `examples/Order_resp.json`](https://github.com/vovanmix/robinhood-nodets/blob/master/examples/Order_resp.json) — the enrichment fields were **live-verified 2026-08-24** (docs/api.md §3.4), including the per-execution `rounded_notional` and that on a limit order `total_notional` (asked terms) differs from `executed_notional` (achieved), which the limit row models |
| `options_orders.json` | **Live-verified 2026-08-24** (docs/api.md §3.4.1). Key set from [robin_stocks `orders.py`/`urls.py`/`export.py`](https://github.com/jmfernandes/robin_stocks), a public example capture in [anthonyk1225/robinhood-to-xlsx `schemas/options.json`](https://github.com/anthonyk1225/robinhood-to-xlsx/blob/master/schemas/options.json), and [CIInc/robinhood-options-mobile `option_order.dart`/`option_leg.dart`](https://github.com/CIInc/robinhood-options-mobile). The sources **disagree on the leg shape** — the capture carries only an `option` URL; the CIInc model parses `strike_price`/`expiration_date`/`option_type` inline. **Live, legs arrived inline**; the fixture still keeps one row of each shape (a test pins both) so the resolver fallback for the older captured shape stays exercised |
| `options_positions.json`, `options_instruments.json`, `options_marketdata.json` | **Live capture 2026-10-01** (docs/api.md §3.9) — no community client documents the batched `ids=` forms or the clearing-basis block, so key sets, order, types, and null-vs-absent were copied from one read of each endpoint and every value replaced. Deliberate choices: the instruments batch is **out of request order** (as live); one position is **partly closed** so `average_price × quantity` ≠ `clearing_cost_basis` (the FIFO trap); every row is `long`/`debit` because no short was observed live (the short path is unit-tested only) |
| `options_events.json` | **Live capture 2026-10-02** (docs/api.md §3.10) — no community client documents this endpoint's row shape, so the key set, order, types and null-vs-absent were copied from one read and every value replaced. One row per live type (exercise, assignment, expiration); its `option_id`s are the contracts in `options_instruments.json`. Deliberate choices: the assignment's cash is a few cents short of shares × strike (fees, as live) and its `underlying_price` is null (an early assignment, as live); the expiration's cash is the live bare `"0"` |
| `options_instrument.json` | [rhood-rs `models/option.rs`](https://github.com/seferino-fernandez/rhood-rs/blob/main/crates/rhood-core/src/models/option.rs) (`OptionInstrument`: the contract's type lives under **`type`**), robin_stocks `export.py` (which resolves legs through this endpoint) |
| `dividends.json` | robin_stocks `get_dividends`; structure taken from a live capture 2026-08-13 (per-state key differences — docs/api.md §3.6) |
| `sweeps.json` | live capture 2026-08-13 (no community client models this endpoint — docs/api.md §3.7) |
| `documents.json` | [rhood-rs `document.rs`](https://github.com/seferino-fernandez/rhood-rs/blob/main/crates/rhood-core/src/models/document.rs), robin_stocks `download_all_documents`, [robinhood-decompiled `Documents.java`](https://github.com/ScriptedAlchemy/robinhood-decompiled/blob/main/app/sources/com/robinhood/shared/documents/statements/Documents.java) (the `type` enum); key set corrected against a live capture 2026-08-12 (`filetype`, `is_from_rhs` — docs/api.md §3.5) |
| `login_success.json` | [robin_stocks `authentication.py`](https://github.com/jmfernandes/robin_stocks/blob/master/robin_stocks/robinhood/authentication.py), [pyhood `auth.py`](https://github.com/jamestford/pyhood/blob/main/pyhood/auth.py), rhood-rs `OAuthResponse` |
| `web_auth_state.json` | The value robinhood.com keeps at `localStorage['web:auth_state']`, imported by `rhd auth login --session-stdin` (docs/api.md §2.8). Key set from the web app's own reader (`AuthPersistence_getAuthStateFromStorage`, which destructures exactly these nine keys) in the public robinhood.com JavaScript bundle, read 2026-10-27 — **no live capture**. It is the `/oauth2/token/` response, so values follow `login_success.json`. Whether the stored object carries keys beyond the nine the reader takes is **UNVERIFIED-LIVE** |
| `browser_session.json` | What `rhd auth login --browser`'s capture expression answers once the owner is signed in (docs/api.md §2.8): `web_auth_state.json` with `device_token` added, `null` as when `document.cookie` cannot see the `device_id` cookie and the browser's cookie jar has to fill it. Built from the expression's own code (`src/capture.rs`), **no live capture** |
| `login_verification_workflow.json` | [robin_stocks #521](https://github.com/jmfernandes/robin_stocks/issues/521) |
| `login_user_machine.json`, `login_user_view_challenge.json`, `login_user_view_approved.json` | a real trace quoted in [CIInc/robinhood-options-mobile `robinhood_service.dart`](https://github.com/CIInc/robinhood-options-mobile/blob/main/src/robinhood_options_mobile/lib/services/robinhood_service.dart) (identifiers replaced) |
| `login_challenge_legacy.json` | a real capture quoted in [pyrh #305](https://github.com/robinhood-unofficial/pyrh/issues/305) (identifiers replaced) |
| `error_bad_credentials.json` | [aurbano/robinhood-node #80](https://github.com/aurbano/robinhood-node/issues/80) |
| `error_unauthorized.json` | [torreyleonard/algotrader #66](https://github.com/torreyleonard/algotrader/issues/66) |
| `error_throttled.json` | [aurbano/robinhood-node #98](https://github.com/aurbano/robinhood-node/issues/98) |

Error bodies are rendered **compactly** (`{"detail":"..."}`, no space after the
colon) because that is how Django REST Framework — which Robinhood runs —
serializes them. Preserved verbatim so a byte-level comparison stays honest.

## Value policy

No fixture may carry anything that identifies a real account, person, holding,
or balance. Types and formats are preserved exactly, since the parsers depend
on them; values are obvious dummies:

| Value | Dummy used |
| --- | --- |
| Account numbers | `SAMPLE01`, `SAMPLE02` |
| Integer account references (`rhs_account_number`) | `100000001`…, `900000009` |
| The other side of a transfer | `Sample Owner`, `SAMPLE99`, `Example Securities`, DTCC `0000` |
| Account nicknames | `Sample Nickname` (or `""`) |
| UUIDs (ids, instrument/order/document ids) | `00000000-0000-4000-8000-…` |
| Ticker symbols | `SAMPL`, `TESTF` (and OCC contract symbols built on them, `SAMPL 261030C00050000`) |
| Company names | `Sample Industries Inc.`, `Test Fund ETF` |
| Money and quantities | round dummies (`150.0000`, `10.00000000`) |
| Tokens | `SAMPLE-…-TOKEN-NOT-A-REAL-CREDENTIAL` |
| `download_url` (pre-signed) | `https://example.invalid/presigned-url-redacted` |
| Usernames / emails | `user@example.com` |

Dates, booleans, and enum-ish strings (`filled`, `margin`, `account_statement`,
`workflow_status_approved`) are kept realistic — they carry no personal
information and the parsing logic depends on their exact form.

The enforcement test is written **positively** ("identity-bearing fields must
hold a known dummy shape") rather than as a denylist of real values, because a
denylist would itself publish the values it exists to keep out of the repo.

## Refreshing

If a shape needs checking against reality, capture with
`rhd api GET <path> > /tmp/raw.json` — **outside the repo** — and hand-copy the
*structure* back, applying the table above. `raw-*.json`, `capture-*.json`, and
`*.raw.json` are gitignored as a backstop, but the rule is simply: **never
commit a capture.** A `download_url` is a working credential, and the account
data is real.
