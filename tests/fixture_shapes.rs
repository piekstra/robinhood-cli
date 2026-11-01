//! Contract tests over `tests/fixtures/`.
//!
//! Two jobs:
//!
//! 1. Assert that the fields the CLI's table views actually read are present
//!    and correctly typed, so an upstream rename fails the build loudly rather
//!    than silently emptying a column.
//! 2. Enforce the synthetic-value policy in `tests/fixtures/README.md`, and
//!    scan the rest of the tracked sources for personal data.
//!
//! The fixtures are synthetic (see the README) — nothing here talks to a
//! network.

use std::path::PathBuf;

use serde_json::Value;

/// Substrings that betray a committed pre-signed URL.
///
/// Assembled at runtime rather than written as literals, so that this file —
/// which `tracked_sources_carry_no_personal_data` also scans — does not
/// contain the very markers it searches for. Exempting the scanner from its
/// own rule would be the easy fix and a worse one: it is a source file like
/// any other, and a real leak could land in it.
fn presign_markers() -> [String; 3] {
    [
        format!("X-Amz{}", "-Signature"),
        format!("X-Amz{}", "-Credential"),
        format!("amazonaws{}", ".com"),
    ]
}

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

fn results(name: &str) -> Vec<Value> {
    fixture(name)["results"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has no results array"))
        .clone()
}

// ---------------------------------------------------------------- pagination

/// Every collection endpoint uses the same DRF envelope, and `next` is a full
/// URL that the paginator follows verbatim.
#[test]
fn collections_use_the_cursor_envelope() {
    for name in [
        "accounts.json",
        "positions.json",
        "orders.json",
        "options_orders.json",
        "options_positions.json",
        "options_instruments.json",
        "options_events.json",
        "documents.json",
    ] {
        let v = fixture(name);
        assert!(v.get("results").is_some(), "{name}: no results");
        assert!(v.get("next").is_some(), "{name}: no next key");
        assert!(v.get("previous").is_some(), "{name}: no previous key");
    }
    // A non-null `next` must be an absolute URL, or following it breaks.
    let orders = fixture("orders.json");
    let next = orders["next"].as_str().expect("orders next");
    assert!(
        next.starts_with("https://"),
        "next must be absolute: {next}"
    );
}

// ----------------------------------------------------------------- accounts

#[test]
fn accounts_carry_the_fields_the_table_reads() {
    let rows = results("accounts.json");
    assert!(rows.len() >= 4, "model a multi-account login (4 seen live)");
    for r in &rows {
        assert!(r["account_number"].is_string(), "account_number missing");
        assert!(r["type"].is_string());
        // Money arrives as strings, never numbers — floats would lose cents.
        assert!(r["buying_power"].is_string());
        assert!(r["cash"].is_string());
        assert!(r["created_at"].is_string());
        // LIVE-VERIFIED 2026-08-21: the community-documented per-account
        // `portfolio` link is **null** in practice — the key exists, the URL
        // does not. Pinned so nobody "restores" a link path that would dead-
        // end at runtime (docs/api.md §3.8).
        assert!(r.get("portfolio").is_some(), "portfolio key exists");
        assert!(
            r["portfolio"].is_null(),
            "portfolio is null on the live wire"
        );
        // The richer designation `net-worth` prefers over cash/margin.
        assert!(r["brokerage_account_type"].is_string());
        // LIVE-VERIFIED 2026-08-21: per-row `portfolio_cash` — the cash leg
        // of `net-worth`'s computed equity, inherently per-account (unlike
        // the portfolio endpoints — docs/api.md §3.8).
        assert!(r["portfolio_cash"].is_string());
    }
}

/// The designation wire strings, LIVE-VERIFIED 2026-08-21 across a real
/// four-account login: `individual`, `ira_traditional`, `ira_roth`,
/// `joint_tenancy_with_ros` — note `ira_roth`, not the guessable
/// `roth_ira`. Pinned so a "helpful" rename to the guess fails loudly.
#[test]
fn the_designations_use_the_live_wire_spellings() {
    let rows = results("accounts.json");
    let designations: Vec<&str> = rows
        .iter()
        .map(|r| r["brokerage_account_type"].as_str().unwrap())
        .collect();
    for expected in [
        "individual",
        "ira_traditional",
        "ira_roth",
        "joint_tenancy_with_ros",
    ] {
        assert!(
            designations.contains(&expected),
            "missing live designation {expected}: {designations:?}"
        );
    }
    assert!(
        !designations.contains(&"roth_ira"),
        "`roth_ira` is the guess; the wire says `ira_roth`"
    );
}

/// The two balance sub-objects are mutually exclusive by account type; a
/// parser that assumes either is always present will panic on the other.
#[test]
fn cash_and_margin_balances_are_mutually_exclusive() {
    let rows = results("accounts.json");
    for r in &rows {
        let cash = r
            .get("cash_balances")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        let margin = r
            .get("margin_balances")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        assert!(
            cash != margin,
            "exactly one of cash_balances/margin_balances should be populated"
        );
    }
}

/// LIVE-VERIFIED 2026-10-05 (docs/api.md §3.2): with `include_managed` and
/// `include_multiple_individual` the listing also carries a managed account
/// and additional individual accounts. Every row carries `nickname` (`""`
/// when unset), `management_type`, and an INTEGER `rhs_account_number` —
/// the reference the ACATS listing joins through.
#[test]
fn accounts_carry_management_nickname_and_an_integer_rhs_number() {
    let rows = results("accounts.json");
    let managed = rows
        .iter()
        .filter(|r| r["management_type"] == "managed")
        .count();
    assert_eq!(managed, 1, "the fixture models one managed account");
    let individuals = rows
        .iter()
        .filter(|r| {
            r["brokerage_account_type"] == "individual" && r["management_type"] == "self_directed"
        })
        .count();
    assert!(
        individuals >= 2,
        "an additional individual account is modelled"
    );
    assert!(rows
        .iter()
        .any(|r| r["nickname"].as_str().is_some_and(|s| !s.is_empty())));
    for r in &rows {
        assert!(r["nickname"].is_string());
        assert!(
            r["rhs_account_number"].is_u64(),
            "rhs_account_number is an integer"
        );
    }
    assert_eq!(rows.iter().filter(|r| r["is_default"] == true).count(), 1);
}

// -------------------------------------------------------------------- ACATS

/// The two fixtures join the way the wire does: an ACATS row's integer
/// `rhs_account_number` names an account row's `rhs_account_number` — and,
/// for the legacy default account, not its `account_number`. The rejected
/// transfer's reference matches no listed account, by design.
#[test]
fn acats_rows_join_accounts_through_the_rhs_number() {
    let accounts = results("accounts.json");
    let find = |rhs: &serde_json::Value| {
        accounts
            .iter()
            .find(|a| &a["rhs_account_number"] == rhs)
            .map(|a| a["account_number"].as_str().unwrap().to_string())
    };
    for r in results("acats_transfers.json") {
        let joined = find(&r["rhs_account_number"]);
        if r["phase"] == "rejected" {
            assert_eq!(joined, None, "the rejected row names an unlisted account");
        } else {
            assert_eq!(joined.as_deref(), Some("SAMPLE01"));
            // The trap: joining on account_number instead finds nothing.
            let rhs_text = r["rhs_account_number"].as_u64().unwrap().to_string();
            assert!(
                accounts
                    .iter()
                    .all(|a| a["account_number"].as_str() != Some(rhs_text.as_str())),
                "the rhs reference must not equal any account_number"
            );
        }
    }
}

/// LIVE-VERIFIED 2026-10-05 (docs/api.md §3.13): the bonfire ACATS listing
/// pages with `prev` (not `previous`), names its account by integer
/// `rhs_account_number`, and carries quantities but no basis.
#[test]
fn acats_transfers_carry_assets_but_no_basis() {
    let v = fixture("acats_transfers.json");
    assert!(v.get("prev").is_some() && v.get("next").is_some());
    assert!(v.get("previous").is_none());
    let rows = results("acats_transfers.json");
    for r in &rows {
        for key in [
            "id",
            "direction",
            "phase",
            "transfer_type",
            "requested_at",
            "settlement_date",
            "estimated_settlement_date",
            "contra_broker_name",
            "contra_dtcc_number",
            "reject_reason",
            "assets",
        ] {
            assert!(r.get(key).is_some(), "acats row missing {key}");
        }
        assert!(r["rhs_account_number"].is_u64());
        for a in r["assets"].as_array().unwrap() {
            for key in [
                "asset_type",
                "direction",
                "quantity",
                "instrument_id",
                "iso_currency_code",
            ] {
                assert!(a.get(key).is_some(), "acats asset missing {key}");
            }
        }
    }
    // The trap: a settled row still carries a reject_reason.
    assert!(rows
        .iter()
        .any(|r| r["phase"] == "settled" && r["reject_reason"].is_string()));
    assert!(!serde_json::to_string(&v).unwrap().contains("basis"));
}

// ---------------------------------------------------------------- positions

/// The single most consequential shape fact: a position has **no symbol**,
/// only an instrument URL. Forgetting this is how the symbol column ends up
/// blank.
#[test]
fn positions_reference_instruments_by_url_and_carry_no_symbol() {
    for r in results("positions.json") {
        assert!(
            r.get("symbol").is_none(),
            "positions must not carry a symbol"
        );
        let inst = r["instrument"].as_str().expect("instrument url");
        assert!(inst.starts_with("https://api.robinhood.com/instruments/"));
        assert!(r["quantity"].is_string());
        assert!(r["average_buy_price"].is_string());
        // LIVE-VERIFIED 2026-08-21: every row names its own account (direct
        // `account_number` plus the `account` URL), which is what lets
        // `net-worth` verify per row that the `?account_number=` filter was
        // honored — the rail that caught the portfolio endpoints lying
        // (docs/api.md §3.8).
        assert!(r["account_number"].is_string());
        assert!(r["account"]
            .as_str()
            .expect("account url")
            .starts_with("https://api.robinhood.com/accounts/"));
    }
}

/// LIVE-VERIFIED 2026-08-21: `?account_number=` on positions scopes
/// **truthfully** — distinct row sets per account. The fixture models rows
/// from more than one account so the multi-account valuation path (and its
/// per-row ownership check) stays exercised.
#[test]
fn positions_span_more_than_one_account() {
    let rows = results("positions.json");
    let owners: std::collections::BTreeSet<&str> = rows
        .iter()
        .map(|r| r["account_number"].as_str().unwrap())
        .collect();
    assert!(
        owners.len() >= 2,
        "model holdings in ≥2 accounts: {owners:?}"
    );
    // Each row's direct account_number agrees with its own account URL —
    // the two claims `net-worth` cross-checks must not drift apart.
    for r in &rows {
        let url_tail = r["account"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(r["account_number"].as_str().unwrap(), url_tail);
    }
}

#[test]
fn instruments_resolve_a_symbol_by_id() {
    for r in results("instruments.json") {
        assert!(r["id"].is_string());
        assert!(r["symbol"].is_string());
    }
}

/// Position instrument URLs must resolve against the instruments fixture, or
/// the batched symbol lookup has nothing to join on.
#[test]
fn every_position_instrument_has_a_matching_instrument() {
    let ids: Vec<String> = results("instruments.json")
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect();
    for p in results("positions.json") {
        let url = p["instrument"].as_str().unwrap();
        let id = url.trim_end_matches('/').rsplit('/').next().unwrap();
        assert!(ids.iter().any(|i| i == id), "unresolvable instrument {url}");
    }
}

// ------------------------------------------------------------------- quotes

/// UNVERIFIED-LIVE shape (docs/api.md §3.8): the batched
/// `/marketdata/quotes/?instruments=` response, modelled on the community
/// record. Prices stay strings; `last_trade_price` can be **null** (the
/// extended-hours print stands in); the envelope can carry **null**
/// entries for unquotable instruments; rows name their instrument both
/// ways, which is the join key back to positions.
#[test]
fn quotes_price_instruments_and_join_back() {
    let rows = results("quotes.json");
    assert!(
        rows.iter().any(Value::is_null),
        "keep a null entry — the endpoint answers null for an unquotable \
         instrument, and the reader must survive it"
    );
    let quotes: Vec<&Value> = rows.iter().filter(|r| !r.is_null()).collect();
    assert!(quotes.len() >= 2);
    for q in &quotes {
        assert!(
            q["last_trade_price"].is_string() || q["last_trade_price"].is_null(),
            "last_trade_price is string-or-null"
        );
        assert!(q["instrument"]
            .as_str()
            .expect("instrument url")
            .starts_with("https://api.robinhood.com/instruments/"));
        assert!(q["instrument_id"].is_string());
    }
    // One row must exercise the documented fallback: regular print absent,
    // extended-hours print present.
    assert!(
        quotes
            .iter()
            .any(|q| q["last_trade_price"].is_null()
                && q["last_extended_hours_trade_price"].is_string()),
        "keep a row with only an extended-hours price"
    );
}

/// Every position's instrument must have a quote row, or the valuation path
/// would exercise only the happy half of its join.
#[test]
fn every_position_instrument_has_a_quote() {
    let quote_ids: Vec<String> = results("quotes.json")
        .iter()
        .filter(|r| !r.is_null())
        .map(|q| q["instrument_id"].as_str().unwrap().to_string())
        .collect();
    for p in results("positions.json") {
        let url = p["instrument"].as_str().unwrap();
        let id = url.trim_end_matches('/').rsplit('/').next().unwrap();
        assert!(quote_ids.iter().any(|q| q == id), "no quote for {url}");
    }
}

// ------------------------------------------------------------------- orders

#[test]
fn orders_carry_the_fields_basis_work_needs() {
    let rows = results("orders.json");
    for r in &rows {
        assert!(r["id"].is_string());
        assert!(r["side"].is_string());
        assert!(r["state"].is_string());
        assert!(r["created_at"].is_string());
        assert!(r["last_transaction_at"].is_string());
        assert!(r["instrument"].is_string());
    }
}

/// A cancelled order has `average_price: null` — the row a naive parser
/// crashes on, and the reason `average_price` is optional in the DTO.
#[test]
fn an_unfilled_order_has_a_null_average_price() {
    let cancelled = results("orders.json")
        .into_iter()
        .find(|r| r["state"] == "cancelled")
        .expect("fixture should include a cancelled order");
    assert!(cancelled["average_price"].is_null());
    assert_eq!(cancelled["cumulative_quantity"], "0.00000000");
}

/// A market order has no limit `price`, which is exactly why the DTO reports
/// `average_price` (what was achieved) rather than `price` (what was asked).
#[test]
fn a_market_order_has_no_limit_price_but_does_have_an_average() {
    let market = results("orders.json")
        .into_iter()
        .find(|r| r["type"] == "market")
        .expect("fixture should include a market order");
    assert!(market["price"].is_null());
    assert!(market["average_price"].is_string());
}

/// The fields the realized-gains feed reads off a filled equity order,
/// beyond the basics — LIVE-VERIFIED (2026-08-24): `fees` is a **flat
/// string**, `executed_notional` is a **nested money object**
/// (`amount`/`currency_code`), and each execution carries
/// price/quantity/**rounded_notional**/settlement_date/timestamp —
/// `rounded_notional` being a per-fill field no community client documents,
/// confirmed present on the live wire.
#[test]
fn filled_orders_carry_the_notional_fees_and_execution_detail() {
    let rows = results("orders.json");
    for r in rows.iter().filter(|r| r["state"] == "filled") {
        assert!(r["fees"].is_string(), "fees is a flat string");
        assert!(r["executed_notional"]["amount"].is_string());
        assert!(r["executed_notional"]["currency_code"].is_string());
        assert!(r.get("total_notional").is_some());
        let execs = r["executions"].as_array().expect("executions array");
        assert!(!execs.is_empty(), "a filled order has at least one fill");
        for e in execs {
            assert!(e["price"].is_string());
            assert!(e["quantity"].is_string());
            assert!(e["rounded_notional"].is_string());
            assert!(e["settlement_date"].is_string());
            assert_eq!(e["settlement_date"].as_str().unwrap().len(), 10);
            assert!(e["timestamp"].is_string());
        }
    }
}

/// LIVE-VERIFIED 2026-08-24: on a filled limit order `total_notional` (the
/// *asked* terms — limit price × quantity) and `executed_notional` (the
/// *achieved* ones) are both present and **differ**. Pinned so nobody
/// "simplifies" the DTO onto the asked figure — the same trap as `price`
/// vs `average_price`.
#[test]
fn total_and_executed_notional_differ_on_a_filled_limit_order() {
    let limit = results("orders.json")
        .into_iter()
        .find(|r| r["type"] == "limit" && r["state"] == "filled")
        .expect("fixture should include a filled limit order");
    assert!(limit["total_notional"]["amount"].is_string());
    assert_ne!(
        limit["total_notional"]["amount"], limit["executed_notional"]["amount"],
        "asked and achieved notionals must model the live divergence"
    );
}

/// A cancelled order has fills to report in neither `executions` nor
/// `executed_notional` — empty array and null respectively, not absent — so
/// the parser's null-tolerance stays exercised.
#[test]
fn a_cancelled_order_has_no_notional_and_no_executions() {
    let cancelled = results("orders.json")
        .into_iter()
        .find(|r| r["state"] == "cancelled")
        .expect("fixture should include a cancelled order");
    assert!(cancelled["executed_notional"].is_null());
    assert_eq!(cancelled["executions"].as_array().map(Vec::len), Some(0));
}

// --------------------------------------------------------- options positions

/// LIVE-VERIFIED 2026-10-01 (docs/api.md §3.9): `/options/positions/` rows
/// name the underlying and the contract id but carry **no strike and no
/// call/put** — the row's `type` is the position direction. Money and
/// quantities are 4-decimal strings; `average_price` is per contract; the
/// clearing basis carries its own direction.
#[test]
fn option_positions_carry_direction_quantity_and_basis_but_no_strike() {
    let rows = results("options_positions.json");
    assert!(rows.len() >= 2);
    for r in &rows {
        for key in [
            "account_number",
            "chain_symbol",
            "option_id",
            "quantity",
            "average_price",
            "trade_value_multiplier",
            "expiration_date",
            "clearing_cost_basis",
            "clearing_direction",
            "opened_at",
        ] {
            assert!(r[key].is_string(), "{key} missing or not a string");
        }
        let t = r["type"].as_str().unwrap();
        assert!(
            t == "long" || t == "short",
            "position type is long/short: {t}"
        );
        assert!(
            r.get("strike_price").is_none(),
            "strike lives on the instrument"
        );
        assert!(
            r.get("option_type").is_none(),
            "call/put lives on the instrument"
        );
        assert!(r["option"]
            .as_str()
            .unwrap()
            .starts_with("https://api.robinhood.com/options/instruments/"));
        let d = r["clearing_direction"].as_str().unwrap();
        assert!(d == "debit" || d == "credit");
    }
}

/// The live trap the DTO's `cost_basis` exists for: after a partial close,
/// `average_price × quantity` (a running average) and `clearing_cost_basis`
/// (FIFO remaining lots) disagree. Keep a row that shows it.
#[test]
fn option_positions_model_average_and_clearing_basis_disagreeing() {
    let rows = results("options_positions.json");
    let disagrees = rows.iter().any(|r| {
        let avg: f64 = r["average_price"].as_str().unwrap().parse().unwrap();
        let qty: f64 = r["quantity"].as_str().unwrap().parse().unwrap();
        let clearing: f64 = r["clearing_cost_basis"].as_str().unwrap().parse().unwrap();
        (avg * qty - clearing).abs() > 0.5
    });
    assert!(
        disagrees,
        "keep a partly-closed row (average x qty != clearing)"
    );
}

/// The batched `/options/instruments/?ids=` read: strike, expiry, call/put
/// under **`type`**. Live, rows came back in a different order than the ids
/// were asked in, so the fixture is out of order and the join is by `id`.
#[test]
fn option_instruments_describe_every_held_contract_by_id() {
    let insts = results("options_instruments.json");
    let positions = results("options_positions.json");
    for i in &insts {
        let t = i["type"].as_str().unwrap();
        assert!(t == "call" || t == "put");
        assert!(i["strike_price"].is_string());
        assert!(i["trade_value_multiplier"].is_string());
    }
    let ids: Vec<&str> = insts.iter().map(|i| i["id"].as_str().unwrap()).collect();
    let wanted: Vec<&str> = positions
        .iter()
        .map(|p| p["option_id"].as_str().unwrap())
        .collect();
    for w in &wanted {
        assert!(ids.contains(w), "no instrument for {w}");
    }
    assert_ne!(ids, wanted, "keep the batch out of request order");
}

/// `/marketdata/options/?ids=`: an envelope with `results` only (no
/// cursor), per-share marks as 6-decimal strings, sizes as integers, and
/// the OCC symbol — the per-contract identity.
#[test]
fn option_marketdata_marks_every_held_contract() {
    let v = fixture("options_marketdata.json");
    assert!(v.get("next").is_none(), "marketdata carries no cursor");
    let rows = results("options_marketdata.json");
    for m in &rows {
        assert!(m["mark_price"].is_string());
        assert!(m["adjusted_mark_price"].is_string());
        assert!(m["instrument_id"].is_string());
        assert!(m["occ_symbol"].is_string());
        assert!(m["updated_at"].is_string());
        assert!(m["open_interest"].is_u64());
    }
    for p in results("options_positions.json") {
        let id = p["option_id"].as_str().unwrap();
        assert!(
            rows.iter().any(|m| m["instrument_id"] == id),
            "no mark for {id}"
        );
    }
}

// ------------------------------------------------------------ option events

/// LIVE-VERIFIED 2026-10-02 (docs/api.md §3.10): every `/options/events/`
/// row carries the same key set, and no contract detail beyond the
/// instrument id — the strike, call/put and expiry come from the batched
/// instruments read, joined by `option_id`.
#[test]
fn option_events_carry_the_fields_resolution_needs_but_no_contract_detail() {
    let rows = results("options_events.json");
    let insts = results("options_instruments.json");
    for e in &rows {
        for key in [
            "id",
            "type",
            "state",
            "direction",
            "event_date",
            "quantity",
            "total_cash_amount",
            "option_id",
            "account_number",
        ] {
            assert!(e[key].is_string(), "{key} on {}", e["id"]);
        }
        assert!(e["equity_components"].is_array());
        for absent in [
            "chain_symbol",
            "strike_price",
            "expiration_date",
            "option_type",
        ] {
            assert!(e.get(absent).is_none(), "{absent} is not on the wire");
        }
        let id = e["option_id"].as_str().unwrap();
        assert!(
            insts.iter().any(|i| i["id"] == id),
            "no instrument for {id}"
        );
    }
}

/// The three live shapes: an exercise buys shares at the strike for
/// exactly shares × strike; an assignment sells them for a little LESS
/// (fees deducted) with a null `underlying_price` when early; an
/// expiration moves no shares and its cash is a bare `"0"`.
#[test]
fn option_events_model_exercise_assignment_and_expiration() {
    let rows = results("options_events.json");
    let of = |t: &str| rows.iter().find(|e| e["type"] == t).unwrap().clone();

    let ex = of("exercise");
    assert_eq!(ex["direction"], "debit");
    let leg = &ex["equity_components"][0];
    assert_eq!(leg["side"], "buy");
    assert_eq!(leg["quantity"], "200.00000000", "8-decimal shares");
    assert_eq!(ex["quantity"], "2.0000", "4-decimal contracts");
    assert_eq!(
        ex["total_cash_amount"], "8000.00",
        "shares x strike exactly"
    );

    let asg = of("assignment");
    assert_eq!(asg["direction"], "credit");
    assert_eq!(asg["equity_components"][0]["side"], "sell");
    assert!(asg["underlying_price"].is_null(), "early assignment");
    assert!(asg["source_ref_id"].is_null());
    assert_ne!(
        asg["total_cash_amount"], "5000.00",
        "net of the sale's fees, not shares x strike"
    );

    let exp = of("expiration");
    assert_eq!(exp["equity_components"].as_array().unwrap().len(), 0);
    assert_eq!(exp["total_cash_amount"], "0", "a bare zero, no decimals");
    assert!(exp["cash_component"].is_null());
}

// ------------------------------------------------------------ options orders

/// LIVE-VERIFIED 2026-08-24 (docs/api.md §3.4.1): the `/options/orders/`
/// envelope and key set, built from community sources and confirmed in the
/// owner smoke. These are the fields the realized-gains feed reads: date,
/// state, direction, premium figures, and per-leg descriptions. (What the
/// smoke did *not* exercise is the bare-leg resolver path — the URL-only
/// row below exists exactly to keep that older captured shape pinned.)
#[test]
fn options_orders_carry_the_fields_premium_work_needs() {
    let rows = results("options_orders.json");
    assert!(rows.len() >= 3);
    for r in &rows {
        assert!(r["id"].is_string());
        assert!(r["state"].is_string());
        // The underlying's ticker is carried directly — no instrument
        // resolution step, unlike equity orders.
        assert!(r["chain_symbol"].is_string());
        assert!(
            r["direction"] == "credit" || r["direction"] == "debit",
            "direction is the debit/credit flag: {:?}",
            r["direction"]
        );
        // Money stays strings — never JSON numbers.
        assert!(r["processed_premium"].is_string());
        assert!(r["premium"].is_string());
        assert!(r["processed_quantity"].is_string());
        assert!(r["created_at"].is_string());
        assert!(r["updated_at"].is_string());
        let legs = r["legs"].as_array().expect("legs array");
        assert!(!legs.is_empty());
        for leg in legs {
            assert!(leg["side"].is_string());
            assert!(leg["position_effect"].is_string());
            assert!(leg["ratio_quantity"].is_number());
            assert!(leg["option"]
                .as_str()
                .expect("option instrument url")
                .starts_with("https://api.robinhood.com/options/instruments/"));
            assert!(leg["executions"].is_array());
        }
    }
}

/// The community sources disagree about whether a leg describes itself:
/// captured responses carry only the `option` URL, while a newer community
/// model parses strike/expiry/type inline. The fixture keeps one row of each
/// shape so both parser paths stay exercised (docs/api.md §3.4.1).
#[test]
fn option_legs_model_both_community_shapes() {
    let rows = results("options_orders.json");
    let leg_described = |r: &Value| {
        r["legs"].as_array().unwrap().iter().all(|leg| {
            leg["option_type"].is_string()
                && leg["strike_price"].is_string()
                && leg["expiration_date"].is_string()
        })
    };
    let leg_bare = |r: &Value| {
        r["legs"].as_array().unwrap().iter().all(|leg| {
            leg.get("option_type").is_none()
                && leg.get("strike_price").is_none()
                && leg.get("expiration_date").is_none()
        })
    };
    assert!(
        rows.iter().any(leg_described),
        "keep a row whose legs carry inline strike/expiry/type"
    );
    assert!(
        rows.iter().any(leg_bare),
        "keep a row whose legs carry only the option URL — the captured shape"
    );
}

/// A round trip needs both directions and both position effects, and a
/// multi-leg strategy must survive parsing — premium is order-level, not
/// per-leg, so a spread is where a naive per-leg reader breaks.
#[test]
fn options_orders_cover_a_round_trip_and_a_spread() {
    let rows = results("options_orders.json");
    let effect = |e: &str| {
        rows.iter().any(|r| {
            r["legs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l["position_effect"] == e)
        })
    };
    assert!(effect("open") && effect("close"));
    assert!(rows.iter().any(|r| r["direction"] == "credit"));
    assert!(rows.iter().any(|r| r["direction"] == "debit"));
    assert!(
        rows.iter()
            .any(|r| r["legs"].as_array().unwrap().len() >= 2),
        "keep a multi-leg (spread) order"
    );
    // A cancelled order: nothing processed, no fills.
    let cancelled = rows
        .iter()
        .find(|r| r["state"] == "cancelled")
        .expect("keep a cancelled options order");
    assert_eq!(cancelled["processed_quantity"], "0.00000");
    assert!(cancelled["legs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l["executions"].as_array().unwrap().is_empty()));
}

/// The resolved option instrument (the fallback for bare legs): its type key
/// is **`type`**, not `option_type` — pinned so the resolver keeps reading
/// the wire's word for it — and strike/expiry are strings.
#[test]
fn the_option_instrument_describes_a_contract_under_the_type_key() {
    let v = fixture("options_instrument.json");
    assert!(v["type"].is_string());
    assert!(v.get("option_type").is_none(), "the wire key is `type`");
    assert!(v["strike_price"].is_string());
    assert!(v["expiration_date"].is_string());
    assert_eq!(v["expiration_date"].as_str().unwrap().len(), 10);
    assert!(v["id"].is_string());
}

// ---------------------------------------------------------------- dividends

#[test]
fn dividends_carry_the_fields_div_reconciliation_needs() {
    let rows = results("dividends.json");
    for r in &rows {
        assert!(r["id"].is_string());
        assert!(
            r["instrument"].is_string(),
            "no symbol — instrument URL only"
        );
        assert!(r["amount"].is_string(), "money stays a string");
        assert!(r["withholding"].is_string());
        assert!(r["state"].is_string());
        // Direct account number, unlike the `account` URL next to it.
        assert!(r["account_number_rhs"].is_string());
        assert!(r["payable_date"].is_string());
    }
}

/// LIVE-VERIFIED 2026-08-13: `paid_at` is null exactly for voided dividends,
/// and reinvested rows carry `drip_order_*` keys the other states lack
/// entirely (absent, not null). A parser requiring either breaks.
#[test]
fn dividend_states_differ_in_shape_the_way_the_live_capture_showed() {
    let rows = results("dividends.json");
    let by_state = |s: &str| {
        rows.iter()
            .find(|r| r["state"] == s)
            .unwrap_or_else(|| panic!("fixture should include a {s} dividend"))
    };
    assert!(by_state("voided")["paid_at"].is_null());
    assert!(by_state("paid")["paid_at"].is_string());
    assert!(by_state("reinvested").get("drip_order_id").is_some());
    assert!(by_state("paid").get("drip_order_id").is_none());
}

// ----------------------------------------------------------------- interest

/// LIVE-VERIFIED 2026-08-13: sweeps nest money as an object — the only place
/// the API does — and carry a direct `account_number`.
#[test]
fn sweeps_carry_nested_money_and_a_direct_account_number() {
    let rows = results("sweeps.json");
    for r in &rows {
        assert!(r["id"].is_string());
        assert!(r["amount"]["amount"].is_string());
        assert!(r["amount"]["currency_code"].is_string());
        assert!(r["account_number"].is_string());
        assert!(r["pay_date"].is_string());
        assert_eq!(r["pay_date"].as_str().unwrap().len(), 10);
        assert!(r["payout_type"].is_string());
    }
}

// ---------------------------------------------------------------- documents

#[test]
fn documents_carry_the_fields_the_downloader_needs() {
    for r in results("documents.json") {
        assert!(r["id"].is_string());
        assert!(r["type"].is_string());
        assert!(r["date"].is_string());
        assert!(r["download_url"].is_string());
        // LIVE-VERIFIED 2026-08-12: every document declares its `filetype`,
        // and download verification keys off it.
        assert!(r["filetype"].is_string());
        assert!(
            ["pdf", "csv", "html"].contains(&r["filetype"].as_str().unwrap()),
            "unexpected filetype {:?}",
            r["filetype"]
        );
        // `date` is a bare ISO date, not a timestamp.
        assert_eq!(r["date"].as_str().unwrap().len(), 10);
    }
}

/// LIVE-VERIFIED 2026-08-12: one tax season ships the consolidated 1099 as a
/// PDF *and* as a CSV export under the same `type`. Losing either row from
/// the fixture would untest the split that made the CSV undownloadable once.
#[test]
fn the_consolidated_1099_comes_as_both_pdf_and_csv() {
    let docs = results("documents.json");
    let filetypes: Vec<&str> = docs
        .iter()
        .filter(|r| r["type"] == "1099")
        .map(|r| r["filetype"].as_str().unwrap())
        .collect();
    assert!(filetypes.contains(&"pdf"), "filetypes: {filetypes:?}");
    assert!(filetypes.contains(&"csv"), "filetypes: {filetypes:?}");
}

/// The filter/type value for the consolidated 1099 is the **bare** string
/// `1099`. `tax_1099` is the natural guess and returns HTTP 400 — pinning it
/// here keeps a future edit from "helpfully" renaming it.
#[test]
fn the_consolidated_1099_type_is_the_bare_string() {
    let docs = results("documents.json");
    let types: Vec<&str> = docs.iter().map(|r| r["type"].as_str().unwrap()).collect();
    assert!(types.contains(&"1099"), "types: {types:?}");
    assert!(!types.iter().any(|t| t.contains("tax_1099")));
    assert!(types.contains(&"account_statement"));
    assert!(types.contains(&"trade_confirm"));
}

// --------------------------------------------------------------- auth flow

#[test]
fn a_successful_login_carries_the_token_triple() {
    let v = fixture("login_success.json");
    assert!(v["access_token"].is_string());
    assert!(v["refresh_token"].is_string());
    assert_eq!(v["token_type"], "Bearer");
    assert!(v["expires_in"].is_number());
    // Present because the login body sets create_read_only_secondary_token.
    assert!(v["read_only_secondary_access_token"].is_string());
}

/// `web:auth_state` is the token response the web app stored: the nine keys
/// its own reader destructures (docs/api.md §2.8). The importer reads the
/// token triple and the read-only token, and has to cope with the nulls.
#[test]
fn the_web_auth_state_is_the_token_response() {
    let v = fixture("web_auth_state.json");
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "access_token",
            "backup_code",
            "expires_in",
            "mfa_code",
            "read_only_secondary_access_token",
            "refresh_token",
            "scope",
            "token_type",
            "user_uuid",
        ]
    );
    assert!(v["access_token"].is_string());
    assert!(v["refresh_token"].is_string());
    assert!(v["read_only_secondary_access_token"].is_string());
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(v["scope"], "internal");
    // The device id is not in localStorage; the `--browser` capture and the
    // --help Console snippet add it from the `device_id` cookie.
    assert!(v.get("device_token").is_none());
    // Same key set as the password login's response.
    let login = fixture("login_success.json");
    let mut login_keys: Vec<&str> = login
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    login_keys.sort_unstable();
    assert_eq!(keys, login_keys);
}

/// What `rhd auth login --browser`'s expression answers once the owner is
/// signed in: the stored session's keys plus `device_token`, null when the
/// page could not read the `device_id` cookie (the jar's copy then fills it;
/// docs/api.md §2.8). Anything else here would mean the browser path hands
/// the parser a different shape than a paste does.
#[test]
fn the_browser_capture_is_the_web_auth_state_with_a_device_slot() {
    let browser = fixture("browser_session.json");
    assert!(browser["device_token"].is_null());
    let mut stored = fixture("web_auth_state.json");
    stored["device_token"] = Value::Null;
    assert_eq!(browser, stored);
}

#[test]
fn the_device_approval_response_carries_a_workflow_id() {
    let v = fixture("login_verification_workflow.json");
    assert!(v["verification_workflow"]["id"].is_string());
    assert_eq!(
        v["verification_workflow"]["workflow_status"],
        "workflow_status_internal_pending"
    );
}

/// The sheriff challenge is duplicated at two paths in real responses, and
/// different community clients read different ones. Both must be present, or
/// the CLI's two-path lookup is untested.
#[test]
fn the_sheriff_challenge_appears_at_both_paths() {
    let v = fixture("login_user_view_challenge.json");
    let direct = v
        .pointer("/context/sheriff_challenge")
        .expect("direct path");
    let nested = v
        .pointer("/type_context/context/sheriff_challenge")
        .expect("nested path");
    assert_eq!(direct, nested, "the duplicate must actually match");
    assert!(direct["id"].is_string());
    assert!(direct["type"].is_string());
    assert_eq!(direct["status"], "issued");
}

#[test]
fn the_approved_workflow_says_approved() {
    let v = fixture("login_user_view_approved.json");
    assert_eq!(v["type_context"]["result"], "workflow_status_approved");
}

#[test]
fn the_legacy_challenge_still_parses() {
    let v = fixture("login_challenge_legacy.json");
    assert!(v["challenge"]["id"].is_string());
    assert!(v["challenge"]["type"].is_string());
    assert_eq!(v["challenge"]["status"], "issued");
}

/// Error bodies key off `detail`. The 429 message carries the wait, which is
/// the actionable part.
#[test]
fn error_bodies_use_detail() {
    for name in [
        "error_bad_credentials.json",
        "error_unauthorized.json",
        "error_throttled.json",
    ] {
        assert!(fixture(name)["detail"].is_string(), "{name}");
    }
    let throttled = fixture("error_throttled.json");
    assert!(throttled["detail"].as_str().unwrap().contains("throttled"));
}

// ------------------------------------------------------- the scrubbing rails

fn all_fixtures() -> Vec<(String, Value)> {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read_to_string(&path).expect("read fixture");
        let v = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {name}: {e}"));
        out.push((name, v));
    }
    assert!(
        !out.is_empty(),
        "no fixtures found — the scrub check is vacuous"
    );
    out
}

/// The value policy from `tests/fixtures/README.md`.
///
/// Stated positively — "identity-bearing fields must hold a known dummy" —
/// rather than as a denylist of real values, because a denylist would itself
/// publish the values it exists to keep out of the repo.
#[test]
fn fixtures_carry_only_synthetic_identifiers() {
    for (name, value) in all_fixtures() {
        check(&value, None, &name);
    }
}

fn check(v: &Value, key: Option<&str>, path: &str) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                check(val, Some(k), path);
            }
        }
        Value::Array(items) => {
            for item in items {
                check(item, key, path);
            }
        }
        Value::String(s) => {
            let ok = match key {
                // `starts_with` so `account_number_rhs` (dividends) and any
                // future variant get the same guard, not the fallthrough.
                Some(k) if k.starts_with("account_number") => s.starts_with("SAMPLE"),
                // The other side of an ACATS transfer: its owner, account
                // and broker are as identifying as ours.
                Some("contra_account_number") => s.starts_with("SAMPLE"),
                Some("contra_account_name") => s.starts_with("Sample"),
                Some("contra_broker_name") => s.starts_with("Example"),
                Some("contra_dtcc_number") | Some("control_number") => s.chars().all(|c| c == '0'),
                Some("nickname") => s.is_empty() || s.starts_with("Sample"),
                Some("symbol") | Some("chain_symbol") => s == "SAMPL" || s == "TESTF",
                // OCC contract symbols lead with the underlying's ticker.
                Some("occ_symbol") => s.starts_with("SAMPL ") || s.starts_with("TESTF "),
                Some("name") | Some("simple_name") => {
                    s.starts_with("Sample") || s.starts_with("Test")
                }
                // Pre-signed links are live credentials; only the dummy host.
                Some("download_url") => s.starts_with("https://example.invalid/"),
                Some("access_token")
                | Some("refresh_token")
                | Some("read_only_secondary_access_token") => s.starts_with("SAMPLE-"),
                _ => true,
            };
            assert!(
                ok,
                "{path}: key `{}` holds a non-synthetic value {s:?} — see \
                 tests/fixtures/README.md",
                key.unwrap_or("?")
            );

            // Any UUID-shaped string anywhere must be a dummy, whatever key
            // it hides under.
            assert!(
                !looks_like_uuid(s) || is_dummy_uuid(s),
                "{path}: key `{}` holds a real-looking UUID {s:?}",
                key.unwrap_or("?")
            );

            // No pre-sign material anywhere, under any key.
            for marker in presign_markers() {
                assert!(
                    !s.contains(&marker),
                    "{path}: value contains {marker:?} — never commit a pre-signed URL"
                );
            }
        }
        // The integer account reference (`rhs_account_number`) must be one
        // of the dummy series, never a real number.
        Value::Number(n) if key.is_some_and(|k| k.starts_with("rhs_account_number")) => {
            let s = n.to_string();
            assert!(
                s.len() == 9 && (s.starts_with("1000000") || s.starts_with("9000000")),
                "{path}: `{}` holds a non-synthetic account reference {s}",
                key.unwrap_or("?")
            );
        }
        _ => {}
    }
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.as_bytes()[8] == b'-'
        && s.as_bytes()[13] == b'-'
        && s.as_bytes()[18] == b'-'
        && s.as_bytes()[23] == b'-'
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A dummy UUID is nearly all zeros — at most a few significant digits.
fn is_dummy_uuid(s: &str) -> bool {
    s.chars().filter(|c| *c != '-' && *c != '0').count() <= 4
}

/// The scrub check has to be able to fail, or it proves nothing.
#[test]
fn the_dummy_uuid_rule_rejects_a_real_looking_uuid() {
    assert!(looks_like_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(is_dummy_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(is_dummy_uuid("00000000-0000-4000-8000-0000000000f1"));

    assert!(looks_like_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));
    assert!(!is_dummy_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));

    assert!(!looks_like_uuid("not-a-uuid"));
}

/// The fixture check only ever guarded `tests/fixtures/`. Personal data leaks
/// into prose and examples at least as easily — a phone number in a doc
/// comment, an account number in a README example — so scan the tracked
/// sources too.
#[test]
fn tracked_sources_carry_no_personal_data() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files"])
        .output();
    let Ok(out) = out else {
        return; // not a git checkout (vendored build) — nothing to scan
    };
    if !out.status.success() {
        return;
    }

    let files = String::from_utf8_lossy(&out.stdout);
    let markers = presign_markers();
    let mut scanned = 0usize;
    for rel in files.lines() {
        if rel.starts_with("tests/fixtures/") || rel.ends_with(".lock") {
            continue;
        }
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;

        for (n, line) in text.lines().enumerate() {
            assert!(
                !has_phone_shape(line),
                "{rel}:{}: looks like a real phone number",
                n + 1
            );
            // The one real bearer-ish constant in this repo is the public
            // OAuth client id, which identifies the app and is not a user
            // credential.
            for marker in &markers {
                assert!(!line.contains(marker), "{rel}:{}: {marker}", n + 1);
            }
        }
    }
    assert!(scanned > 0, "scanned nothing — the check would be vacuous");
}

/// `NNN-NNN-NNNN` / `(NNN) NNN-NNNN`, ignoring version-like and date-like runs.
fn has_phone_shape(line: &str) -> bool {
    let digits: Vec<char> = line
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let s: String = digits.into_iter().collect();
    for part in s.split(|c: char| !c.is_ascii_digit() && c != '-') {
        let groups: Vec<&str> = part.split('-').collect();
        if groups.len() == 3 && groups[0].len() == 3 && groups[1].len() == 3 && groups[2].len() == 4
        {
            return true;
        }
    }
    false
}

#[test]
fn the_phone_shape_rule_can_fail() {
    // Assembled rather than written out, for the same reason as
    // `presign_markers`: this file is scanned by the rule it is testing, and
    // even a fictional 555 number would trip it.
    let sample = format!("call {}-{}-{} now", "555", "867", "5309");
    assert!(has_phone_shape(&sample));

    assert!(!has_phone_shape("version 1.431.4"));
    assert!(!has_phone_shape("2026-08-12"));
    assert!(!has_phone_shape("00000000-0000-4000-8000-000000000001"));
}

/// A decimal wire string as an integer in 1e-8 units (the wire's own
/// precision), so the fill arithmetic below is exact.
fn e8(raw: &str) -> i128 {
    let (int, frac) = raw.split_once('.').unwrap_or((raw, ""));
    assert!(frac.len() <= 8, "`{raw}` is finer than the wire's 1e-8");
    let frac = format!("{frac:0<8}");
    int.parse::<i128>().unwrap() * 100_000_000 + frac.parse::<i128>().unwrap()
}

/// The consumer contract a per-leg reader rests on (docs/api.md §3.4.1,
/// live-verified 2026-10-02): on a filled order, each leg's fills — price
/// per share × contracts × 100, a sold leg receiving and a bought leg
/// paying — sum to the order's `processed_premium`, signed by `direction`.
/// So a multi-leg order's net premium splits into its legs' cash exactly.
#[test]
fn a_filled_orders_leg_fills_sum_to_its_processed_premium() {
    let rows = results("options_orders.json");
    let filled: Vec<&Value> = rows.iter().filter(|r| r["state"] == "filled").collect();
    assert!(filled
        .iter()
        .any(|r| r["legs"].as_array().unwrap().len() >= 2));
    for row in filled {
        let mut legs_cash = 0i128;
        for leg in row["legs"].as_array().unwrap() {
            let value: i128 = leg["executions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    e8(f["price"].as_str().unwrap()) * e8(f["quantity"].as_str().unwrap()) * 100
                        / 100_000_000
                })
                .sum();
            legs_cash += if leg["side"] == "sell" { value } else { -value };
        }
        let premium = e8(row["processed_premium"].as_str().unwrap());
        let signed = if row["direction"] == "credit" {
            premium
        } else {
            -premium
        };
        assert_eq!(legs_cash, signed, "{}", row["id"]);
    }
}
