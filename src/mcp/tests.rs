//! The `rhd mcp` tools, offline: every tool runs in process against the
//! scrubbed fixtures through the `Source` seam, mapped by the commands' own
//! mappers, and cli-common's conformance helper checks the definitions and
//! every result's shape and size.

use std::sync::Mutex;

use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definition_size};
use pk_cli_mcp::CallToolResult;
use serde_json::json;

use super::*;

fn results(raw: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(raw).expect("fixture parses");
    v["results"].as_array().expect("results").clone()
}

struct Fixtures {
    accounts: Vec<Value>,
    positions: Vec<Value>,
    /// Rows served in one account's positions whatever they claim, to test
    /// the attribution rail.
    served_to: Vec<(String, Value)>,
    quotes: Vec<Value>,
    instruments: Vec<Value>,
    orders: Vec<Value>,
    dividends: Vec<Value>,
    sweeps: Vec<Value>,
    documents: Vec<Value>,
    /// Every source call, as `method:arg`.
    calls: Mutex<Vec<String>>,
    /// When set, every call fails with this.
    fail: Mutex<Option<CliError>>,
}

impl Fixtures {
    fn new() -> Self {
        Self {
            accounts: results(include_str!("../../tests/fixtures/accounts.json")),
            positions: results(include_str!("../../tests/fixtures/positions.json")),
            served_to: Vec::new(),
            quotes: results(include_str!("../../tests/fixtures/quotes.json")),
            instruments: results(include_str!("../../tests/fixtures/instruments.json")),
            orders: results(include_str!("../../tests/fixtures/orders.json")),
            dividends: results(include_str!("../../tests/fixtures/dividends.json")),
            sweeps: results(include_str!("../../tests/fixtures/sweeps.json")),
            documents: results(include_str!("../../tests/fixtures/documents.json")),
            calls: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn record(&self, call: String) -> Result<(), CliError> {
        self.calls.lock().unwrap().push(call);
        match self.fail.lock().unwrap().as_ref() {
            None => Ok(()),
            Some(CliError::Auth(m)) => Err(CliError::Auth(m.clone())),
            Some(CliError::Upstream(m)) => Err(CliError::Upstream(m.clone())),
            Some(other) => Err(CliError::Other(other.to_string())),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn owned_by(rows: &[Value], key: &str, account: &str) -> Vec<Value> {
    rows.iter()
        .filter(|r| str_at(r, key).as_deref() == Some(account))
        .cloned()
        .collect()
}

impl Source for Fixtures {
    async fn accounts(&self) -> Result<Vec<(String, Value)>, CliError> {
        self.record("accounts".into())?;
        Ok(self
            .accounts
            .iter()
            .filter_map(|r| str_at(r, "account_number").map(|n| (n, r.clone())))
            .collect())
    }

    async fn positions(&self, account: &str) -> Result<Vec<Value>, CliError> {
        self.record(format!("positions:{account}"))?;
        let mut rows = owned_by(&self.positions, "account_number", account);
        rows.extend(
            self.served_to
                .iter()
                .filter(|(to, _)| to == account)
                .map(|(_, row)| row.clone()),
        );
        Ok(rows)
    }

    async fn prices(
        &self,
        instruments: &BTreeSet<String>,
    ) -> Result<HashMap<String, i64>, CliError> {
        self.record(format!("prices:{}", instruments.len()))?;
        Ok(networth::price_map(&self.quotes))
    }

    async fn symbols(&self, rows: &[&Value]) -> Result<HashMap<String, String>, CliError> {
        self.record("symbols".into())?;
        instruments::resolve_symbols_with(
            rows,
            |ids| {
                Ok(self
                    .instruments
                    .iter()
                    .filter(|i| str_at(i, "id").is_some_and(|id| ids.contains(&id)))
                    .cloned()
                    .collect())
            },
            |_| Ok(None),
        )
    }

    async fn orders(&self, account: &str, since: &str) -> Result<Vec<Value>, CliError> {
        self.record(format!("orders:{account}:{since}"))?;
        Ok(owned_by(&self.orders, "account_number", account))
    }

    async fn dividends(&self) -> Result<Vec<Value>, CliError> {
        self.record("dividends".into())?;
        Ok(self.dividends.clone())
    }

    async fn interest(&self) -> Result<Vec<Value>, CliError> {
        self.record("interest".into())?;
        Ok(self.sweeps.clone())
    }

    async fn documents(&self, kind: Option<&str>) -> Result<Vec<Value>, CliError> {
        self.record(format!("documents:{}", kind.unwrap_or("all")))?;
        Ok(self
            .documents
            .iter()
            .filter(|d| kind.is_none_or(|k| str_at(d, "type").as_deref() == Some(k)))
            .cloned()
            .collect())
    }
}

fn tools() -> RobinhoodTools<Fixtures> {
    RobinhoodTools::new(Fixtures::new(), Ok("default".into())).on(summer)
}

/// The pinned "today" of every test, so none depends on the clock.
fn summer() -> Civil {
    (2026, 8, 31)
}

fn err(r: &CallToolResult) -> &str {
    assert!(r.is_error(), "expected an error, got {}", r.text());
    assert!(r.structured().is_none());
    r.text()
}

fn field(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap_or("-").to_string())
        .collect()
}

fn find<'a>(items: &'a Value, key: &str, value: &str) -> &'a Value {
    items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i[key] == value)
        .unwrap_or_else(|| panic!("no item with {key} = {value} in {items}"))
}

// ---- the definitions --------------------------------------------------------

#[test]
fn the_tools_conform_to_the_mcp_profile() {
    assert_conforms(&tools());
}

#[test]
fn the_definitions_stay_small() {
    let t = tools();
    let mut total = 0;
    for name in [PORTFOLIO_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL] {
        let size = definition_size(&t, name);
        eprintln!("{name}: {size} characters");
        assert!(size < 2_500, "{name} takes {size} characters");
        total += size;
    }
    assert!(total <= 8_000, "the definitions take {total} characters");
}

#[test]
fn listing_and_describing_the_tools_reads_nothing() {
    let t = tools();
    let _ = t.tools();
    let _ = t.server();
    assert!(t.source().calls().is_empty());
}

// ---- robinhood_portfolio ----------------------------------------------------

#[test]
fn the_portfolio_values_every_account_and_position_exactly() {
    let t = tools();
    let r = call(&t, PORTFOLIO_TOOL, json!({}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    // Cash plus quantity x last trade, per account (net-worth's own sums):
    // 500 + 10 x 155 + 40 x 25.75; 250; 300 + 0.5 x 155; three x 100.
    assert_eq!(out["net_worth"]["total"], "4007.50");
    assert_eq!(out["net_worth"]["covers"], json!(["cash", "equities"]));
    assert!(out["net_worth"].get("liabilities").is_none());
    assert_eq!(
        field(&out["accounts"], "name"),
        [
            "individual …LE01",
            "ira_traditional",
            "ira_roth",
            "joint_tenancy_with_ros",
            "individual …LE05",
            "Sample Nickname"
        ]
    );
    assert_eq!(field(&out["accounts"], "total")[0], "3080.00");
    assert!(
        out["accounts"][0].get("account_number").is_none(),
        "concise"
    );

    assert_eq!(field(&out["items"], "symbol"), ["SAMPL", "TESTF", "SAMPL"]);
    let first = &out["items"][0];
    assert_eq!(first["account"], "individual …LE01");
    assert_eq!(first["quantity"], "10");
    assert_eq!(first["market_value"], "1550.00");
    assert_eq!(first["average_buy_price"], "150.00");
    assert!(first.get("price").is_none(), "concise");
    assert_eq!(out["items"][2]["account"], "ira_roth");
    assert_eq!(out["items"][2]["market_value"], "77.50");
    // One price lookup and one symbol lookup for every account's holdings.
    let calls = t.source().calls();
    assert_eq!(calls.iter().filter(|c| c.starts_with("prices")).count(), 1);
    assert_eq!(calls.iter().filter(|c| *c == "symbols").count(), 1);
}

#[test]
fn detailed_positions_add_the_price_and_ids() {
    let t = tools();
    let r = call(&t, PORTFOLIO_TOOL, json!({"response_format": "detailed"}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(out["items"][1]["price"], "25.75");
    assert_eq!(
        out["items"][1]["instrument_id"],
        "00000000-0000-4000-8000-000000000002"
    );
    assert_eq!(out["accounts"][0]["account_number"], "SAMPLE01");
}

#[test]
fn an_account_is_named_and_narrows_the_valuation() {
    let t = tools();
    let r = call(
        &t,
        PORTFOLIO_TOOL,
        json!({"account": "IRA_ROTH", "symbol": "sampl"}),
    );
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(out["net_worth"]["total"], "377.50");
    assert_eq!(field(&out["accounts"], "name"), ["ira_roth"]);
    assert_eq!(field(&out["items"], "market_value"), ["77.50"]);
    assert!(!t
        .source()
        .calls()
        .contains(&"positions:SAMPLE01".to_string()));

    let r = call(&t, PORTFOLIO_TOOL, json!({"account": "sample nickname"}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(out["net_worth"]["total"], "100.00");
    assert_eq!(out["returned"], 0);
}

#[test]
fn an_unknown_account_lists_the_names_that_exist() {
    let t = tools();
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({"account": "Rainy Day"}))).to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(text.contains("individual …LE01, ira_traditional"), "{text}");
}

/// A row in one account's listing that belongs to another is refused
/// (net-worth's rail), never valued under the wrong account.
#[test]
fn a_misattributed_position_fails_the_valuation() {
    let mut fixtures = Fixtures::new();
    let row = fixtures.positions[0].clone(); // SAMPLE01's
    fixtures.served_to.push(("SAMPLE02".into(), row));
    let t = RobinhoodTools::new(fixtures, Ok("default".into()));
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(text.contains("different account"), "{text}");
}

/// A login with no active account is refused, as `rhd net-worth` refuses
/// it, never reported as a net worth of zero.
#[test]
fn no_active_account_is_an_upstream_error_not_a_zero() {
    let mut fixtures = Fixtures::new();
    for row in &mut fixtures.accounts {
        row["deactivated"] = json!(true);
    }
    let t = RobinhoodTools::new(fixtures, Ok("default".into()));
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(text.contains("no active brokerage accounts"), "{text}");
}

#[test]
fn positions_page_with_a_cursor_bound_to_the_filters() {
    let t = tools();
    let first = call(&t, PORTFOLIO_TOOL, json!({"limit": 2}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &first);
    assert_eq!(out["returned"], 2);
    let cursor = out["next_cursor"].as_str().unwrap().to_string();
    let second = call(&t, PORTFOLIO_TOOL, json!({"limit": 2, "cursor": cursor}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &second);
    assert_eq!(field(&out["items"], "account"), ["ira_roth"]);
    let other = call(
        &t,
        PORTFOLIO_TOOL,
        json!({"limit": 2, "cursor": cursor, "symbol": "TESTF"}),
    );
    assert!(err(&other).starts_with("usage:"));
}

// ---- robinhood_activity -----------------------------------------------------

#[test]
fn activity_merges_trades_dividends_and_interest_newest_first() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    let kinds = field(&out["items"], "type");
    let dates = field(&out["items"], "date");
    assert!(dates.windows(2).all(|w| w[0] >= w[1]), "{dates:?}");
    // The cancelled order with nothing filled is not activity.
    assert_eq!(kinds.iter().filter(|k| *k == "trade").count(), 2);
    assert_eq!(kinds.iter().filter(|k| *k == "dividend").count(), 3);
    assert_eq!(kinds.iter().filter(|k| *k == "interest").count(), 2);
    let sell = find(&out["items"], "side", "sell");
    assert_eq!(sell["symbol"], "TESTF");
    assert_eq!(sell["quantity"], "20");
    assert_eq!(sell["price"], "30.00");
    assert_eq!(sell["amount"], "600.00");
    assert_eq!(sell["account"], "individual …LE01");
    assert!(sell.get("state").is_none(), "a filled trade says nothing");
    assert!(sell.get("fees").is_none(), "concise");
    let voided = find(&out["items"], "state", "voided");
    assert_eq!(voided["account"], "ira_traditional");
    // Orders are read per account from `since`.
    assert!(t
        .source()
        .calls()
        .contains(&"orders:SAMPLE06:2026-01-01".to_string()));
}

/// A page boundary falls inside a day, and a dividend pays before the next page. A cursor holds no
/// state at Robinhood, so a second set of fixtures stands for the later read.
#[test]
fn a_dividend_paid_between_pages_repeats_nothing_and_skips_nothing() {
    let template = Fixtures::new().dividends[0].clone();
    let row = |id: &str, date: &str| {
        let mut row = template.clone();
        row["id"] = json!(id);
        row["paid_at"] = json!(format!("{date}T12:00:00Z"));
        row["payable_date"] = json!(date);
        row
    };
    let with_rows = |rows: Vec<Value>| {
        let mut fixtures = Fixtures::new();
        fixtures.dividends = rows;
        RobinhoodTools::new(fixtures, Ok("default".into())).on(summer)
    };
    let before = vec![
        row("d", "2026-03-04"),
        row("c", "2026-03-03"),
        row("b", "2026-03-03"),
        row("a", "2026-03-01"),
    ];
    let mut after = vec![row("e", "2026-03-05")];
    after.extend(before.clone());
    let args = json!({"since": "2026-01-01", "until": "2026-12-31", "type": "dividend",
                      "limit": 2, "response_format": "detailed"});
    let ids = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect()
    };

    let tools = with_rows(before);
    let answer = call(&tools, ACTIVITY_TOOL, args.clone());
    let first = assert_fits(&tools, ACTIVITY_TOOL, &answer);
    let mut seen = ids(first);
    assert_eq!(seen[0], "d");
    let later = with_rows(after);
    let mut cursor = first["next_cursor"].clone();
    while cursor.is_string() {
        let mut next = args.clone();
        next["cursor"] = cursor;
        let answer = call(&later, ACTIVITY_TOOL, next);
        let page = assert_fits(&later, ACTIVITY_TOOL, &answer);
        seen.extend(ids(page));
        cursor = page["next_cursor"].clone();
    }
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(sorted, ["a", "b", "c", "d"], "{seen:?}");
}

#[test]
fn activity_narrows_by_type_symbol_account_and_window() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "type": "Dividend", "symbol": "SAMPL"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert!(!field(&out["items"], "type").is_empty());
    assert!(field(&out["items"], "type").iter().all(|k| k == "dividend"));
    assert!(field(&out["items"], "symbol").iter().all(|s| s == "SAMPL"));
    assert!(!t.source().calls().iter().any(|c| c.starts_with("orders")));

    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "type": "interest", "account": "ira_traditional"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "amount"), ["0.45"]);

    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-03-01", "until": "2026-03-31"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert!(field(&out["items"], "date")
        .iter()
        .all(|d| d.starts_with("2026-03")));
    let mut kinds = field(&out["items"], "type");
    kinds.sort();
    assert_eq!(kinds, ["dividend", "trade"]);
}

/// Dividends and interest come in one read for the login, so a row that
/// names no account is kept while no account is asked for, as
/// `rhd dividends list` keeps it, and left out once one is.
#[test]
fn a_payment_naming_no_account_is_kept_until_an_account_is_named() {
    let mut fixtures = Fixtures::new();
    let mut orphan = fixtures.dividends[0].clone();
    orphan.as_object_mut().unwrap().remove("account_number_rhs");
    orphan["id"] = json!("00000000-0000-4000-8000-000000000039");
    fixtures.dividends.push(orphan);
    let t = RobinhoodTools::new(fixtures, Ok("default".into()));
    let year = json!({"since": "2026-01-01", "until": "2026-12-31", "type": "dividend"});
    let r = call(&t, ACTIVITY_TOOL, year.clone());
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["returned"], 4);
    let unnamed: Vec<_> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i.get("account").is_none())
        .collect();
    assert_eq!(unnamed.len(), 1, "{out}");
    assert_eq!(unnamed[0]["amount"], "12.34");

    let mut scoped = year;
    scoped["account"] = json!("individual …LE01");
    let r = call(&t, ACTIVITY_TOOL, scoped);
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "amount"), ["5.00", "12.34"]);
    assert!(out["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["account"] == "individual …LE01"));
}

#[test]
fn a_symbol_filter_skips_the_interest_read() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "symbol": "TESTF"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert!(field(&out["items"], "symbol").iter().all(|s| s == "TESTF"));
    assert!(!t.source().calls().contains(&"interest".to_string()));
}

#[test]
fn activity_defaults_to_the_year_to_date() {
    let t = tools();
    let r = call(&t, ACTIVITY_TOOL, json!({}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(
        (&out["since"], &out["until"]),
        (&json!("2026-01-01"), &json!("2026-08-31"))
    );
}

/// The default `since` is January 1 of `until`'s year, not of today's: last
/// year asked for on New Year's Day is still last year.
#[test]
fn a_default_since_follows_until_across_a_year_end() {
    fn new_year() -> Civil {
        (2027, 1, 1)
    }
    let t = tools().on(new_year);
    let r = call(&t, ACTIVITY_TOOL, json!({"until": "2026-12-31"}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    let r = call(&t, ACTIVITY_TOOL, json!({}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(
        (&out["since"], &out["until"]),
        (&json!("2027-01-01"), &json!("2027-01-01"))
    );
}

#[test]
fn detailed_activity_adds_states_fees_and_ids() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-07-01", "until": "2026-07-31", "type": "trade", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    let sell = &out["items"][0];
    assert_eq!(sell["state"], "filled");
    assert_eq!(sell["fees"], "0.02");
    assert!(sell["id"].is_string());
}

#[test]
fn bad_arguments_fail_before_any_read() {
    let t = tools();
    for args in [
        json!({"since": "08/01/2026"}),
        json!({"since": "2026-09-01", "until": "2026-08-01"}),
        json!({"type": "transfer"}),
    ] {
        let text = err(&call(&t, ACTIVITY_TOOL, args.clone())).to_string();
        assert!(text.starts_with("usage:"), "{args}: {text}");
    }
    let text = err(&call(&t, DOCUMENTS_TOOL, json!({"type": "tax_1099"}))).to_string();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(text.contains("`1099`"), "{text}");
    assert!(t.source().calls().is_empty());
}

/// An unpadded date compares as a string, so it is padded first.
#[test]
fn unpadded_dates_are_padded_before_any_comparison() {
    let (s, u) = window(Some("2026-8-5"), Some("2026-08-31"), summer()).unwrap();
    assert_eq!((s.as_str(), u.as_str()), ("2026-08-05", "2026-08-31"));
}

// ---- robinhood_documents ----------------------------------------------------

#[test]
fn documents_list_names_and_types_never_a_link() {
    let t = tools();
    let r = call(&t, DOCUMENTS_TOOL, json!({}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(
        field(&out["items"], "date"),
        [
            "2027-03-01",
            "2027-02-15",
            "2026-07-31",
            "2026-06-30",
            "2026-03-14"
        ]
    );
    let form = find(&out["items"], "date", "2027-02-15");
    assert_eq!(form["name"], "Consolidated 1099 2027-02-15");
    assert_eq!(form["type"], "1099");
    assert!(form.get("id").is_none(), "concise");
    assert!(!r.text().contains("http"), "{}", r.text());
}

#[test]
fn tax_forms_alone_with_their_ids_on_request() {
    let t = tools();
    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"type": "1099", "since": "2027-01-01", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "type"), ["1099", "1099"]);
    assert!(out["items"][0]["id"].is_string());
    assert_eq!(t.source().calls(), ["documents:1099"]);
}

// ---- errors -----------------------------------------------------------------

#[test]
fn a_missing_session_asks_for_the_browser_login_in_a_terminal() {
    let t = RobinhoodTools::new(Fixtures::new(), Ok("household".into()));
    *t.source().fail.lock().unwrap() = Some(CliError::Auth(
        "no cached session for profile `household`".into(),
    ));
    for name in [PORTFOLIO_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL] {
        let text = err(&call(&t, name, json!({}))).to_string();
        assert!(text.starts_with("auth:"), "{name}: {text}");
        assert!(
            text.contains(
                "Ask the user to run `rhd auth login --browser --overwrite --profile household` \
                 in a terminal"
            ),
            "{name}: {text}"
        );
        assert!(text.contains("never sign in"), "{name}: {text}");
    }
}

/// A profile that could not be chosen fails every call before any read,
/// keeping its kind, with the remedy of choosing one.
#[test]
fn an_unchosen_profile_keeps_its_kind_and_reads_nothing() {
    for (why, kind) in [
        (
            CliError::Usage("several login profiles are configured (a, b)".into()),
            "usage:",
        ),
        (
            CliError::NotFound("no login profile named `c` (known: a, b)".into()),
            "not_found:",
        ),
    ] {
        let t = RobinhoodTools::new(Fixtures::new(), Err(why));
        for name in [PORTFOLIO_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL] {
            let text = err(&call(&t, name, json!({}))).to_string();
            assert!(text.starts_with(kind), "{name}: {text}");
            assert!(
                text.contains("no Robinhood login profile could be chosen"),
                "{name}: {text}"
            );
            assert!(text.contains("`rhd profiles use <NAME>`"), "{name}: {text}");
        }
        assert!(t.source().calls().is_empty());
    }
}

#[test]
fn a_provider_failure_is_upstream_not_the_arguments() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Upstream("HTTP 503".into()));
    let text = err(&call(&t, ACTIVITY_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(!text.contains("auth login"), "{text}");
}

/// A block at the edge is not cleared by signing in, so the fix does not lead with one.
#[test]
fn a_block_at_the_edge_does_not_ask_for_a_new_sign_in_first() {
    let t = RobinhoodTools::new(Fixtures::new(), Ok("household".into()));
    const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
    *t.source().fail.lock().unwrap() = Some(
        crate::client::classify(403, "https://example.test/dummy", None, PAGE)
            .unwrap_err()
            .into_cli_error(),
    );
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("auth:"), "{text}");
    assert!(
        text.contains("Wait or try another network, then call the tool again once"),
        "{text}"
    );
    assert!(
        text.contains(
            "ask the user to run `rhd auth login --browser --overwrite --profile household`"
        ),
        "{text}"
    );
    assert!(text.contains("never sign in"), "{text}");
    assert!(!text.contains("in a terminal, then call"), "{text}");
}

/// An HTML page with a 200 may be a session logged out elsewhere, which no number of
/// calls will clear, so the fix names both remedies and sets a limit on the retry.
#[test]
fn an_html_200_names_both_remedies_and_limits_the_retry() {
    let t = RobinhoodTools::new(Fixtures::new(), Ok("household".into()));
    const PAGE: &str = "<!DOCTYPE html><html><title>Log in</title></html>";
    *t.source().fail.lock().unwrap() = Some(
        crate::client::classify(200, "https://example.test/dummy", None, PAGE)
            .unwrap_err()
            .into_cli_error(),
    );
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("auth:"), "{text}");
    assert!(
        text.contains("Ask the user whether this session was logged out or revoked elsewhere"),
        "{text}"
    );
    assert!(
        text.contains(
            "ask them to run `rhd auth login --browser --overwrite --profile household` in a \
             terminal now"
        ),
        "{text}"
    );
    assert!(
        text.contains("a bot check may clear after waiting: wait, then call the tool again once"),
        "{text}"
    );
    assert!(text.contains("do not keep calling it"), "{text}");
    assert!(text.contains("never sign in"), "{text}");
    assert!(!text.contains("in a terminal, then call"), "{text}");
    assert!(!text.contains("Wait or try another network"), "{text}");
}

/// An outage at the token endpoint asks the agent for no sign-in.
#[test]
fn a_renewal_outage_asks_for_no_sign_in() {
    let t = RobinhoodTools::new(Fixtures::new(), Ok("household".into()));
    const PAGE: &str = "<!DOCTYPE html><html><title>Service Unavailable</title></html>";
    *t.source().fail.lock().unwrap() = Some(crate::client::renewal_answer(503, PAGE).unwrap_err());
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(!text.contains("auth login"), "{text}");
}

#[test]
fn the_instructions_name_the_browser_login_and_the_scope() {
    let text = pk_cli_mcp::instructions(&tools());
    assert!(text.contains("`rhd auth login --browser`"), "{text}");
    assert!(text.contains("read-only"), "{text}");
    assert!(
        text.contains("options and crypto are not included"),
        "{text}"
    );
}
