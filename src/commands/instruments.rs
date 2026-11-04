//! Equity instruments by id — the batched `/instruments/?ids=` read
//! (docs/api.md §3.3) every equity command names its rows' symbols with,
//! and the single `/instruments/<id>/` read for an id the batch leaves out.
//! Positions, orders and dividends all carry only an instrument URL.

use pk_cli_core::CliError;
use serde_json::Value;

use crate::commands::{instrument_id, str_at, Ctx};

pub const INSTRUMENTS_PATH: &str = "/instruments/";

/// How many instrument ids to resolve per request.
const SYMBOL_BATCH: usize = 25;

/// The most instruments one invocation reads one at a time after the batch
/// left them out: a bound on the fallback's requests, never a retry.
const SYMBOL_FALLBACK_CAP: usize = 25;

/// Map instrument URL → ticker symbol for a set of rows.
///
/// Positions and orders both reference instruments by URL and carry no symbol
/// of their own. Resolving them one at a time would cost one request per row
/// against a rate-limited API, so this batches via `/instruments/?ids=a,b,c`.
/// An id the batch leaves out (docs/api.md §3.3) is read once on its own
/// from `/instruments/<id>/`, at most [`SYMBOL_FALLBACK_CAP`] of them.
///
/// An instrument the API does not answer for (left out of the batch past the
/// cap, a 404, a record naming another id) is left unresolved, not an error:
/// the caller omits the symbol rather than inventing one, because a wrong
/// ticker on a tax row is worse than a missing one. A failed read (auth,
/// upstream) is an error, as a failed batch is.
pub fn resolve_symbols(
    ctx: &Ctx,
    token: &str,
    rows: &[&Value],
) -> Result<std::collections::HashMap<String, String>, CliError> {
    resolve_symbols_checked(ctx, token, rows, &|| Ok(()))
}

/// [`resolve_symbols`], asking `before_read` before each request, so a tool can stop a lookup
/// nobody is waiting for.
pub fn resolve_symbols_checked(
    ctx: &Ctx,
    token: &str,
    rows: &[&Value],
    before_read: &dyn Fn() -> Result<(), CliError>,
) -> Result<std::collections::HashMap<String, String>, CliError> {
    let quiet = ctx.common.quiet;
    resolve_symbols_with(
        rows,
        |chunk| {
            ctx.rh.paginate_checked(
                token,
                INSTRUMENTS_PATH,
                &[("ids", chunk.join(","))],
                before_read,
            )
        },
        |id| {
            before_read()?;
            if !quiet {
                eprintln!("resolving instrument {id} on its own: the batched lookup left it out");
            }
            let path = format!("{INSTRUMENTS_PATH}{id}/");
            absent_if_not_found(ctx.rh.get(token, &ctx.rh.url(&path), &[]))
        },
    )
}

/// [`resolve_symbols`] over its two reads: `batch` answers a chunk of ids
/// (`/instruments/?ids=`), `one` a single id (`/instruments/<id>/`; `None`
/// when the API has no such instrument). The single read is built from the
/// id, never from the provider's URL, so it cannot leave the API origin.
pub(crate) fn resolve_symbols_with(
    rows: &[&Value],
    mut batch: impl FnMut(&[String]) -> Result<Vec<Value>, CliError>,
    mut one: impl FnMut(&str) -> Result<Option<Value>, CliError>,
) -> Result<std::collections::HashMap<String, String>, CliError> {
    use std::collections::{BTreeSet, HashMap};

    let urls: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| str_at(r, "instrument"))
        .collect();
    let ids: Vec<String> = urls
        .iter()
        .filter_map(|u| instrument_id(u))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut by_id: HashMap<String, String> = HashMap::new();
    for chunk in ids.chunks(SYMBOL_BATCH) {
        by_id.extend(batch(chunk)?.iter().filter_map(id_and_symbol));
    }
    let missing: Vec<&String> = ids.iter().filter(|id| !by_id.contains_key(*id)).collect();
    for id in missing.into_iter().take(SYMBOL_FALLBACK_CAP) {
        // The record must name the id asked for, or it describes some other
        // instrument.
        if let Some((got, sym)) = one(id)?.as_ref().and_then(id_and_symbol) {
            if &got == id {
                by_id.insert(got, sym);
            }
        }
    }

    Ok(urls
        .into_iter()
        .filter_map(|u| {
            let sym = by_id.get(&instrument_id(&u)?)?.clone();
            Some((u, sym))
        })
        .collect())
}

/// An instrument record's `(id, symbol)`; `None` for a `null` entry or a
/// record without both.
fn id_and_symbol(inst: &Value) -> Option<(String, String)> {
    Some((str_at(inst, "id")?, str_at(inst, "symbol")?))
}

/// A single instrument read's answer: a 404 is an instrument the API no
/// longer knows (`None`); any other failure stays an error.
fn absent_if_not_found(read: Result<Value, CliError>) -> Result<Option<Value>, CliError> {
    match read {
        Ok(v) => Ok(Some(v)),
        Err(CliError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use serde_json::json;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn order(id: &str) -> Value {
        json!({ "instrument": format!("https://api.robinhood.com/instruments/{id}/") })
    }

    fn url(id: &str) -> String {
        order(id)["instrument"].as_str().unwrap().to_string()
    }

    const ACTIVE: &str = "00000000-0000-4000-8000-000000000001";
    const LEFT_OUT: &str = "00000000-0000-4000-8000-000000000003";

    /// The batch as `instruments.json` answers it: only the asked ids it
    /// knows, which leaves the inactive instrument out.
    fn batch(asked: &[String]) -> Result<Vec<Value>, CliError> {
        let all = fixture("instruments.json")["results"]
            .as_array()
            .unwrap()
            .clone();
        Ok(all
            .into_iter()
            .filter(|i| asked.iter().any(|a| Some(a.as_str()) == i["id"].as_str()))
            .collect())
    }

    /// An instrument the batch leaves out is read once on its own, and only
    /// that one: the batch's answers cost no second request.
    #[test]
    fn an_instrument_the_batch_leaves_out_is_read_on_its_own() {
        let rows = [order(ACTIVE), order(LEFT_OUT), order(LEFT_OUT)];
        let refs: Vec<&Value> = rows.iter().collect();
        let asked = RefCell::new(Vec::new());
        let symbols = resolve_symbols_with(&refs, batch, |id| {
            asked.borrow_mut().push(id.to_string());
            Ok(Some(fixture("instrument.json")))
        })
        .unwrap();
        assert_eq!(*asked.borrow(), [LEFT_OUT], "one read, for the left-out id");
        assert_eq!(symbols[&url(ACTIVE)], "SAMPL");
        assert_eq!(symbols[&url(LEFT_OUT)], "TESTF");
    }

    /// A 404, or a record naming some other instrument, leaves the symbol
    /// out rather than inventing one.
    #[test]
    fn an_unknown_or_mismatched_instrument_stays_unresolved() {
        let rows = [order(LEFT_OUT)];
        let refs: Vec<&Value> = rows.iter().collect();
        let gone = resolve_symbols_with(&refs, batch, |_| Ok(None)).unwrap();
        assert!(gone.is_empty());
        let other = resolve_symbols_with(&refs, batch, |_| {
            Ok(Some(fixture("instruments.json")["results"][0].clone()))
        })
        .unwrap();
        assert!(other.is_empty(), "{other:?}");
    }

    /// A failed single read fails the listing as a failed batch does: an
    /// auth or upstream error is not an unknown instrument.
    #[test]
    fn a_failed_single_read_is_an_error() {
        let rows = [order(LEFT_OUT)];
        let refs: Vec<&Value> = rows.iter().collect();
        let err =
            resolve_symbols_with(&refs, batch, |_| Err(CliError::Upstream("HTTP 503".into())))
                .unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    /// The single read's 404 is an unknown instrument; an auth or upstream
    /// failure is not, and fails the listing.
    #[test]
    fn only_a_404_reads_as_an_unknown_instrument() {
        let found = absent_if_not_found(Ok(json!({ "id": LEFT_OUT }))).unwrap();
        assert!(found.is_some());
        let gone = absent_if_not_found(Err(CliError::NotFound("HTTP 404".into()))).unwrap();
        assert!(gone.is_none());
        for err in [
            CliError::Auth("expired".into()),
            CliError::Upstream("HTTP 503".into()),
        ] {
            let code = err.exit_code();
            assert_eq!(absent_if_not_found(Err(err)).unwrap_err().exit_code(), code);
        }
    }

    /// The fallback is bounded: past the cap, a left-out instrument costs no
    /// request and stays unresolved.
    #[test]
    fn the_single_reads_are_capped() {
        let rows: Vec<Value> = (0..SYMBOL_FALLBACK_CAP + 5)
            .map(|n| order(&format!("00000000-0000-4000-8000-{:012x}", 0x100 + n)))
            .collect();
        let refs: Vec<&Value> = rows.iter().collect();
        let mut reads = 0;
        let symbols = resolve_symbols_with(&refs, batch, |_| {
            reads += 1;
            Ok(None)
        })
        .unwrap();
        assert_eq!(reads, SYMBOL_FALLBACK_CAP);
        assert!(symbols.is_empty());
    }
}
