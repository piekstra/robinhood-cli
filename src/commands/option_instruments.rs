//! Option contracts by id — the batched `/options/instruments/?ids=` read
//! (docs/api.md §3.9) every option command describes its contracts with.
//! Option positions and option events both carry only an instrument id; the
//! strike, call/put, expiry, underlying and multiplier live here.

use std::collections::{BTreeSet, HashMap};

use pk_cli_core::CliError;
use serde_json::Value;

use crate::commands::{instrument_id, str_at, Ctx};

pub const INSTRUMENTS_PATH: &str = "/options/instruments/";

/// Contracts per batched request — the same trade as the equity symbol
/// lookup: one request per contract against a rate-limited API is the
/// wrong one.
const BATCH: usize = 25;

/// The option instrument UUID a row refers to: `option_id`, else the id out
/// of its `option` URL.
pub fn option_id_of(row: &Value) -> Option<String> {
    str_at(row, "option_id").or_else(|| str_at(row, "option").as_deref().and_then(instrument_id))
}

/// Batched `?ids=` read keyed by `key` (falling back to the UUID out of an
/// `instrument` URL). A response without a `results` array is a shape
/// change and fails loudly; `null` entries (an unquotable contract) are
/// skipped so the absence surfaces per row. Serves the marketdata batch
/// too, which shares the shape.
pub fn fetch_by_ids(
    ctx: &Ctx,
    token: &str,
    path: &str,
    ids: &BTreeSet<String>,
    key: &str,
) -> Result<HashMap<String, Value>, CliError> {
    let mut out = HashMap::new();
    let ids: Vec<&String> = ids.iter().collect();
    for chunk in ids.chunks(BATCH) {
        let joined = chunk
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let body = ctx.rh.get(token, &ctx.rh.url(path), &[("ids", joined)])?;
        let rows = body
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CliError::Upstream(format!(
                    "{path} answered without a results array — the shape may have changed; \
                 see docs/api.md §3.9"
                ))
            })?;
        out.extend(index_by(rows, key));
    }
    Ok(out)
}

pub(crate) fn index_by(rows: &[Value], key: &str) -> HashMap<String, Value> {
    rows.iter()
        .filter(|r| !r.is_null())
        .filter_map(|r| {
            let id = str_at(r, key)
                .or_else(|| str_at(r, "instrument").as_deref().and_then(instrument_id))?;
            Some((id, r.clone()))
        })
        .collect()
}
