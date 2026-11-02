//! `rhd documents …` — tax forms and statements (`documents/v1` profile).
//!
//! This is the tax-season path: the consolidated 1099 lives here, and it is
//! the **source of truth** for realized gains (see `transactions.rs` for why
//! the order history is not).
//!
//! # LIVE-VERIFIED 2026-08-12
//!
//! The endpoint, the `?type=1099` filter, and a real consolidated-1099 PDF
//! download (`%PDF` magic confirmed) were all verified against a live
//! account. The capture also surfaced a field the community docs missed:
//! every document carries a **`filetype`** (`pdf`, `csv`, or `html`) — each
//! tax season's 1099 ships as a PDF *and* a CSV export, and older account
//! statements can be HTML. Downloads are verified against that declared
//! filetype (`pk_cli_documents::verify`); a body
//! that doesn't match is an error, never a written file. Every
//! provider-controlled string that reaches a filename (`type`, `filetype`,
//! `date`, `id`) goes through the shared `fs_safe`. See docs/api.md §3.5.

use std::path::{Path, PathBuf};

use pk_cli_core::{CliError, Paged, RangeArgs};
use pk_cli_documents::{fs_safe, Document, DownloadBatch, SavedDocument};
use serde_json::Value;

use crate::commands::{str_at, Ctx};

pub const PATH: &str = "/documents/";

/// Accepted `?type=` filter values, from community sources.
///
/// `1099` is the bare string — **not** `tax_1099` or `form_1099`, which are
/// the natural guesses and return HTTP 400.
pub const TYPE_1099: &str = "1099";

/// Map a provider document onto the profile DTO.
pub(crate) fn to_document(v: &Value) -> Option<Document> {
    let id = str_at(v, "id")?;
    let kind = str_at(v, "type");
    let date = str_at(v, "date");
    let filetype = str_at(v, "filetype");

    let mut doc = Document::new(
        id.clone(),
        display_name(kind.as_deref(), date.as_deref(), filetype.as_deref()),
    );
    doc.date = date.clone();
    doc.category = kind.clone();
    doc.file = Some(file_name(
        &id,
        kind.as_deref(),
        date.as_deref(),
        filetype.as_deref(),
    ));
    Some(doc)
}

/// A human title, since the provider ships none — only a type and a date.
///
/// Non-PDF variants are labelled, because a season's consolidated 1099 comes
/// as *both* a PDF and a CSV export with the same type and near-identical
/// dates — without the suffix the two rows are indistinguishable.
fn display_name(kind: Option<&str>, date: Option<&str>, filetype: Option<&str>) -> String {
    let label = match kind {
        Some("1099") => "Consolidated 1099".to_string(),
        Some("account_statement") => "Account statement".to_string(),
        Some("trade_confirm") => "Trade confirmation".to_string(),
        // Unknown types keep the provider's own word rather than being
        // flattened into "Document" — a new form type should be visible.
        Some(other) => other.replace('_', " "),
        None => "Document".to_string(),
    };
    let label = match date {
        Some(d) => format!("{label} {d}"),
        None => label,
    };
    match filetype {
        Some(ft) if !ft.eq_ignore_ascii_case("pdf") => {
            format!("{label} ({})", ft.to_uppercase())
        }
        _ => label,
    }
}

/// A filesystem-safe name for the saved file, extension from the declared
/// `filetype` (PDF assumed when the provider omits it).
fn file_name(id: &str, kind: Option<&str>, date: Option<&str>, filetype: Option<&str>) -> String {
    let kind = fs_safe(kind.unwrap_or("document"));
    let ext = fs_safe(filetype.unwrap_or("pdf"));
    match date {
        // A real ISO date passes through fs_safe unchanged; anything else
        // was never a date.
        Some(d) => format!("{}-{kind}.{ext}", fs_safe(d)),
        // Fall back to the id so two undated documents can't collide.
        None => format!("{kind}-{}.{ext}", fs_safe(id)),
    }
}

/// Validate a `--type` filter before it costs a request.
///
/// `tax_1099` and `form_1099` are the natural guesses and both return HTTP
/// 400, so they are caught here with the right answer rather than surfacing
/// as an opaque upstream error.
pub fn validate_type(kind: &str) -> Result<(), CliError> {
    match kind {
        "tax_1099" | "form_1099" | "1099_tax" => Err(CliError::Usage(format!(
            "`{kind}` is not a valid document type — the consolidated 1099 filter is the bare \
             string `{TYPE_1099}`"
        ))),
        "" => Err(CliError::Usage("--type needs a value".into())),
        _ => Ok(()),
    }
}

pub fn list(ctx: &Ctx, range: &RangeArgs, kind: Option<&str>) -> Result<(), CliError> {
    let docs = fetch(ctx, range, kind)?;
    Paged::new("document", docs).emit(ctx.common.json);
    Ok(())
}

fn fetch(ctx: &Ctx, range: &RangeArgs, kind: Option<&str>) -> Result<Vec<Document>, CliError> {
    let token = ctx.access_token()?;
    let query: Vec<(&'static str, String)> = match kind {
        Some(k) => vec![("type", k.to_string())],
        None => Vec::new(),
    };
    let rows = ctx.rh.paginate(&token, PATH, &query, None)?;

    let mut docs: Vec<Document> = rows.iter().filter_map(to_document).collect();

    // Newest first, per the profile contract. Undated documents sort last
    // rather than being dropped.
    docs.sort_by(|a, b| b.date.cmp(&a.date));

    docs.retain(|d| date_in_range(d.date.as_deref(), range));

    if let Some(n) = range.limit {
        docs.truncate(n as usize);
    }
    Ok(docs)
}

/// The date-range rule `list` and `download --all` share.
pub(crate) fn date_in_range(date: Option<&str>, range: &RangeArgs) -> bool {
    match date {
        Some(date) => {
            crate::commands::date_within(date, range.since.as_deref(), range.until.as_deref())
        }
        // With no date there is nothing to compare, so an explicit range
        // excludes it rather than silently including it. (Deliberately the
        // opposite of the transaction-like lists — see `date_within`.)
        None => range.since.is_none() && range.until.is_none(),
    }
}

pub fn download(
    ctx: &Ctx,
    id: Option<&str>,
    output: Option<&Path>,
    all: bool,
    range: &RangeArgs,
    kind: Option<&str>,
) -> Result<(), CliError> {
    let token = ctx.access_token()?;
    // `--type` is pushed server-side (same as `list`); dates apply below.
    let query: Vec<(&'static str, String)> = match kind {
        Some(k) => vec![("type", k.to_string())],
        None => Vec::new(),
    };
    let rows = ctx.rh.paginate(&token, PATH, &query, None)?;

    if all {
        let dir = output.unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)
            .map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))?;

        // Pair each row with its DTO so the filters see dates while the
        // download still gets the row's download_url and filetype. Newest
        // first, so `--limit` means "the N most recent", matching `list`.
        let mut pairs: Vec<(&Value, Document)> = rows
            .iter()
            .filter_map(|r| to_document(r).map(|d| (r, d)))
            .filter(|(_, d)| date_in_range(d.date.as_deref(), range))
            .collect();
        pairs.sort_by(|a, b| b.1.date.cmp(&a.1.date));
        if let Some(n) = range.limit {
            pairs.truncate(n as usize);
        }

        let mut saved = Vec::new();
        for (row, doc) in &pairs {
            let bytes = fetch_one(ctx, &token, row)?;
            let path = dir.join(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id)));
            write_file(&path, &bytes)?;
            saved.push(SavedDocument::from_document(
                doc,
                path.display().to_string(),
                bytes.len() as u64,
            ));
        }
        let batch = DownloadBatch::new(dir.display().to_string(), saved);
        crate::commands::emit_self_tagged(&batch, ctx.common.json);
        return Ok(());
    }

    let wanted = id.expect("validated in main: an id or --all is required");
    let row = rows
        .iter()
        .find(|r| str_at(r, "id").as_deref() == Some(wanted))
        .ok_or_else(|| {
            CliError::NotFound(format!(
                "no document `{wanted}` — run `rhd documents list` to see the ids"
            ))
        })?;
    let doc = to_document(row)
        .ok_or_else(|| CliError::Upstream("the document listing is missing its id field".into()))?;

    let bytes = fetch_one(ctx, &token, row)?;

    // `-` means stdout, which is the one case that writes no file.
    if output.map(|p| p == Path::new("-")).unwrap_or(false) {
        use std::io::Write;
        return std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::Other(format!("writing to stdout: {e}")));
    }

    let path: PathBuf = match output {
        Some(p) if p.is_dir() => p.join(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id))),
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id))),
    };
    write_file(&path, &bytes)?;

    let saved = SavedDocument::from_document(&doc, path.display().to_string(), bytes.len() as u64);
    crate::commands::emit_self_tagged(&saved, ctx.common.json);
    Ok(())
}

/// Fetch one document's bytes, verified against the row's declared
/// `filetype` by `pk_cli_documents::verify_download`.
fn fetch_one(ctx: &Ctx, token: &str, row: &Value) -> Result<Vec<u8>, CliError> {
    let url = str_at(row, "download_url")
        .or_else(|| str_at(row, "url").map(|u| format!("{}download/", ensure_slash(&u))))
        .ok_or_else(|| {
            CliError::Upstream("this document carries no download_url — see docs/api.md §4".into())
        })?;
    ctx.rh
        .download_document(token, &url, str_at(row, "filetype").as_deref())
}

fn ensure_slash(u: &str) -> String {
    if u.ends_with('/') {
        u.to_string()
    } else {
        format!("{u}/")
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, bytes)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_1099() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-000000000020",
            "type": "1099",
            "date": "2027-02-15",
            "filetype": "pdf",
            "download_url": "https://example.invalid/presigned-url-redacted",
            "url": "https://api.robinhood.com/documents/00000000-0000-4000-8000-000000000020/",
            "created_at": "2027-02-15T00:00:00.000000Z",
            "updated_at": "2027-02-15T00:00:00.000000Z"
        })
    }

    #[test]
    fn a_1099_maps_onto_the_profile_dto() {
        let d = to_document(&sample_1099()).unwrap();
        assert_eq!(d.category.as_deref(), Some("1099"));
        assert_eq!(d.date.as_deref(), Some("2027-02-15"));
        assert_eq!(d.name, "Consolidated 1099 2027-02-15");
        assert_eq!(d.file.as_deref(), Some("2027-02-15-1099.pdf"));
    }

    /// LIVE-VERIFIED 2026-08-12: a season's consolidated 1099 also ships as a
    /// CSV export with the same `type`. The variant must stay visible in the
    /// name and drive the saved file's extension.
    #[test]
    fn a_csv_1099_is_labelled_and_saved_as_csv() {
        let mut row = sample_1099();
        row["filetype"] = json!("csv");
        let d = to_document(&row).unwrap();
        assert_eq!(d.name, "Consolidated 1099 2027-02-15 (CSV)");
        assert_eq!(d.file.as_deref(), Some("2027-02-15-1099.csv"));
    }

    /// A missing `filetype` keeps the historical PDF assumption rather than
    /// inventing an extension.
    #[test]
    fn a_row_without_a_filetype_is_assumed_pdf() {
        let mut row = sample_1099();
        row.as_object_mut().unwrap().remove("filetype");
        let d = to_document(&row).unwrap();
        assert_eq!(d.name, "Consolidated 1099 2027-02-15");
        assert_eq!(d.file.as_deref(), Some("2027-02-15-1099.pdf"));
    }

    /// `type`, `filetype`, and (in the undated fallback) `id` are
    /// provider-controlled and become a filename; nothing in them may
    /// traverse or hide the extension.
    #[test]
    fn provider_strings_cannot_shape_the_path() {
        let name = file_name(
            "id-x",
            Some("../../etc"),
            Some("2027-01-01"),
            Some("pdf/../x"),
        );
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");

        // The undated fallback interpolates the id (review finding, PR #1).
        let name = file_name("../../etc/passwd", Some("1099"), None, Some("pdf"));
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");

        // The dated path interpolates the date (review finding, PR #1).
        let name = file_name("id-x", Some("1099"), Some("../../etc/passwd"), Some("pdf"));
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");
    }

    /// The filter value is `1099`; `tax_1099` is the natural guess and is
    /// rejected by the provider with a 400, so the CLI catches it locally and
    /// says what the right value is.
    #[test]
    fn the_1099_filter_value_is_the_bare_string() {
        assert_eq!(TYPE_1099, "1099");
        assert!(validate_type("1099").is_ok());
        assert!(validate_type("account_statement").is_ok());

        for wrong in ["tax_1099", "form_1099", "1099_tax"] {
            let err = validate_type(wrong).unwrap_err();
            assert_eq!(err.exit_code(), 2);
            assert!(err.to_string().contains("`1099`"), "{err}");
        }
        assert!(validate_type("").is_err());
    }

    #[test]
    fn unknown_types_keep_the_providers_own_word() {
        let name = display_name(Some("1099r"), Some("2027-02-15"), None);
        assert!(name.contains("1099r"), "{name}");
        // A brand new form type must stay visible, not collapse to "Document".
        let name = display_name(Some("some_new_form"), None, None);
        assert_eq!(name, "some new form");
    }

    #[test]
    fn undated_documents_get_collision_free_filenames() {
        let a = file_name("id-a", Some("1099"), None, None);
        let b = file_name("id-b", Some("1099"), None, None);
        assert_ne!(a, b);
        assert!(a.ends_with(".pdf"));
    }

    #[test]
    fn statements_and_confirms_are_named_readably() {
        assert_eq!(
            display_name(Some("account_statement"), Some("2026-03-31"), None),
            "Account statement 2026-03-31"
        );
        assert_eq!(
            display_name(Some("trade_confirm"), None, None),
            "Trade confirmation"
        );
        // LIVE-VERIFIED: older account statements come as HTML, and the
        // variant must stay visible next to the PDF one.
        assert_eq!(
            display_name(Some("account_statement"), Some("2026-03-31"), Some("html")),
            "Account statement 2026-03-31 (HTML)"
        );
    }

    #[test]
    fn a_row_without_an_id_is_dropped() {
        assert!(to_document(&json!({"type": "1099"})).is_none());
    }

    #[test]
    fn the_download_url_falls_back_to_the_canonical_path() {
        assert_eq!(
            ensure_slash("https://api.robinhood.com/documents/x"),
            "https://api.robinhood.com/documents/x/"
        );
        assert_eq!(
            ensure_slash("https://api.robinhood.com/documents/x/"),
            "https://api.robinhood.com/documents/x/"
        );
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new("document", vec![to_document(&sample_1099()).unwrap()]);
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "document-list/v1");
        assert_eq!(v["items"][0]["category"], "1099");
    }

    #[test]
    fn a_saved_document_reports_where_it_landed() {
        let doc = to_document(&sample_1099()).unwrap();
        let saved = SavedDocument::from_document(&doc, "/tmp/x.pdf", 2048);
        let v = serde_json::to_value(&saved).unwrap();
        assert_eq!(v["schema"], "document-download/v1");
        assert_eq!(v["bytes"], 2048);
    }
}
