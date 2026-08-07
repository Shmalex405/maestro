//! Markdown → HTML → PDF pipeline for report downloads.
//!
//! The Python backend uses `markdown` + `WeasyPrint` (see
//! `backend/app/routers/reports.py:172-206`). We do the same semantic
//! pipeline with Rust tools:
//!
//!   - `pulldown-cmark` renders GFM markdown to HTML (tables + fenced code
//!     extensions).
//!   - `headless_chrome` drives a bundled Chromium to print the HTML at
//!     A4 with the same CSS the Python backend emits, so the PDF output is
//!     faithful to the existing reports.
//!
//! Chromium is started lazily on the first PDF request so cold-start stays
//! fast for the non-PDF endpoints. The browser handle is kept alive for the
//! process lifetime.

use std::sync::OnceLock;

use headless_chrome::{types::PrintToPdfOptions, Browser, LaunchOptions};
use pulldown_cmark::{html, Options, Parser};
use tokio::sync::Mutex;

use crate::error::{AppError, AppResult};

/// Shared report stylesheet. Single source of truth for both the MCP
/// server's `docker/scripts/md-to-pdf.js` (Playwright path, used by the
/// desktop's local report export) and this backend renderer (headless
/// Chromium path, used by `GET /reports/{id}/download?format=pdf`).
///
/// `include_str!` bakes it into the Rust binary at compile time. The JS
/// side reads the same file with `fs.readFileSync` at startup. Whoever
/// edits the CSS updates both PDF pipelines atomically.
const REPORT_CSS: &str = include_str!("../../docker/scripts/report-style.css");

pub fn render_html(title: &str, markdown_text: &str) -> String {
    let body = md_to_styled_html(markdown_text);
    wrap_html(title, &body, /* for_pdf */ false)
}

fn pdf_html(title: &str, markdown_text: &str) -> String {
    let body = md_to_styled_html(markdown_text);
    wrap_html(title, &body, /* for_pdf */ true)
}

fn md_to_styled_html(markdown_text: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(markdown_text, opts);
    let mut raw = String::new();
    html::push_html(&mut raw, parser);
    post_process(&raw)
}

fn wrap_html(title: &str, body: &str, for_pdf: bool) -> String {
    let page_rule = if for_pdf {
        "@page { size: A4; margin: 2cm; }"
    } else {
        ""
    };
    format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
{page_rule}
{css}
    </style>
</head>
<body>
{body}
</body>
</html>
"##,
        title = html_escape(title),
        page_rule = page_rule,
        css = REPORT_CSS,
        body = body,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ──────────────────────────────────────────────────────────────────────────
// HTML post-processing — mirrors the keyword wrapping that gives the PDFs
// their visual character (severity pill badges, colored finding headings,
// section accents).
// ──────────────────────────────────────────────────────────────────────────

use once_cell::sync::Lazy;
use regex::{Captures, Regex};

/// Maps the bold-keyword tokens the report writers emit to the CSS
/// `data-severity` value the stylesheet is keyed on.
fn severity_class(keyword_upper: &str) -> Option<&'static str> {
    match keyword_upper {
        "CRITICAL" => Some("critical"),
        "HIGH" => Some("high"),
        "MEDIUM" => Some("medium"),
        "LOW" => Some("low"),
        "INFORMATIONAL" | "INFO" => Some("info"),
        _ => None,
    }
}

fn status_class(keyword_upper: &str) -> Option<&'static str> {
    match keyword_upper {
        "TRUE" => Some("exploitable-true"),
        "FALSE" => Some("exploitable-false"),
        "POTENTIALLY" => Some("exploitable-potentially"),
        "PASS" => Some("pass"),
        "FAIL" => Some("fail"),
        "BLOCKED" => Some("blocked"),
        "N/A" | "NA" => Some("na"),
        "EXPOSED" => Some("exposed"),
        "CONFIRMED" => Some("confirmed"),
        "NOT EXPOSABLE" => Some("not-exposable"),
        "NOT_EXPLOITABLE" | "NOT EXPLOITABLE" => Some("not-exploitable"),
        "MITIGATED" => Some("mitigated"),
        "INCONCLUSIVE" => Some("inconclusive"),
        "SKIPPED" => Some("skipped"),
        "YES" => Some("yes"),
        "NO" => Some("no"),
        _ => None,
    }
}

fn post_process(html: &str) -> String {
    let html = tag_table_cell_severity(html);
    let html = tag_table_cell_status(&html);
    let html = tag_finding_headings(&html);
    let html = tag_section_headings(&html);
    let html = wrap_inline_severity_badges(&html);
    let html = wrap_cover_page(&html);
    html
}

/// Matches Playwright's `SECTION_CLASS_MAP` from `docker/scripts/md-to-pdf.js`.
/// These classes are what make H2s get their colored accent bars.
fn section_class_for(heading_lower: &str) -> Option<&'static str> {
    const MAP: &[(&str, &str)] = &[
        ("executive summary", "section-executive"),
        ("assessment walkthrough", "section-walkthrough"),
        ("targets assessed", "section-targets"),
        ("findings summary", "section-findings"),
        ("critical & high findings", "section-critical-high"),
        ("critical and high findings", "section-critical-high"),
        ("medium findings", "section-medium"),
        ("low & informational findings", "section-low-info"),
        ("low and informational findings", "section-low-info"),
        ("exploitation validation", "section-exploitation"),
        ("exploitation summary matrix", "section-exploitation"),
        ("qa review summary", "section-qa"),
        ("recommendations", "section-recommendations"),
        ("recommendations by priority", "section-recommendations"),
        ("testing methodology", "section-methodology"),
        ("detailed methodology", "section-methodology"),
        ("compliance mapping", "section-compliance"),
        ("coverage checklist", "section-coverage"),
        ("conclusion", "section-conclusion"),
        ("table of contents", "section-toc"),
        ("appendix", "section-appendix"),
        ("dast findings", "section-dast"),
        ("sast findings", "section-sast"),
        ("cross-validated findings", "section-cross-validated"),
        ("code remediation guide", "section-remediation"),
    ];
    for (pattern, cls) in MAP {
        if heading_lower.contains(pattern) {
            return Some(cls);
        }
    }
    None
}

/// `<h2>Executive Summary</h2>` → add `page-break-section` + a
/// section-specific class so the colored accent bars kick in.
static H2_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<h2>([^<]*)</h2>").unwrap());

fn tag_section_headings(html: &str) -> String {
    H2_RE
        .replace_all(html, |caps: &Captures| {
            let inner = &caps[1];
            let lower = inner.to_lowercase();
            let mut classes = vec!["page-break-section"];
            if let Some(sec) = section_class_for(&lower) {
                classes.push(sec);
            }
            format!("<h2 class=\"{}\">{}</h2>", classes.join(" "), inner)
        })
        .into_owned()
}

/// Wrap everything before the first `<h2` in a `.cover-page` div so the
/// centered cover treatment applies. Mirrors `wrapCoverPage` in the JS.
fn wrap_cover_page(html: &str) -> String {
    if let Some(idx) = html.find("<h2") {
        let (before, after) = html.split_at(idx);
        if before.trim().is_empty() {
            return html.to_string();
        }
        format!("<div class=\"cover-page\">{before}</div>\n{after}")
    } else {
        html.to_string()
    }
}

/// `<td>**CRITICAL**</td>` or `<td>CRITICAL</td>` → add `data-severity=…`.
static TD_CELL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<(td|th)>([^<]+)</(td|th)>").unwrap());

fn tag_table_cell_severity(html: &str) -> String {
    TD_CELL_RE
        .replace_all(html, |caps: &Captures| {
            let open_tag = &caps[1];
            let inner = caps[2].trim();
            // Strip leading/trailing `**…**` so bolded keywords match too.
            let stripped = inner
                .trim_start_matches("**")
                .trim_end_matches("**")
                .trim();
            match severity_class(&stripped.to_uppercase()) {
                Some(cls) => format!(
                    "<{tag} data-severity=\"{cls}\">{inner}</{tag}>",
                    tag = open_tag,
                    cls = cls,
                    inner = &caps[2],
                ),
                None => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn tag_table_cell_status(html: &str) -> String {
    TD_CELL_RE
        .replace_all(html, |caps: &Captures| {
            let open_tag = &caps[1];
            let full = caps[0].to_string();
            // Skip if we already tagged with data-severity (avoid collision).
            if full.contains("data-severity") {
                return full;
            }
            let inner = caps[2].trim();
            let stripped = inner
                .trim_start_matches("**")
                .trim_end_matches("**")
                .trim();
            match status_class(&stripped.to_uppercase()) {
                Some(cls) => format!(
                    "<{tag} data-status=\"{cls}\">{inner}</{tag}>",
                    tag = open_tag,
                    cls = cls,
                    inner = &caps[2],
                ),
                None => full,
            }
        })
        .into_owned()
}

/// `### FINDING N: [CRITICAL] Title` → `<h3 class="finding-heading finding-heading-critical">…</h3>`.
static H3_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<h3>([^<]*)</h3>").unwrap());
static FINDING_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*finding\s+\d+").unwrap());

fn tag_finding_headings(html: &str) -> String {
    H3_RE
        .replace_all(html, |caps: &Captures| {
            let inner = &caps[1];
            if !FINDING_RE.is_match(inner) {
                return caps[0].to_string();
            }
            let upper = inner.to_uppercase();
            let mut classes = vec!["finding-heading"];
            let sev_cls = if upper.contains("CRITICAL") {
                Some("finding-heading-critical")
            } else if upper.contains("HIGH") {
                Some("finding-heading-high")
            } else if upper.contains("MEDIUM") {
                Some("finding-heading-medium")
            } else if upper.contains("LOW") {
                Some("finding-heading-low")
            } else if upper.contains("INFO") {
                Some("finding-heading-info")
            } else {
                None
            };
            if let Some(c) = sev_cls {
                classes.push(c);
            }
            format!("<h3 class=\"{}\">{}</h3>", classes.join(" "), inner)
        })
        .into_owned()
}

/// `<strong>CRITICAL</strong>` inline → colored pill badge.
static STRONG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<strong>([^<]+)</strong>").unwrap());

fn wrap_inline_severity_badges(html: &str) -> String {
    STRONG_RE
        .replace_all(html, |caps: &Captures| {
            let inner = &caps[1];
            let upper = inner.trim().to_uppercase();
            // Both classes matter: `severity-badge` gives the pill shape
            // (padding + border-radius + font-weight), and the color-specific
            // class picks the background + text color.
            if let Some(cls) = severity_class(&upper) {
                return format!(
                    r#"<span class="severity-badge severity-{cls}">{inner}</span>"#
                );
            }
            if let Some(cls) = status_class(&upper) {
                return format!(
                    r#"<span class="status-badge status-{cls}">{inner}</span>"#
                );
            }
            caps[0].to_string()
        })
        .into_owned()
}

static BROWSER: OnceLock<Mutex<Option<Browser>>> = OnceLock::new();

fn browser_slot() -> &'static Mutex<Option<Browser>> {
    BROWSER.get_or_init(|| Mutex::new(None))
}

async fn launch_browser() -> AppResult<Browser> {
    // Launch on a blocking thread because headless_chrome is sync.
    //
    // `sandbox(false)` is required when running as a non-root user inside a
    // Docker container — Chromium's sandbox needs CAP_SYS_ADMIN or the
    // setuid sandbox helper, neither of which our runtime image carries.
    // Without this flag Chromium dies silently during startup and
    // headless_chrome times out after 30 s.
    tokio::task::spawn_blocking(|| {
        let opts = LaunchOptions::default_builder()
            .headless(true)
            .sandbox(false)
            .args(vec![
                std::ffi::OsStr::new("--no-sandbox"),
                std::ffi::OsStr::new("--disable-dev-shm-usage"),
                std::ffi::OsStr::new("--disable-gpu"),
            ])
            .build()
            .map_err(|e| AppError::Internal(format!("LaunchOptions: {e}")))?;
        Browser::new(opts)
            .map_err(|e| AppError::Internal(format!("Chromium launch failed: {e}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

/// Render `markdown_text` to PDF bytes. Title is used for the document
/// title and the <title> tag.
///
/// We keep a persistent Chromium handle for speed, but Chrome's DevTools
/// websocket drops after long idle periods. If a render attempt fails with
/// a connection-closed error we discard the stale handle, spin up a fresh
/// Chromium, and retry once.
pub async fn render_pdf(title: String, markdown_text: String) -> AppResult<Vec<u8>> {
    let html = pdf_html(&title, &markdown_text);

    match try_render(&html).await {
        Ok(bytes) => Ok(bytes),
        Err(first_err) => {
            let stale = is_stale_browser_error(&first_err);
            if !stale {
                return Err(first_err);
            }
            tracing::warn!(error = %first_err, "PDF render hit stale Chromium; relaunching and retrying");
            {
                let mut slot = browser_slot().lock().await;
                *slot = None;
            }
            try_render(&html).await
        }
    }
}

async fn try_render(html: &str) -> AppResult<Vec<u8>> {
    let browser = {
        let mut slot = browser_slot().lock().await;
        if slot.is_none() {
            *slot = Some(launch_browser().await?);
        }
        slot.as_ref().unwrap().clone()
    };

    let url = format!(
        "data:text/html;charset=utf-8;base64,{}",
        base64_encode(html.as_bytes())
    );
    tokio::task::spawn_blocking(move || {
        let tab = browser
            .new_tab()
            .map_err(|e| AppError::Internal(format!("Chromium new_tab: {e}")))?;
        tab.navigate_to(&url)
            .and_then(|t| t.wait_until_navigated())
            .map_err(|e| AppError::Internal(format!("Chromium navigate: {e}")))?;
        // Templates mirror `docker/scripts/md-to-pdf.js`'s
        // `headerTemplate` / `footerTemplate` — the running banner and page
        // counter Chromium renders natively when `displayHeaderFooter` is on.
        let header = r#"<div style="font-size:8px;width:100%;text-align:center;color:#999;padding-top:8px;border-top:2px solid #1a1a2e;">Security Assessment Report &mdash; Confidential</div>"#;
        let footer = r#"<div style="font-size:8px;width:100%;text-align:center;color:#999;padding-bottom:8px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>"#;
        let opts = PrintToPdfOptions {
            print_background: Some(true),
            prefer_css_page_size: Some(false),
            // A4 in inches: 8.27 × 11.69
            paper_width: Some(8.27),
            paper_height: Some(11.69),
            margin_top: Some(0.7),
            margin_right: Some(0.55),
            margin_bottom: Some(0.8),
            margin_left: Some(0.55),
            display_header_footer: Some(true),
            header_template: Some(header.to_string()),
            footer_template: Some(footer.to_string()),
            ..Default::default()
        };
        tab.print_to_pdf(Some(opts))
            .map_err(|e| AppError::Internal(format!("Chromium print_to_pdf: {e}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

fn is_stale_browser_error(e: &AppError) -> bool {
    let msg = e.to_string();
    msg.contains("underlying connection is closed")
        || msg.contains("channel closed")
        || msg.contains("no such target")
        || msg.contains("Got a timeout while listening")
}

fn base64_encode(bytes: &[u8]) -> String {
    // Minimal base64 to avoid pulling another dep; tune if profiled hot.
    const CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8 | bytes[i + 2] as u32;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}
