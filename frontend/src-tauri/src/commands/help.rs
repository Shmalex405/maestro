// Reads slash command + agent definitions for the in-app Help page.
//
// `.claude/commands/*.md` and `.claude/agents/*.md` are embedded into the
// Tauri binary at compile time via `include_dir!`. This is the only way the
// Help page works on customer machines: a customer doesn't have the source
// repo on disk, so any `find_project_root` walk-up would fail (which is the
// bug Alex hit on prod — "Could not locate project root (.mcp.json)").
// Embedding the markdown also means CI builds bake exactly what was on
// `main` at release time, so the Help page never drifts from the agent
// files actually shipping in that release.
//
// Slash commands: filename stem becomes the command (`assess.md` → `/assess`).
// Description is the first non-empty, non-frontmatter line.
//
// Agents: YAML frontmatter holds `name` + `description`. We skip
// `_preamble.md` (shared rules across all agents, not an agent itself).
// `user-invocable: false` agents are kept in the list but flagged
// `team_only: true` — they don't show up in claude's `/agents:*`
// autocomplete but the team lead spawns them during /assess so users still
// want to know they exist.

use crate::error::{AppError, Result};
use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};

static COMMANDS_DIR: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/../../.claude/commands");
static AGENTS_DIR: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/../../.claude/agents");
static USER_GUIDE_DIR: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/../../docs/user-guide");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelpCommand {
    /// Filename stem — e.g. "assess" → user types `/assess`.
    pub name: String,
    /// One-line summary (first non-empty line of the file).
    pub description: String,
    /// Path within the embedded resource tree, e.g. ".claude/commands/assess.md".
    /// Useful for the UI to show users where the canonical definition lives.
    pub source_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelpAgent {
    pub name: String,
    pub description: String,
    pub source_path: String,
    /// True when the agent has `user-invocable: false` in its frontmatter.
    pub team_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelpResources {
    pub commands: Vec<HelpCommand>,
    pub agents: Vec<HelpAgent>,
    /// Marker indicating the resources are embedded (not read from disk).
    /// The frontend can use this to display a "shipped with v0.1.x" hint
    /// instead of a filesystem path.
    pub project_root: String,
}

fn first_non_empty_line(content: &str) -> String {
    let mut in_frontmatter = false;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Skip the YAML frontmatter block — `---` on first line opens it,
        // next `---` closes it, content after that is the prose summary.
        if idx == 0 && trimmed == "---" {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if trimmed == "---" {
                in_frontmatter = false;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return trimmed.to_string();
    }
    String::new()
}

/// Minimal frontmatter parser — returns the value of `name` and `description`
/// if the file starts with a `---`-delimited YAML block. We don't pull a
/// full YAML lib for this; only `key: value` pairs at the top level are
/// supported, which matches the shape every agent file uses.
fn parse_frontmatter(content: &str) -> (Option<String>, Option<String>, bool) {
    let mut name = None;
    let mut description = None;
    let mut user_invocable = true;

    let mut lines = content.lines();
    if lines.next().map(str::trim) != Some("---") {
        return (None, None, user_invocable);
    }
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');
            match key {
                "name" => name = Some(value.to_string()),
                "description" => description = Some(value.to_string()),
                "user-invocable" => {
                    if value.eq_ignore_ascii_case("false") {
                        user_invocable = false;
                    }
                }
                _ => {}
            }
        }
    }
    (name, description, user_invocable)
}

#[tauri::command]
pub async fn list_help_resources() -> Result<HelpResources> {
    let mut commands = Vec::new();
    let mut agents = Vec::new();

    for file in COMMANDS_DIR.files() {
        let path = file.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let content = file.contents_utf8().unwrap_or("");
        let description = first_non_empty_line(content);
        commands.push(HelpCommand {
            name: stem,
            description,
            source_path: format!(".claude/commands/{}", path.display()),
        });
    }

    for file in AGENTS_DIR.files() {
        let path = file.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if stem == "_preamble" {
            continue;
        }
        let content = file.contents_utf8().unwrap_or("");
        let (fm_name, fm_description, user_invocable) = parse_frontmatter(content);
        let name = fm_name.unwrap_or_else(|| stem.clone());
        let description = fm_description
            .unwrap_or_else(|| "(no description in frontmatter)".to_string());
        agents.push(HelpAgent {
            name,
            description,
            source_path: format!(".claude/agents/{}", path.display()),
            team_only: !user_invocable,
        });
    }

    commands.sort_by(|a, b| a.name.cmp(&b.name));
    agents.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(HelpResources {
        commands,
        agents,
        project_root: "embedded".to_string(),
    })
}

/// One entry in the User Guide tree.
///
/// The guide is a one-level hierarchy: a top-level `.md` file is a leaf
/// page; a top-level *folder* is a section whose `children` are the pages
/// inside it. Slugs are the path from the guide root with `.md` stripped
/// and `/` as the separator — e.g. `getting-started`, `cloud-accounts/aws`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGuideEntry {
    /// URL-safe slug — the path from the guide root, no extension, e.g.
    /// "getting-started" or "cloud-accounts/aws". For a section node this
    /// is the folder path (not itself navigable — `is_section` is true).
    pub slug: String,
    /// Display title. For a page: the first `# Heading`. For a section:
    /// the folder name, humanized (e.g. "cloud-accounts" → "Cloud Accounts").
    pub title: String,
    /// First non-empty paragraph after the title — a one-line description
    /// for the index. For a section, taken from its `overview.md`.
    pub summary: String,
    /// True when this entry is a folder/section rather than a page. The
    /// index renders it as a group header with `children` beneath it.
    #[serde(default)]
    pub is_section: bool,
    /// Pages within a section. Empty for leaf pages.
    #[serde(default)]
    pub children: Vec<UserGuideEntry>,
}

fn parse_doc_meta(content: &str, slug: &str) -> (String, String) {
    let mut title: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut after_title = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if title.is_none() && line.starts_with("# ") {
            title = Some(line.trim_start_matches('#').trim().to_string());
            after_title = true;
            continue;
        }
        if after_title && summary.is_none() && !line.is_empty() && !line.starts_with('#') {
            // First non-heading, non-empty line after the title — strip
            // basic markdown markers so it reads cleanly in a card.
            let cleaned = line
                .trim_start_matches("> ")
                .trim_start_matches('-')
                .trim();
            summary = Some(cleaned.to_string());
            break;
        }
    }
    (
        title.unwrap_or_else(|| slug.replace('-', " ")),
        summary.unwrap_or_default(),
    )
}

/// Humanize a folder slug into a section title: "cloud-accounts" →
/// "Cloud Accounts", "code-repos-and-imports" → "Code Repos and Imports".
fn humanize(slug: &str) -> String {
    const SMALL: &[&str] = &[
        "and", "or", "the", "of", "to", "a", "an", "vs", "in", "on", "for",
    ];
    // Domain acronyms rendered all-caps (e.g. "scheduled-dast" → "Scheduled DAST").
    const ACRONYMS: &[&str] = &["dast", "sast", "ai", "api", "dns", "ssl", "tls", "idp", "iam"];
    slug.split('-')
        .enumerate()
        .map(|(i, word)| {
            if ACRONYMS.contains(&word) {
                return word.to_uppercase();
            }
            if i != 0 && SMALL.contains(&word) {
                return word.to_string();
            }
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Slug for an embedded file = path from the guide root, no `.md`, with
/// `/` separators. Returns `None` for non-markdown files.
fn file_slug(file: &include_dir::File<'_>) -> Option<String> {
    let path = file.path();
    if path.extension().and_then(|s| s.to_str()) != Some("md") {
        return None;
    }
    Some(path.with_extension("").to_string_lossy().replace('\\', "/"))
}

/// True when a slug points at a section's `overview` page.
fn is_overview(slug: &str) -> bool {
    slug == "overview" || slug.ends_with("/overview")
}

/// Build leaf page entries for the `.md` files directly inside `dir`,
/// sorted with `overview` first, then alphabetically by title.
fn page_entries(dir: &Dir<'_>) -> Vec<UserGuideEntry> {
    let mut pages: Vec<UserGuideEntry> = Vec::new();
    for file in dir.files() {
        let slug = match file_slug(file) {
            Some(s) => s,
            None => continue,
        };
        let stem = slug.rsplit('/').next().unwrap_or(&slug).to_string();
        let content = file.contents_utf8().unwrap_or("");
        let (title, summary) = parse_doc_meta(content, &stem);
        pages.push(UserGuideEntry {
            slug,
            title,
            summary,
            is_section: false,
            children: Vec::new(),
        });
    }
    pages.sort_by(|a, b| match (is_overview(&a.slug), is_overview(&b.slug)) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.title.cmp(&b.title),
    });
    pages
}

#[tauri::command]
pub async fn list_user_guide() -> Result<Vec<UserGuideEntry>> {
    // Top-level files are leaf pages.
    let mut entries: Vec<UserGuideEntry> = page_entries(&USER_GUIDE_DIR);

    // Each top-level folder is a section; its pages are the children.
    for sub in USER_GUIDE_DIR.dirs() {
        let folder = sub
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if folder.is_empty() {
            continue;
        }
        let children = page_entries(sub);
        if children.is_empty() {
            continue;
        }
        // The section's one-liner comes from its overview page, if present.
        let summary = children
            .iter()
            .find(|c| is_overview(&c.slug))
            .map(|c| c.summary.clone())
            .unwrap_or_default();
        entries.push(UserGuideEntry {
            slug: folder.clone(),
            title: humanize(&folder),
            summary,
            is_section: true,
            children,
        });
    }

    // Stable order — getting-started first, then alphabetical by title.
    entries.sort_by(|a, b| match (a.slug.as_str(), b.slug.as_str()) {
        ("getting-started", _) => std::cmp::Ordering::Less,
        (_, "getting-started") => std::cmp::Ordering::Greater,
        _ => a.title.cmp(&b.title),
    });
    Ok(entries)
}

#[tauri::command]
pub async fn read_user_guide_doc(slug: String) -> Result<String> {
    // Slugs may now contain `/` for nested sections (e.g. "cloud-accounts/aws"),
    // but never path traversal, backslashes, or a leading/absolute path.
    if slug.contains("..")
        || slug.contains('\\')
        || slug.starts_with('/')
        || slug.is_empty()
    {
        return Err(AppError::Config(format!(
            "Invalid doc slug: {slug}"
        )));
    }
    let filename = format!("{slug}.md");
    let file = USER_GUIDE_DIR
        .get_file(&filename)
        .ok_or_else(|| AppError::Config(format!("Doc not found: {slug}")))?;
    let content = file
        .contents_utf8()
        .ok_or_else(|| AppError::Config(format!("Doc {slug} is not valid UTF-8")))?;
    Ok(content.to_string())
}
