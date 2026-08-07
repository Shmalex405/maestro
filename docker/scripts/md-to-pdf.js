#!/usr/bin/env node
/**
 * Markdown-to-PDF converter with professional security report styling.
 *
 * Reads a markdown file, converts to styled HTML with severity-aware
 * coloring, finding cards, and status badges, then renders to PDF via Playwright.
 *
 * Usage: node md-to-pdf.js <input.md> [output.pdf]
 */

const { chromium } = require("playwright");
const { marked } = require("marked");
const fs = require("fs");
const path = require("path");

const STATE_DIR = "/opt/pentest/output/browser-state";
const BRANDS_DIR = path.join(__dirname, "brands");

// ─── Severity / Status keyword maps ──────────────────────────────────────────

const SEVERITY_KEYWORDS = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFORMATIONAL: "info",
  INFO: "info",
};

const STATUS_KEYWORDS = {
  // Exploitability (finding metadata)
  TRUE: "exploitable-true",
  FALSE: "exploitable-false",
  POTENTIALLY: "exploitable-potentially",
  // Test coverage statuses
  PASS: "pass",
  FAIL: "fail",
  BLOCKED: "blocked",
  "N/A": "na",
  NA: "na",
  // Exploitation matrix
  EXPOSED: "exposed",
  CONFIRMED: "confirmed",
  "NOT EXPOSABLE": "not-exposable",
  "NOT_EXPLOITABLE": "not-exploitable",
  MITIGATED: "mitigated",
  INCONCLUSIVE: "inconclusive",
  SKIPPED: "skipped",
  YES: "yes",
  NO: "no",
  // Oracle verdicts (migration 0049). VERIFIED is the strongest claim the
  // report can make about a finding: an oracle re-proved it in code and the
  // finding carries a replay capsule the reader can run themselves. CANDIDATE
  // is deliberately styled as a caution, not a success — it means detected but
  // never independently re-proven.
  VERIFIED: "verified",
  CANDIDATE: "candidate",
  REFUTED: "refuted",
};

// ─── Section CSS class mapping (heading text → class) ────────────────────────

const SECTION_CLASS_MAP = {
  "executive summary": "section-executive",
  "assessment walkthrough": "section-walkthrough",
  "targets assessed": "section-targets",
  "findings summary": "section-findings",
  "critical & high findings": "section-critical-high",
  "critical and high findings": "section-critical-high",
  "medium findings": "section-medium",
  "low & informational findings": "section-low-info",
  "low and informational findings": "section-low-info",
  "exploitation validation": "section-exploitation",
  "exploitation summary matrix": "section-exploitation",
  "qa review summary": "section-qa",
  "recommendations": "section-recommendations",
  "recommendations by priority": "section-recommendations",
  "testing methodology": "section-methodology",
  "detailed methodology": "section-methodology",
  "compliance mapping": "section-compliance",
  "coverage checklist": "section-coverage",
  "conclusion": "section-conclusion",
  "table of contents": "section-toc",
  "appendix": "section-appendix",
  "dast findings": "section-dast",
  "sast findings": "section-sast",
  "cross-validated findings": "section-cross-validated",
  "code remediation guide": "section-remediation",
};

// ─── Brand configuration loader ─────────────────────────────────────────────

function loadBrand(brandName) {
  if (!brandName) return null;
  const brandPath = path.join(BRANDS_DIR, `${brandName}.json`);
  if (!fs.existsSync(brandPath)) {
    console.error(`Brand config not found: ${brandPath}`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(brandPath, "utf-8"));
}

function generateBrandCSS(brand) {
  if (!brand) return "";
  const c = brand.colors;
  return `
/* ========== Client Brand Overrides ========== */
:root {
  --color-navy: ${c.navy || c.primary};
  --color-dark: ${c.dark || c.primary};
  --color-muted: ${c.muted || "#4a4a6a"};
  --color-border: ${c.border || "#e0e0e0"};
  --color-bg-stripe: ${c.bgStripe || "#f8f9fa"};
  --brand-accent: ${c.accent};
  --brand-accent-dark: ${c.accentDark || c.accent};
  --brand-secondary: ${c.secondary || c.accent};
  --brand-cover-start: ${c.coverGradientStart || c.primary};
  --brand-cover-end: ${c.coverGradientEnd || c.dark || c.primary};
}

/* ── Branded cover page ── */
.cover-page {
  background: linear-gradient(135deg, var(--brand-cover-start) 0%, var(--brand-cover-end) 100%);
  color: #fff;
  min-height: 100vh;
  padding: 60px 50px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  page-break-after: always;
  position: relative;
}

.cover-page::before {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  background: radial-gradient(ellipse at 30% 20%, rgba(70, 224, 211, 0.15) 0%, transparent 60%),
              radial-gradient(ellipse at 70% 80%, rgba(77, 101, 255, 0.1) 0%, transparent 50%);
  pointer-events: none;
}

.cover-page > * {
  position: relative;
  z-index: 1;
}

.cover-page .brand-logo {
  margin-bottom: 40px;
}

.cover-page .brand-logo img {
  max-width: 320px;
  max-height: 120px;
}

/* All text inside cover must be white-on-dark */
.cover-page strong {
  color: ${c.accent} !important;
}

.cover-page p strong {
  color: ${c.accent} !important;
}

.cover-page a {
  color: ${c.accent} !important;
}

/* Cover page table overrides */
.cover-page table {
  border: 1px solid rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.05);
  max-width: 85%;
  margin: 20px auto;
  border-radius: 8px;
  overflow: hidden;
}

.cover-page th {
  background: rgba(255, 255, 255, 0.12);
  color: ${c.accent};
  font-size: 8.5pt;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.cover-page td {
  color: rgba(255, 255, 255, 0.9);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  font-size: 9pt;
  background: transparent !important;
}

.cover-page td strong {
  color: #fff !important;
}

.cover-page tr:nth-child(even) td {
  background: rgba(255, 255, 255, 0.03) !important;
}

.cover-page h1 {
  font-size: 32pt;
  color: #fff;
  border-bottom: 3px solid ${c.accent};
  padding-bottom: 20px;
  margin: 0 0 30px 0;
  letter-spacing: -0.5px;
  line-height: 1.2;
}

.cover-page p {
  font-size: 12pt;
  color: rgba(255, 255, 255, 0.85);
  margin: 5px 0;
}

.cover-page .classification-banner {
  background: rgba(255, 255, 255, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.3);
  color: #fff;
  margin-top: 30px;
}

.cover-page hr { display: none; }

.cover-page .cover-divider {
  width: 80px;
  height: 3px;
  background: ${c.accent};
  border: none;
  margin: 20px auto;
  border-radius: 2px;
}

.cover-page .cover-meta-table {
  margin-top: 30px;
  font-size: 10pt;
  color: rgba(255, 255, 255, 0.8);
  border-collapse: collapse;
  width: auto;
}

.cover-page .cover-meta-table td {
  padding: 4px 12px;
  border: none;
  background: transparent !important;
  color: rgba(255, 255, 255, 0.8);
  text-align: left;
}

.cover-page .cover-meta-table td:first-child {
  font-weight: 600;
  color: ${c.accent};
  text-align: right;
  white-space: nowrap;
}

/* ── Branded heading accents ── */
h1 {
  border-bottom-color: var(--brand-accent, var(--color-navy));
}

h2 {
  border-bottom-color: ${c.accent};
}

/* ── Branded table headers ── */
th {
  background: var(--color-navy);
}

/* ── Branded code block accent ── */
pre {
  border-left-color: ${c.accent};
}

/* ── Branded links ── */
a {
  color: ${c.secondary || c.accent};
}

/* ── Branded section highlights ── */
.section-toc {
  border-bottom-color: ${c.accent};
}

.section-executive {
  border-bottom-color: ${c.accent};
}

/* ── Subtle accent bar at top of each page (via header) ── */
`;
}

function resolveBrandLogoDataUri(brand) {
  // Returns a data URI string for the logo, ready for <img src="...">
  if (!brand) return null;

  // If the brand config already has a data URI, use it directly
  if (brand.logoDataUri) return brand.logoDataUri;

  // Check for a logo file next to the brand config
  for (const ext of ["png", "jpg", "jpeg", "svg"]) {
    const logoPath = path.join(BRANDS_DIR, `${brand.id}-logo.${ext}`);
    if (fs.existsSync(logoPath)) {
      const data = fs.readFileSync(logoPath);
      const mime = ext === "svg" ? "image/svg+xml" : `image/${ext === "jpg" ? "jpeg" : ext}`;
      return `data:${mime};base64,${data.toString("base64")}`;
    }
  }
  return null;
}

function generateBrandedCoverHtml(brand, logoDataUri) {
  if (!brand) return "";
  let logoHtml = "";
  if (logoDataUri) {
    logoHtml = `<div class="brand-logo"><img src="${logoDataUri}" alt="${brand.clientName}" /></div>`;
  } else if (brand.logoUrl) {
    logoHtml = `<div class="brand-logo"><img src="${brand.logoUrl}" alt="${brand.clientName}" /></div>`;
  } else if (brand.logoSvgFallback) {
    logoHtml = `<div class="brand-logo">${brand.logoSvgFallback}</div>`;
  }
  return logoHtml;
}

// ─── Custom marked renderer ──────────────────────────────────────────────────

function createCustomRenderer() {
  return {
    heading({ tokens, depth }) {
      const text = this.parser.parseInline(tokens);
      const rawText = tokens.map((t) => t.raw || t.text || "").join("");
      const id = rawText
        .toLowerCase()
        .replace(/[^\w\s-]/g, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-")
        .trim();

      const classes = [];

      // Section class detection
      const lowerText = rawText.toLowerCase().trim();
      for (const [pattern, cls] of Object.entries(SECTION_CLASS_MAP)) {
        if (lowerText.includes(pattern)) {
          classes.push(cls);
          break;
        }
      }

      // Finding heading detection: ### FINDING N: Title
      if (/^finding\s+\d+/i.test(lowerText)) {
        classes.push("finding-heading");
        // Detect severity from the title (e.g., "FINDING 1: [CRITICAL] SQL Injection")
        for (const [kw, sev] of Object.entries(SEVERITY_KEYWORDS)) {
          if (rawText.toUpperCase().includes(kw)) {
            classes.push(`finding-heading-${sev}`);
            break;
          }
        }
      }

      // Page break for h2
      if (depth === 2) {
        classes.push("page-break-section");
      }

      const classAttr = classes.length ? ` class="${classes.join(" ")}"` : "";
      return `<h${depth} id="${id}"${classAttr}>${text}</h${depth}>\n`;
    },

    tablecell({ tokens, header }) {
      const text = this.parser.parseInline(tokens);
      const tag = header ? "th" : "td";
      const rawText = tokens.map((t) => t.raw || t.text || "").join("").trim();
      const upperText = rawText.toUpperCase().trim();

      const attrs = [];

      // Check severity keywords
      for (const [kw, sev] of Object.entries(SEVERITY_KEYWORDS)) {
        if (upperText === kw || upperText === `**${kw}**`) {
          attrs.push(`data-severity="${sev}"`);
          break;
        }
      }

      // Check status keywords
      if (!attrs.length) {
        for (const [kw, status] of Object.entries(STATUS_KEYWORDS)) {
          if (upperText === kw || upperText === `**${kw}**`) {
            attrs.push(`data-status="${status}"`);
            break;
          }
        }
      }

      const attrStr = attrs.length ? " " + attrs.join(" ") : "";
      return `<${tag}${attrStr}>${text}</${tag}>\n`;
    },

    strong({ tokens }) {
      const text = this.parser.parseInline(tokens);
      const rawText = tokens.map((t) => t.raw || t.text || "").join("").trim();
      const upperText = rawText.toUpperCase().trim();

      // Severity badge
      for (const [kw, sev] of Object.entries(SEVERITY_KEYWORDS)) {
        if (upperText === kw) {
          return `<strong class="severity-badge severity-${sev}">${text}</strong>`;
        }
      }

      // Status badge
      for (const [kw, status] of Object.entries(STATUS_KEYWORDS)) {
        if (upperText === kw) {
          return `<strong class="status-badge status-${status}">${text}</strong>`;
        }
      }

      // Special: CONFIDENTIAL / INTERNAL ONLY
      if (/confidential|internal only/i.test(upperText)) {
        return `<strong class="classification-banner">${text}</strong>`;
      }

      // "STILL IN CURRENT CODE" badge
      if (/still in current code/i.test(upperText)) {
        return `<strong class="status-badge status-exposed">${text}</strong>`;
      }

      return `<strong>${text}</strong>`;
    },

    hr() {
      return '<hr class="finding-separator">\n';
    },
  };
}

// ─── HTML post-processor ─────────────────────────────────────────────────────

function postProcessHtml(html, brand, logoDataUri) {
  // 1. Re-scan <td> tags that might have missed data attributes
  //    (handles cases where bold is nested inside the cell)
  html = html.replace(/<td>([^<]*?)<\/td>/g, (match, content) => {
    const trimmed = content.trim().toUpperCase();
    for (const [kw, sev] of Object.entries(SEVERITY_KEYWORDS)) {
      if (trimmed === kw) return `<td data-severity="${sev}">${content}</td>`;
    }
    for (const [kw, status] of Object.entries(STATUS_KEYWORDS)) {
      if (trimmed === kw) return `<td data-status="${status}">${content}</td>`;
    }
    return match;
  });

  // Also handle td with bold children that have severity badges
  html = html.replace(
    /<td>(\s*<strong class="severity-badge severity-(\w+)">.*?<\/strong>\s*)<\/td>/g,
    (match, content, sev) => `<td data-severity="${sev}">${content}</td>`
  );
  html = html.replace(
    /<td>(\s*<strong class="status-badge status-([\w-]+)">.*?<\/strong>\s*)<\/td>/g,
    (match, content, status) => `<td data-status="${status}">${content}</td>`
  );

  // 2. Wrap finding blocks in finding-card divs
  //    Detect: <h3 ... class="...finding-heading...">FINDING N: ...</h3>
  //    until the next finding-heading or <h2 or end
  html = wrapFindingCards(html);

  // 3. Wrap cover page (content before the first <h2)
  html = wrapCoverPage(html, brand, logoDataUri);

  return html;
}

function wrapFindingCards(html) {
  // Split on finding headings, detect severity from the card content
  const findingPattern = /(<h3[^>]*class="[^"]*finding-heading[^"]*"[^>]*>)/g;
  const parts = html.split(findingPattern);

  if (parts.length <= 1) return html;

  let result = parts[0]; // content before first finding

  for (let i = 1; i < parts.length; i += 2) {
    const heading = parts[i];
    const body = parts[i + 1] || "";

    // Detect severity from the heading class or from content
    let severity = "info";
    const headingSevMatch = heading.match(/finding-heading-(\w+)/);
    if (headingSevMatch) {
      severity = headingSevMatch[1];
    } else {
      // Try to detect from body content (first table cell with severity)
      const bodySevMatch = body.match(/data-severity="(\w+)"/);
      if (bodySevMatch) severity = bodySevMatch[1];
    }

    // Find where this finding ends (next finding-heading h3, or next h2, or next <hr with a following h3 finding)
    // For simplicity, wrap just the heading — CSS :has() can't be relied on in print
    // Instead, we'll add a colored accent bar above each finding heading via CSS
    result += heading + body;
  }

  return result;
}

function wrapCoverPage(html, brand, logoDataUri) {
  // Find the first <h2 — everything before it is the cover page
  const firstH2 = html.indexOf("<h2");
  if (firstH2 === -1) return html;

  const coverContent = html.substring(0, firstH2);
  const rest = html.substring(firstH2);

  // Inject brand logo at start of cover page
  const logoHtml = brand ? generateBrandedCoverHtml(brand, logoDataUri) : "";

  return `<div class="cover-page">${logoHtml}${coverContent}</div>\n${rest}`;
}

// ─── CSS ─────────────────────────────────────────────────────────────────────

// Shared stylesheet. Single source of truth for both PDF pipelines
// (this script + backend-rs/src/pdf.rs). Edit docker/scripts/report-style.css
// and both renderers pick it up — JS at startup, Rust at compile time.
const CSS = fs.readFileSync(path.join(__dirname, 'report-style.css'), 'utf8');

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  // Parse CLI args: node md-to-pdf.js <input.md> [output.pdf] [--brand <name>]
  const args = process.argv.slice(2);
  let inputPath = null;
  let outputPath = null;
  let brandName = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--brand" && args[i + 1]) {
      brandName = args[++i];
    } else if (!inputPath) {
      inputPath = args[i];
    } else if (!outputPath) {
      outputPath = args[i];
    }
  }

  if (!outputPath) outputPath = inputPath ? inputPath.replace(/\.md$/, ".pdf") : null;

  if (!inputPath) {
    console.error("Usage: node md-to-pdf.js <input.md> [output.pdf] [--brand <name>]");
    console.error("Brands: " + (fs.existsSync(BRANDS_DIR) ? fs.readdirSync(BRANDS_DIR).map(f => f.replace(".json", "")).join(", ") : "none"));
    process.exit(1);
  }

  // Load brand configuration
  const brand = loadBrand(brandName);

  const markdown = fs.readFileSync(inputPath, "utf-8");

  // Configure marked with custom renderer
  marked.use({
    gfm: true,
    breaks: false,
    renderer: createCustomRenderer(),
  });

  let htmlBody = marked.parse(markdown);

  // Resolve brand logo to a data URI for inline embedding
  const logoDataUri = resolveBrandLogoDataUri(brand);

  // Post-process HTML for finding cards, cover page, etc.
  htmlBody = postProcessHtml(htmlBody, brand, logoDataUri);

  // Build CSS: base + brand overrides
  const brandCSS = generateBrandCSS(brand);
  const combinedCSS = CSS + brandCSS;

  // Header/footer templates
  const headerText = brand ? brand.headerText : "Security Assessment Report &mdash; Confidential";
  const footerText = brand ? brand.footerText : "";
  const accentColor = brand ? brand.colors.accent : "#1a1a2e";

  const headerTemplate = `<div style="font-size:8px;width:100%;text-align:center;color:#999;padding-top:8px;border-top:2px solid ${accentColor};">${headerText}</div>`;
  const footerTemplate = `<div style="font-size:8px;width:100%;text-align:center;color:#999;padding-bottom:8px;">${footerText ? footerText + " &mdash; " : ""}Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>`;

  const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${brand ? brand.clientName + " — " : ""}Security Assessment Report</title>
  <style>${combinedCSS}</style>
</head>
<body>
${htmlBody}
</body>
</html>`;

  // Write HTML to temp file (useful for debugging)
  const htmlPath = outputPath.replace(/\.pdf$/, ".html");
  fs.writeFileSync(htmlPath, fullHtml);

  // Render to PDF with Playwright
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }

  const context = await chromium.launchPersistentContext(STATE_DIR, {
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
  });

  const page = context.pages()[0] || await context.newPage();

  // setContent with inline data URIs for images
  await page.setContent(fullHtml, { waitUntil: "networkidle" });

  await page.pdf({
    path: outputPath,
    format: "A4",
    margin: { top: "50px", right: "40px", bottom: "60px", left: "40px" },
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate,
    footerTemplate,
  });

  await context.close();

  // Clean up temp HTML
  fs.unlinkSync(htmlPath);

  const stats = fs.statSync(outputPath);
  console.log(JSON.stringify({
    success: true,
    path: outputPath,
    size_kb: Math.round(stats.size / 1024),
    brand: brandName || "default",
    pages: "generated",
  }));
}

main().catch((err) => {
  console.error(JSON.stringify({ success: false, error: err.message }));
  process.exit(1);
});
