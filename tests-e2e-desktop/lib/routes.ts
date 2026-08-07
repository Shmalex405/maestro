/**
 * The desktop app's primary navigation surface. Single source of truth for
 * the smoke suite — one entry per primary route, mapped to:
 *   - `path`: the URL path (matched against `window.location.pathname`)
 *   - `sidebar`: the sidebar link text that navigates here (or `null` if
 *     the route isn't in the sidebar — sub-routes, etc.)
 *   - `heading`: text we expect to find in the page's <h1> as a smoke
 *     signal that the page actually rendered its content
 *   - `pageObject`: optional POM module that owns more-specific selectors
 *
 * Keep this list in sync with `frontend/app/`. If you add a new route to
 * the sidebar, add it here too — `routes.smoke.test.ts` iterates it.
 */

export interface RouteSpec {
  /** URL path (e.g. `/assessments`) */
  path: string;
  /** Sidebar link text, or `null` for routes not in the primary nav */
  sidebar: string | null;
  /** Expected first <h1> on the page (substring match) */
  heading: string;
  /** Human label for spec output */
  label: string;
}

export const PRIMARY_ROUTES: RouteSpec[] = [
  // ── Primary nav (sidebar) ──────────────────────────────────────────────
  // Home was renamed Dashboard → Coverage in the coverage-centric IA (v1.0.66).
  { path: '/',             sidebar: 'Coverage',    heading: 'Coverage',      label: 'Coverage' },
  { path: '/scheduled',    sidebar: 'Scheduled DAST', heading: 'Scheduled',  label: 'Scheduled DAST' },
  { path: '/assessments',  sidebar: 'Assessments', heading: 'Assessments',   label: 'Assessments list' },
  { path: '/findings',     sidebar: 'Findings',    heading: 'Findings',      label: 'Findings list' },
  { path: '/reports',      sidebar: 'Reports',     heading: 'Reports',       label: 'Reports list' },
  { path: '/repositories', sidebar: 'Code Repos',  heading: 'Repositories',  label: 'Repositories' },
  { path: '/import',       sidebar: 'Import',      heading: 'Import',        label: 'Import' },
  { path: '/users',        sidebar: 'Users',       heading: 'Users',         label: 'Users' },
  { path: '/docs',         sidebar: 'Docs',        heading: 'Documentation', label: 'Docs index' },
  { path: '/help',         sidebar: 'Help',        heading: 'Help',          label: 'Help' },
  { path: '/config',       sidebar: 'Config',      heading: 'Configuration', label: 'Config root' },
  { path: '/audit-logs',   sidebar: 'Audit Logs',  heading: 'Audit',         label: 'Audit logs' },
];

/**
 * Sub-routes (no sidebar entry — reached via in-page navigation). The
 * smoke tests visit each one by setting `window.location.pathname`
 * directly rather than clicking through.
 */
export const SUB_ROUTES: RouteSpec[] = [
  { path: '/assessments/new',     sidebar: null, heading: 'New Assessment', label: 'New assessment wizard' },
  { path: '/assessments/detail',  sidebar: null, heading: '',               label: 'Assessment detail (empty)' },
  { path: '/findings/detail',     sidebar: null, heading: '',               label: 'Finding detail (empty)' },
  { path: '/findings/jira',       sidebar: null, heading: 'Jira',           label: 'Finding → Jira' },
  { path: '/config/tools',        sidebar: null, heading: 'Tools',          label: 'Config / Tools' },
  { path: '/config/claude',       sidebar: null, heading: 'Claude',         label: 'Config / Claude' },
  { path: '/config/codex',        sidebar: null, heading: 'Codex',          label: 'Config / Codex' },
  { path: '/config/scope',        sidebar: null, heading: 'Scope',          label: 'Config / Scope' },
  { path: '/config/integrations', sidebar: null, heading: 'Integrations',   label: 'Config / Integrations' },
  { path: '/config/cloud',        sidebar: null, heading: 'Cloud',          label: 'Config / Cloud' },
  { path: '/config/cloud-accounts', sidebar: null, heading: 'Cloud',        label: 'Config / Cloud Accounts' },
  { path: '/config/credentials',  sidebar: null, heading: 'Credentials',    label: 'Config / Credentials' },
];
