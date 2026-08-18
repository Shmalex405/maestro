-- Code-context + remediation-code + PR linkage on findings.
--
-- The MCP promotion path (complete_assessment) already SENDS file_path,
-- line_start/end, code_snippet, remediation_code, remediation_explanation and
-- file_locations, but the cloud API dropped them (they were absent from
-- FindingCreate). Persist them so SAST/code findings carry their structured fix
-- data to the dashboard — which the "Open Fix PR" remediation action needs to
-- build a patch, and the finding detail view needs to render the code.
--
-- pr_* mirrors jira_ticket/jira_url: set when a draft remediation PR is opened
-- for a code finding, surfaced as a PR chip in the Findings UI.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS file_path TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS line_start INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS line_end INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS code_snippet TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_code TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_explanation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS file_locations TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS pr_url TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS pr_status TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS pr_branch TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS pr_number INTEGER;
