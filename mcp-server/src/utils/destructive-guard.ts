/**
 * Central, harness-wide non-destructive backstop.
 *
 * Every container command flows through executeInKaliDetailed() (the same
 * chokepoint that records tool provenance), so screening here makes the WHOLE
 * harness non-destructive by construction — not just the two exploit tools that
 * self-screen. See .claude/agents/_preamble.md (Red Team Exploitation Mandate)
 * and CLAUDE.md ("NEVER execute destructive exploits").
 *
 * Design constraint that shapes every pattern below: this is a red-team tool
 * that LEGITIMATELY sends destructive-looking payloads — a SQLi test literally
 * carries "'; DROP TABLE--", an XSS test carries "<script>", etc. Those travel
 * as QUOTED ARGUMENTS to a scanner; they are not operations the shell executes.
 * So screenCommand() matches destructive OPERATIONS THE SHELL WOULD RUN, anchored
 * at command position — never scary substrings that live inside a payload. It is
 * deliberately scoped to operations that wipe our own environment, the target
 * host, or infrastructure and have ZERO legitimate place as an executed command
 * in this harness. Target-data/cloud-resource destruction (DROP TABLE via a db
 * client, `aws ec2 terminate-instances`) lives in payload-adjacent space where a
 * central regex would false-positive; that intent is gated at the exploit-tool
 * layer via isDestructiveIntent() and the per-tool read-only defaults instead.
 */

export interface CommandScreen {
  blocked: boolean;
  /** Short machine-readable category of the matched destructive operation. */
  category?: string;
  /** Human-readable reason, suitable for surfacing to the agent. */
  reason?: string;
}

interface CatastrophicRule {
  re: RegExp;
  category: string;
  reason: string;
}

/**
 * `rm` with a recursive flag targeting a filesystem root, a critical system
 * directory, a home directory, or a root-level wildcard. Deliberately does NOT
 * match scoped cleanup like `rm -rf /tmp/scan-123` or
 * `rm -rf /opt/pentest/output/x`, which tools do constantly — only bare
 * dangerous roots match.
 */
const DANGEROUS_RM =
  /\brm\s+(?:-\S*\s+)*-\S*r\S*\s+(?:-\S*\s+)*(?:\/\*?|~\/?|\$HOME|\/(?:etc|var|usr|bin|sbin|lib|lib64|boot|root|home|dev|proc|sys)(?:\/\*?)?)(?=\s|;|\||&|>|$)/i;

const CATASTROPHIC_RULES: CatastrophicRule[] = [
  { re: DANGEROUS_RM, category: "filesystem-wipe", reason: "recursive delete of a filesystem root / critical system directory" },
  { re: /\bmkfs(?:\.\w+)?\b/i, category: "filesystem-format", reason: "filesystem creation/format" },
  { re: /\bdd\b[^\n|;&]*\bof=\/dev\/(?:sd|nvme|vd|hd|xvd|disk|mapper)/i, category: "disk-overwrite", reason: "raw write to a block device" },
  { re: /\b(?:wipefs|blkdiscard)\b/i, category: "disk-wipe", reason: "block-device wipe" },
  { re: /\bshred\b[^\n|;&]*\/dev\//i, category: "disk-shred", reason: "shred of a block device" },
  { re: />\s*\/dev\/(?:sd|nvme|vd|hd|xvd|disk)[a-z0-9]/i, category: "disk-overwrite", reason: "redirect over a block device" },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, category: "fork-bomb", reason: "shell fork bomb" },
  { re: /\b(?:shutdown|reboot|poweroff|halt)\b/i, category: "system-control", reason: "host power-state change" },
  { re: /\binit\s+[06]\b/i, category: "system-control", reason: "runlevel change (halt/reboot)" },
  // An HTTP DELETE issued via curl/wget/httpie is an EXECUTED operation against
  // the target (the method flag, not a quoted payload), and removing target data
  // is never permitted (CLAUDE.md: "NEVER execute destructive exploits"). Anchored
  // on the method flag so a URL/body/header containing the word DELETE never
  // false-positives. Schema fuzzing is separately non-destructive (fuzz-api.py
  // skips write methods); this is the harness-wide backstop for any other path.
  { re: /\bcurl\b[^\n|;&]*?(?:-X\s*|--request[ =])DELETE\b/i, category: "http-delete", reason: "HTTP DELETE against the target (would remove data)" },
  { re: /\bwget\b[^\n|;&]*--method[ =]DELETE\b/i, category: "http-delete", reason: "wget DELETE against the target (would remove data)" },
];

/**
 * Screen a shell command for catastrophic, never-legitimate operations before it
 * runs in the container. Returns `{ blocked: true, category, reason }` when the
 * command must be refused, `{ blocked: false }` otherwise.
 */
export function screenCommand(command: string): CommandScreen {
  for (const rule of CATASTROPHIC_RULES) {
    if (rule.re.test(command)) {
      return { blocked: true, category: rule.category, reason: rule.reason };
    }
  }
  return { blocked: false };
}

/**
 * Intent-level destructive check for the exploit tools (run_metasploit /
 * execute_custom_exploit). Unlike screenCommand() — which guards the shell
 * chokepoint against catastrophic OS ops — this flags red-team exploits whose
 * intent is destruction (DoS, data deletion) so the handler records an
 * EXPLOITED (DESTRUCTIVE — WITHHELD) finding instead of detonating. Operates on
 * a module path + serialized options, or a script body. Whole-word matching so a
 * target named "dropbox" no longer trips the "drop" rule.
 */
const DESTRUCTIVE_INTENT =
  /\b(?:dos|denial(?:[-\s]?of[-\s]?service)?|crash|delete|drop|truncate|destroy|wipe|shutdown|reboot|format|flushall|flushdb|deltree)\b|\brm\s+-\S*[rf]/i;

export function isDestructiveIntent(text: string): boolean {
  return DESTRUCTIVE_INTENT.test(text);
}
