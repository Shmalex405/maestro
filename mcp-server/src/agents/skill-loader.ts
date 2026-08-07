/**
 * Skill Loader
 *
 * Loads SKILL.md files for each agent to include in their system prompts.
 * This ensures agents have access to the detailed documentation about
 * their capabilities, workflows, and best practices.
 */

import * as fs from "fs";
import * as path from "path";

// Map agent names to their skill directory names
const AGENT_SKILL_MAP: Record<string, string> = {
  "recon-agent": "recon",
  "auth-agent": "auth",
  "vuln-scan-agent": "vuln-scanner",
  "web-app-agent": "web-app",
  "exploit-agent": "exploit",
  "security-scan-agent": "security-scan",
  "report-agent": "report",
};

// Cache loaded skills
const skillCache: Record<string, string> = {};

/**
 * Get the path to the skills directory
 */
function getSkillsBasePath(): string {
  // Navigate from mcp-server/src/agents to skills/
  return path.join(__dirname, "../../../skills");
}

/**
 * Load a skill file for a specific agent
 */
export function loadSkill(agentName: string): string | null {
  // Check cache first
  if (skillCache[agentName]) {
    return skillCache[agentName];
  }

  const skillDir = AGENT_SKILL_MAP[agentName];
  if (!skillDir) {
    console.warn(`[skill-loader] No skill mapping for agent: ${agentName}`);
    return null;
  }

  const skillPath = path.join(getSkillsBasePath(), skillDir, "SKILL.md");

  try {
    const content = fs.readFileSync(skillPath, "utf-8");
    skillCache[agentName] = content;
    console.log(`[skill-loader] Loaded skill for ${agentName} from ${skillPath}`);
    return content;
  } catch (error) {
    console.warn(`[skill-loader] Could not load skill for ${agentName}: ${error}`);
    return null;
  }
}

/**
 * Load all skills at once
 */
export function loadAllSkills(): Record<string, string> {
  const skills: Record<string, string> = {};

  for (const [agentName, skillDir] of Object.entries(AGENT_SKILL_MAP)) {
    const skill = loadSkill(agentName);
    if (skill) {
      skills[agentName] = skill;
    }
  }

  return skills;
}

/**
 * Get skill content formatted for inclusion in system prompt
 */
export function getSkillForSystemPrompt(agentName: string): string {
  const skill = loadSkill(agentName);

  if (!skill) {
    return "";
  }

  return `
## Skill Documentation

The following is your detailed skill documentation. Follow these guidelines carefully.

${skill}

---
`;
}

/**
 * Clear the skill cache (useful for development/testing)
 */
export function clearSkillCache(): void {
  for (const key of Object.keys(skillCache)) {
    delete skillCache[key];
  }
}
