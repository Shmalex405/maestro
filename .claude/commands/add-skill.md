Create or update a SKILL.md documentation file for an MCP agent. The user specifies the agent via $ARGUMENTS.

If a SKILL.md already exists for this agent, update it. Otherwise create a new one.

## File location

`skills/<agent-name>/SKILL.md`

Existing agents and their skill files:
- `skills/recon/SKILL.md` — Recon Agent
- `skills/vuln-scanner/SKILL.md` — Vulnerability Scanner Agent
- `skills/web-app/SKILL.md` — Web Application Agent
- `skills/exploit/SKILL.md` — Exploit Validation Agent
- `skills/report/SKILL.md` — Report Generation Agent
- `skills/security-scan/SKILL.md` — Security Scan Agent
- `skills/qa/SKILL.md` — QA Validation Agent

## Standard SKILL.md Template

```markdown
# <Agent Name> Agent

## Purpose
<2-3 sentences describing what this agent does and why>

## Capabilities
- <Capability 1>
- <Capability 2>
- <Capability 3>

## Tools Available

| Tool | Description | When to Use |
|------|-------------|-------------|
| `<tool_name>` | <What it does> | <When the agent should use it> |

## Workflow

### Standard Flow
1. **<Phase 1>**: <Description>
2. **<Phase 2>**: <Description>
3. **<Phase 3>**: <Description>

### Decision Points
- If <condition>, then <action>
- If <condition>, then <action>

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Max iterations | 15 | Maximum LLM reasoning loops |
| Timeout | 10 min | Maximum execution time |
| Scope validation | Yes/No | Whether targets need scope check |

## Input Format

```json
{
  "targets": ["<target1>", "<target2>"],
  "options": {}
}
```

## Output Format

The agent returns an `AgentState` object with:
- `findings`: Array of discovered vulnerabilities
- `errors`: Any errors encountered
- `context`: Shared state for downstream agents

## Best Practices
- <Practice 1>
- <Practice 2>

## Integration with Other Agents
- **Receives from**: <upstream agents>
- **Passes to**: <downstream agents>
- **Context shared**: <what data flows between agents>

## Example Usage

```
Tool: run_<name>_agent
Arguments: { "targets": ["https://example.com"] }
```
```

## When updating an existing SKILL.md

1. Read the current file first
2. Preserve any custom content the user added
3. Update tool lists to match actual tools in the agent's config
4. Add any new capabilities or workflow changes
5. Keep the standard section structure

---

User request: $ARGUMENTS
