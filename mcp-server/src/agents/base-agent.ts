/**
 * Base Agent Class
 *
 * Abstract class that all security agents extend. Provides:
 * - Claude API integration for AI-driven decision making
 * - Tool execution via existing handlers
 * - State management and progress tracking
 * - Finding extraction and aggregation
 * - Scope validation and audit logging
 */

import { validateScope } from "../scope/validator";
import { checkExclusions } from "../scope/exclusion-guard";
import { logCommand } from "../logging/audit-logger";
import { getSkillForSystemPrompt } from "./skill-loader";
import {
  LLMProvider,
  getLLMProvider,
  LLMMessage,
  ContentBlock,
  LLMToolCall,
  ToolDefinition as LLMToolDefinition,
} from "../llm";
import { generateFingerprint } from "../integrations/finding-fingerprint";

// Agent execution status
export type AgentStatus = "idle" | "running" | "completed" | "failed" | "cancelled";

// Severity levels for findings
export type Severity = "info" | "low" | "medium" | "high" | "critical";

// Agent state during execution
export interface AgentState {
  id: string;
  agentName: string;
  status: AgentStatus;
  startedAt: string;
  completedAt?: string;
  currentStep: string;
  progress: number; // 0-100
  findings: AgentFinding[];
  errors: string[];
  toolCallsCount: number;
  iterations: number;
  context: Record<string, any>; // Shared context between steps
}

// Finding structure
export interface AgentFinding {
  id: string;
  title: string;
  severity: Severity;
  target: string;
  description: string;
  evidence?: string;
  remediation?: string;
  source: string; // Which agent/tool found it
  timestamp: string;
  metadata?: Record<string, any> & {
    // QA Agent fields (populated after QA validation)
    qaConfidence?: number;        // 1-10 confidence score from QA
    qaValidated?: boolean;        // Whether QA re-tested this finding
    qaStatus?: "confirmed" | "not_reproduced" | "inconclusive";
    qaNote?: string;              // QA agent's notes on this finding
    qaFalsePositive?: boolean;    // True if QA marked as false positive
    // Code context fields (Tier 1 — all findings with file_path)
    codeContext?: string;            // The source code at the vulnerability location
    codeContextFile?: string;        // file:line reference
    codeContextLanguage?: string;    // detected language (python, typescript, etc.)
    codeContextVerified?: boolean;   // Whether source code was read and confirmed
    // Code remediation fields (Tier 2 — HIGH/CRITICAL only)
    remediationCode?: string;        // The fixed code snippet
    remediationExplanation?: string; // Why the fix works
    remediationVerified?: boolean;   // Whether LLM-generated fix was produced
    // Chain analysis fields (populated by chain-analysis-agent)
    chainGrants?: string[];        // Capabilities this finding grants an attacker
    chainRequires?: string[];      // Capabilities needed to exploit this finding
    chainIds?: string[];           // IDs of chains this finding participates in
    chainRole?: 'step' | 'amplifier' | 'prerequisite';  // Role in the chain
    chainSeverityAdjusted?: 'info' | 'low' | 'medium' | 'high' | 'critical';  // Severity when considering chain context
  };
}

// Agent configuration
export interface AgentConfig {
  name: string;
  description: string;
  maxIterations: number;
  timeoutMs: number;
  requiresScopeValidation: boolean;
  tools: string[]; // Tool names this agent can use
}

// Input to agent execution
export interface AgentInput {
  targets?: string[];
  repoPaths?: string[];
  severity?: Severity;
  options?: Record<string, any>;
  context?: Record<string, any>; // Data from previous agents
}

// Output from agent execution
export interface AgentOutput {
  success: boolean;
  agentName: string;
  findings: AgentFinding[];
  summary: string;
  errors: string[];
  context: Record<string, any>; // Data to pass to next agents
  executionTimeMs: number;
  toolCallsCount: number;
  iterations: number;
}

// Tool definition for LLM API (re-export from llm module for compatibility)
export type ToolDefinition = LLMToolDefinition;

// Progress callback type
export type ProgressCallback = (state: AgentState) => void;

/**
 * Abstract base class for all agents
 */
export abstract class BaseAgent {
  protected llm: LLMProvider;
  protected config: AgentConfig;
  protected state: AgentState;
  protected toolHandlers: Record<string, Function>;
  protected onProgress?: ProgressCallback;
  protected abortController?: AbortController;

  constructor(
    config: AgentConfig,
    toolHandlers: Record<string, Function>,
    onProgress?: ProgressCallback
  ) {
    this.config = config;
    this.toolHandlers = toolHandlers;
    this.onProgress = onProgress;

    // Initialize LLM provider (Anthropic is the only implementation)
    this.llm = getLLMProvider();

    // Initialize state
    this.state = this.initializeState();
  }

  // ==================== Abstract Methods ====================
  // Each agent must implement these

  /**
   * Get tool definitions available to this agent
   * Maps inputSchema to input_schema format for Claude API
   */
  abstract getToolDefinitions(): ToolDefinition[];

  /**
   * Build the initial prompt for Claude based on input
   */
  abstract buildInitialPrompt(input: AgentInput): string;

  /**
   * Get agent-specific system prompt additions
   */
  abstract getSystemPrompt(): string;

  // ==================== Public Methods ====================

  /**
   * Execute the agent with given input
   */
  async execute(input: AgentInput): Promise<AgentOutput> {
    const startTime = Date.now();
    this.state = this.initializeState();
    this.state.status = "running";
    this.state.startedAt = new Date().toISOString();
    this.abortController = new AbortController();
    this.emitProgress();

    console.log(`[${this.config.name}] Starting execution`);

    // Validate scope for network agents
    if (this.config.requiresScopeValidation && input.targets) {
      const scopeErrors = await this.validateTargetsScope(input.targets);
      if (scopeErrors.length > 0) {
        console.log(`[${this.config.name}] Scope validation failed: ${scopeErrors.join(", ")}`);
        return this.createFailureOutput(scopeErrors, startTime);
      }
    }

    try {
      const result = await this.runAgentLoop(input);
      this.state.status = "completed";
      this.state.completedAt = new Date().toISOString();
      this.emitProgress();
      console.log(`[${this.config.name}] Completed with ${this.state.findings.length} findings`);
      return result;
    } catch (error) {
      this.state.status = "failed";
      this.state.errors.push(String(error));
      this.state.completedAt = new Date().toISOString();
      this.emitProgress();
      console.error(`[${this.config.name}] Failed:`, error);
      return this.createFailureOutput([String(error)], startTime);
    }
  }

  /**
   * Cancel the agent execution
   */
  cancel(): void {
    console.log(`[${this.config.name}] Cancelling execution`);
    this.state.status = "cancelled";
    this.abortController?.abort();
    this.emitProgress();
  }

  /**
   * Get current agent state
   */
  getState(): AgentState {
    return { ...this.state };
  }

  // ==================== Protected Methods ====================

  /**
   * Main AI-driven execution loop
   */
  protected async runAgentLoop(input: AgentInput): Promise<AgentOutput> {
    const startTime = Date.now();

    // Initialize context with input context
    this.state.context = { ...input.context };

    // Build messages array for LLM conversation
    const messages: LLMMessage[] = [
      { role: "user", content: this.buildInitialPrompt(input) },
    ];

    const tools = this.getToolDefinitions();
    let iterations = 0;
    const maxIterations = this.config.maxIterations;

    // Main loop - LLM decides what to do
    while (iterations < maxIterations && this.state.status === "running") {
      iterations++;
      this.state.iterations = iterations;
      this.state.currentStep = `Iteration ${iterations}/${maxIterations}`;
      this.state.progress = Math.min(90, (iterations / maxIterations) * 100);
      this.emitProgress();

      console.log(`[${this.config.name}] Iteration ${iterations} (using ${this.llm.name})`);

      try {
        // Call LLM provider
        const response = await this.llm.chat({
          system: this.buildFullSystemPrompt(),
          messages: messages,
          tools: tools,
          maxTokens: 4096,
        });

        // Add assistant response to messages
        messages.push({ role: "assistant", content: response.content });

        // If no tool calls, agent is done
        if (response.toolCalls.length === 0) {
          console.log(`[${this.config.name}] Agent finished (no more tool calls)`);
          // Try to extract summary from final text
          if (response.textContent) {
            this.state.context.finalSummary = response.textContent;
          }
          break;
        }

        // Execute all tool calls
        const toolResults = await this.executeToolCalls(response.toolCalls, input);

        // Add tool results to messages
        messages.push({
          role: "user",
          content: toolResults.map((r) => ({
            type: "tool_result" as const,
            tool_use_id: r.id,
            content: r.result,
          })),
        });

        // Check stop reason
        if (response.stopReason === "end_turn") {
          console.log(`[${this.config.name}] Agent finished (end_turn)`);
          break;
        }
      } catch (error: any) {
        // Check if it's a retryable error
        if (this.isRetryableError(error) && iterations < maxIterations) {
          console.warn(`[${this.config.name}] Retryable error, continuing:`, error.message);
          await this.delay(Math.pow(2, iterations) * 1000);
          continue;
        }
        throw error;
      }
    }

    if (iterations >= maxIterations) {
      console.warn(`[${this.config.name}] Reached max iterations (${maxIterations})`);
    }

    return {
      success: true,
      agentName: this.config.name,
      findings: this.state.findings,
      summary: this.generateSummary(),
      errors: this.state.errors,
      context: this.state.context,
      executionTimeMs: Date.now() - startTime,
      toolCallsCount: this.state.toolCallsCount,
      iterations: this.state.iterations,
    };
  }

  /**
   * Execute tool calls and return results
   */
  protected async executeToolCalls(
    toolCalls: LLMToolCall[],
    agentInput: AgentInput
  ): Promise<Array<{ id: string; result: string }>> {
    const results: Array<{ id: string; result: string }> = [];

    for (const call of toolCalls) {
      this.state.toolCallsCount++;
      this.state.currentStep = `Executing: ${call.name}`;
      this.emitProgress();

      console.log(`[${this.config.name}] Executing tool: ${call.name}`);

      // Cross-cutting exclusion check FIRST. The agent path bypasses the
      // per-dimension dispatcher (validateToolScope), so never-touch / excluded
      // targets must be enforced here too — independent of requiresScopeValidation,
      // since an exclusion is a hard deny that applies even to agents whose
      // primary scoping is handled elsewhere.
      const exclusionCheck = await checkExclusions(
        call.input as Record<string, unknown>
      );
      if (exclusionCheck.blocked) {
        console.warn(`[${this.config.name}] Exclusion block: ${exclusionCheck.reason}`);
        results.push({
          id: call.id,
          result: JSON.stringify({
            error: "SCOPE_EXCLUSION",
            message: exclusionCheck.reason,
          }),
        });
        continue;
      }

      // Scope validation for individual tool calls
      const inputAny = call.input as Record<string, string | undefined>;
      const target = inputAny.target || inputAny.domain || inputAny.cidr;
      if (target && this.config.requiresScopeValidation) {
        const scopeCheck = await validateScope(target);
        if (!scopeCheck.valid) {
          console.warn(`[${this.config.name}] Scope violation for ${target}`);
          results.push({
            id: call.id,
            result: JSON.stringify({
              error: "SCOPE_VIOLATION",
              message: `Target "${target}" is not in scope: ${scopeCheck.reason}`,
            }),
          });
          continue;
        }
      }

      // Log command to audit trail
      await logCommand({
        tool: call.name,
        arguments: call.input as Record<string, unknown>,
        target: target || inputAny.repo_path || inputAny.file_path,
        timestamp: new Date().toISOString(),
        user: `agent:${this.config.name}`,
      });

      // Execute the tool
      const handler = this.toolHandlers[call.name];
      if (!handler) {
        console.error(`[${this.config.name}] Unknown tool: ${call.name}`);
        results.push({
          id: call.id,
          result: JSON.stringify({ error: `Unknown tool: ${call.name}` }),
        });
        continue;
      }

      try {
        const result = await handler(call.input);
        const resultStr = typeof result === "string" ? result : JSON.stringify(result);
        results.push({ id: call.id, result: resultStr });

        // Extract findings from result
        this.extractFindings(resultStr, call.name, target);
      } catch (error) {
        console.error(`[${this.config.name}] Tool ${call.name} failed:`, error);
        results.push({
          id: call.id,
          result: JSON.stringify({ error: String(error) }),
        });
        this.state.errors.push(`Tool ${call.name} failed: ${error}`);
      }
    }

    return results;
  }

  /**
   * Build full system prompt with base + agent-specific instructions + skill docs
   */
  protected buildFullSystemPrompt(): string {
    // Load skill documentation for this agent
    const skillContent = getSkillForSystemPrompt(this.config.name);

    return `You are ${this.config.name}, a specialized security assessment agent.

${this.getSystemPrompt()}

${skillContent}

## General Instructions

1. Use the available tools systematically to accomplish your goal
2. Make intelligent decisions based on tool results
3. If a tool fails, try alternative approaches
4. Document all significant findings
5. When your task is complete, provide a summary of what you found

## Safety Rules

- ALWAYS validate that targets are in scope before testing
- NEVER execute destructive operations
- If something seems dangerous, report it but don't execute
- Log everything for audit purposes

## Output Format

When you're done, summarize:
- What you tested
- What you found (by severity)
- Recommendations for next steps
`;
  }

  /**
   * Initialize agent state
   */
  protected initializeState(): AgentState {
    return {
      id: `${this.config.name}-${Date.now()}`,
      agentName: this.config.name,
      status: "idle",
      startedAt: "",
      currentStep: "Initializing",
      progress: 0,
      findings: [],
      errors: [],
      toolCallsCount: 0,
      iterations: 0,
      context: {},
    };
  }

  /**
   * Emit progress to callback
   */
  protected emitProgress(): void {
    if (this.onProgress) {
      this.onProgress(this.getState());
    }
  }

  /**
   * Extract findings from tool results
   * Override in subclasses for agent-specific extraction
   */
  protected extractFindings(result: string, toolName: string, target?: string): void {
    try {
      const parsed = JSON.parse(result);

      // Look for common finding patterns in results
      if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
        for (const vuln of parsed.vulnerabilities) {
          this.addFinding({
            title: vuln.title || vuln.name || `Finding from ${toolName}`,
            severity: this.mapSeverity(vuln.severity),
            target: target || vuln.target || "unknown",
            description: vuln.description || vuln.info || JSON.stringify(vuln),
            evidence: vuln.evidence || vuln.output,
            source: toolName,
          });
        }
      }

      // Look for severity-keyed findings (common in nuclei output)
      for (const severity of ["critical", "high", "medium", "low", "info"]) {
        if (parsed[severity] && Array.isArray(parsed[severity])) {
          for (const finding of parsed[severity]) {
            this.addFinding({
              title: finding.title || finding.name || `${severity} finding from ${toolName}`,
              severity: severity as Severity,
              target: target || finding.target || finding.host || "unknown",
              description: finding.description || finding.info || JSON.stringify(finding),
              evidence: finding.evidence || finding.output || finding.matched,
              source: toolName,
            });
          }
        }
      }

      // Store raw results in context for later use
      if (!this.state.context.toolResults) {
        this.state.context.toolResults = {};
      }
      this.state.context.toolResults[toolName] = parsed;
    } catch {
      // Not JSON or no findings structure - that's fine
    }
  }

  /**
   * Add a finding to the state
   * Uses fingerprint-based deduplication for consistent cross-tool matching
   */
  protected addFinding(finding: Omit<AgentFinding, "id" | "timestamp">): void {
    // Generate fingerprint for deduplication
    const fingerprint = generateFingerprint({
      target: finding.target,
      title: finding.title,
      cve: finding.metadata?.cve,
      cwe: finding.metadata?.cwe,
      description: finding.description,
    });

    const newFinding: AgentFinding = {
      ...finding,
      id: `${this.config.name}-${Date.now()}-${this.state.findings.length}`,
      timestamp: new Date().toISOString(),
      metadata: {
        ...finding.metadata,
        fingerprint, // Store fingerprint for later DB deduplication
      },
    };

    // Check for duplicate using fingerprint (more reliable than title/target/severity)
    const isDuplicate = this.state.findings.some(
      (f) => f.metadata?.fingerprint === fingerprint
    );

    if (!isDuplicate) {
      this.state.findings.push(newFinding);
      console.log(
        `[${this.config.name}] Found: ${newFinding.severity.toUpperCase()} - ${newFinding.title}`
      );
    } else {
      console.log(
        `[${this.config.name}] Skipped duplicate: ${finding.title} on ${finding.target}`
      );
    }
  }

  /**
   * Map various severity formats to our standard
   */
  protected mapSeverity(severity: string | undefined): Severity {
    if (!severity) return "info";
    const lower = severity.toLowerCase();
    if (lower.includes("critical")) return "critical";
    if (lower.includes("high")) return "high";
    if (lower.includes("medium") || lower.includes("moderate")) return "medium";
    if (lower.includes("low")) return "low";
    return "info";
  }

  /**
   * Generate summary of findings
   */
  protected generateSummary(): string {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const finding of this.state.findings) {
      counts[finding.severity]++;
    }

    const parts = [];
    if (counts.critical > 0) parts.push(`${counts.critical} critical`);
    if (counts.high > 0) parts.push(`${counts.high} high`);
    if (counts.medium > 0) parts.push(`${counts.medium} medium`);
    if (counts.low > 0) parts.push(`${counts.low} low`);
    if (counts.info > 0) parts.push(`${counts.info} info`);

    if (parts.length === 0) {
      return `${this.config.name} completed with no findings.`;
    }

    return `${this.config.name} found ${this.state.findings.length} issues: ${parts.join(", ")}.`;
  }

  /**
   * Validate targets against scope
   */
  protected async validateTargetsScope(targets: string[]): Promise<string[]> {
    const errors: string[] = [];

    for (const target of targets) {
      const result = await validateScope(target);
      if (!result.valid) {
        errors.push(`Target "${target}" is not in scope: ${result.reason}`);
      }
    }

    return errors;
  }

  /**
   * Create failure output
   */
  protected createFailureOutput(errors: string[], startTime: number): AgentOutput {
    return {
      success: false,
      agentName: this.config.name,
      findings: this.state.findings,
      summary: `${this.config.name} failed: ${errors.join("; ")}`,
      errors: errors,
      context: this.state.context,
      executionTimeMs: Date.now() - startTime,
      toolCallsCount: this.state.toolCallsCount,
      iterations: this.state.iterations,
    };
  }

  /**
   * Check if error is retryable
   */
  protected isRetryableError(error: any): boolean {
    const message = String(error);
    const retryablePatterns = [
      "rate_limit",
      "overloaded",
      "ECONNRESET",
      "ETIMEDOUT",
      "503",
      "529",
    ];
    return retryablePatterns.some((p) => message.toLowerCase().includes(p.toLowerCase()));
  }

  /**
   * Delay helper
   */
  protected delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
