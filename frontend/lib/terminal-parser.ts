'use client';

/**
 * Terminal Output Parser
 *
 * Streaming line-by-line parser that converts raw Claude Code CLI PTY output
 * into structured ParsedBlock objects for a clean chat-like view.
 *
 * Claude Code uses a full-screen TUI, so we aggressively strip ANSI escape
 * sequences and filter out TUI chrome (menus, status bars, box drawing) to
 * extract only meaningful user prompts and assistant responses.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type BlockType =
  | 'user_input'
  | 'assistant_text'
  | 'tool_call'
  | 'tool_result'
  | 'thinking'
  | 'system'
  | 'finding_detected'
  | 'cost_info'
  | 'prompt_waiting';

export interface ParsedBlock {
  id: string;
  type: BlockType;
  content: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface ToolCallMetadata {
  toolName: string;
  arguments?: Record<string, unknown>;
  status: 'running' | 'completed' | 'failed';
  durationMs?: number;
  [key: string]: unknown;
}

export interface FindingMetadata {
  title: string;
  severity: string;
  target: string;
  assessmentId?: string;
  // Cloud-shaped metadata, populated when create_finding payload includes
  // these fields. Cloud-recon and cloud-exploit agents emit them so the
  // terminal can render provider/account/resource branding instead of
  // dumping the finding into a generic block.
  arn?: string;
  cloud_provider?: 'aws' | 'azure' | 'gcp' | 'k8s';
  account_id?: string;
  region?: string;
  resource_type?: string;
  k8s_cluster?: string;
  k8s_namespace?: string;
  // Hint for the renderer about evidence shape — when 'json' the block
  // can render with collapsible JSON viewer instead of raw text.
  evidence_type?: 'json' | 'text' | 'http' | 'kubectl';
  [key: string]: unknown;
}

export interface CostMetadata {
  cost?: string;
  tokensIn?: number;
  tokensOut?: number;
  cacheRead?: number;
  cacheWrite?: number;
  totalTokens?: number;
  [key: string]: unknown;
}

// ─── ANSI Stripping ─────────────────────────────────────────────────────────

/** Comprehensive ANSI/terminal escape code stripping */
function stripAnsi(str: string): string {
  return str
    // CSI sequences: \x1b[ (with optional ? ! > prefix in params) followed by letter
    .replace(/\x1b\[[0-9;?!>]*[a-zA-Z]/g, '')
    // CSI sequences that end with ~ (e.g., \x1b[200~ for bracketed paste)
    .replace(/\x1b\[[0-9;?]*~/g, '')
    // OSC sequences: \x1b] ... (terminated by BEL \x07 or ST \x1b\\)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    // Character set designation: \x1b( or \x1b) followed by a char
    .replace(/\x1b[()][A-Z0-9]/g, '')
    // Other 2-char ESC sequences (e.g., \x1b=, \x1b>, \x1bM, etc.)
    .replace(/\x1b[\x20-\x2F]*[\x30-\x7E]/g, '')
    // DCS / PM / APC / SOS sequences (start with \x1bP, \x1b^, \x1b_, \x1bX)
    .replace(/\x1b[P^_X][^\x1b]*(?:\x1b\\|\x07)/g, '')
    // Stray ESC not followed by anything recognisable
    .replace(/\x1b/g, '')
    // Control characters (except newline and tab)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    // Carriage return
    .replace(/\r/g, '');
}

// ─── Noise Filtering ────────────────────────────────────────────────────────

/** Patterns that indicate TUI chrome, startup noise, or non-content lines */
const NOISE_PATTERNS: RegExp[] = [
  // Claude Code startup / banner
  /^╭|^╰|^│|^├|^└|^┌|^┐|^┘|^┤|^┬|^┴|^┼/,          // box drawing
  /^─+$/,                                               // horizontal rules (box borders)
  /^\s*Claude\s*Code\s*v?\d/i,                          // version banner
  /^\s*Opus\s+\d/i,                                     // model info line
  /^\s*~\/\S+/,                                          // cwd line in banner
  /^\/remote-control\s+is\s+active/i,                   // remote control notice
  /^\?\s*for\s+shortcuts/i,                              // shortcuts hint
  /^https?:\/\/claude\.ai\/code\/session/,              // session URL
  /^\s*\|\s*\w+/,                                       // TUI menu items like |Recent activity|
  /\|Recent\s*activity\|/i,
  /\|Welcome\s*/i,
  /\|No\s*recent\s*activity\|/i,
  // Empty / decorative
  /^[─━═╌╍┄┅┈┉\s]+$/,                                 // only line-drawing chars
  /^[│┃┆┇┊┋\s]+$/,                                     // only vertical line chars
  /^[░▒▓█\s]+$/,                                        // block drawing
  /^\s*[❯›>]\s*$/,                                      // bare prompt with no content
  // ANSI leftovers (shouldn't happen, but just in case)
  /^\?\d{4}[a-z]/,                                      // leftover like ?2004h
  // Tauri / system noise
  /^Added\s+.*bundled/i,
  /^Fixed\s+local\s+slash/i,
  /^Reduced\s+spurious/i,
  /^\s*What's\s*new/i,
  /^release-notes/i,
  // Status bar fragments (model, org, plan)
  /^Opus\s*4\.\d\s/i,
  /^Claude\s*Max/i,
];

/** Returns true if the line is noise that should be discarded */
function isNoiseLine(line: string): boolean {
  const trimmed = line.trim();
  // Too short to be meaningful (single chars, stray punctuation)
  if (trimmed.length <= 1) return true;
  // Mostly non-printable / garbled (more than 30% special chars)
  const printable = trimmed.replace(/[^\x20-\x7E]/g, '');
  if (printable.length < trimmed.length * 0.5) return true;
  // Check noise patterns
  return NOISE_PATTERNS.some((re) => re.test(trimmed));
}

// ─── Parser State Machine ───────────────────────────────────────────────────

type ParserState =
  | 'idle'
  | 'user_input'
  | 'assistant_text'
  | 'tool_call'
  | 'tool_result'
  | 'thinking';

let blockCounter = 0;
function nextBlockId(): string {
  return `blk_${Date.now()}_${++blockCounter}`;
}

export class TerminalParser {
  private state: ParserState = 'idle';
  private buffer: string = '';
  private lineBuffer: string = '';
  private currentBlock: ParsedBlock | null = null;
  private currentToolName: string = '';
  private toolResultBuffer: string = '';
  private onBlock: (block: ParsedBlock) => void;
  private onBlockUpdate: (id: string, content: string) => void;
  /** Stay silent until first real user prompt (❯ <text>) */
  private startupDone: boolean = false;

  constructor(
    onBlock: (block: ParsedBlock) => void,
    onBlockUpdate: (id: string, content: string) => void
  ) {
    this.onBlock = onBlock;
    this.onBlockUpdate = onBlockUpdate;
  }

  /** Feed raw PTY data into the parser */
  feed(data: string): void {
    const clean = stripAnsi(data);
    this.buffer += clean;

    // Process complete lines
    const lines = this.buffer.split('\n');
    // Keep the last incomplete line in the buffer
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      this.processLine(line);
    }
  }

  /** Process a single complete line */
  private processLine(line: string): void {
    const trimmed = line.trim();

    // ─── Gate: suppress ALL output until first real user prompt ───
    // Claude Code TUI startup produces garbled text when ANSI codes are
    // stripped (cursor positioning turns into mashed-together text).
    // We stay silent until we see `❯ <actual content>`.
    if (!this.startupDone) {
      // Check for a real user prompt: ❯ or > followed by meaningful text
      const promptContent = trimmed.match(/^[❯>]\s+(.+)/)?.[1]?.trim();
      if (promptContent && promptContent.length > 2) {
        this.startupDone = true;
        // Fall through to process this line as user_input below
      } else {
        return; // Silently discard everything during startup
      }
    }

    // ─── Filter noise ───
    if (!trimmed || isNoiseLine(trimmed)) {
      if (!trimmed && this.state === 'assistant_text' && this.currentBlock) {
        this.currentBlock.content += '\n';
        this.onBlockUpdate(this.currentBlock.id, this.currentBlock.content);
      } else if (!trimmed && this.state === 'tool_result') {
        this.toolResultBuffer += '\n';
      }
      return;
    }

    // ─── Cost info line ───
    const costMatch = trimmed.match(/(?:total\s+)?cost:\s*\$([0-9.]+)/i) ||
      trimmed.match(/(\$[0-9.]+)\s+total/i);
    const tokenMatch = trimmed.match(/(\d[\d,]+)\s+tokens?\b/i);
    if (costMatch || (tokenMatch && trimmed.toLowerCase().includes('token'))) {
      this.flushCurrentBlock();
      const metadata: CostMetadata = {};
      if (costMatch) metadata.cost = costMatch[1].startsWith('$') ? costMatch[1] : `$${costMatch[1]}`;

      const inMatch = trimmed.match(/input:\s*(\d[\d,]*)/i);
      const outMatch = trimmed.match(/output:\s*(\d[\d,]*)/i);
      const cacheReadMatch = trimmed.match(/cache[\s_]?read:\s*(\d[\d,]*)/i);
      const cacheWriteMatch = trimmed.match(/cache[\s_]?write:\s*(\d[\d,]*)/i);
      if (inMatch) metadata.tokensIn = parseInt(inMatch[1].replace(/,/g, ''));
      if (outMatch) metadata.tokensOut = parseInt(outMatch[1].replace(/,/g, ''));
      if (cacheReadMatch) metadata.cacheRead = parseInt(cacheReadMatch[1].replace(/,/g, ''));
      if (cacheWriteMatch) metadata.cacheWrite = parseInt(cacheWriteMatch[1].replace(/,/g, ''));
      if (tokenMatch) metadata.totalTokens = parseInt(tokenMatch[1].replace(/,/g, ''));

      this.emitBlock({
        id: nextBlockId(),
        type: 'cost_info',
        content: trimmed,
        timestamp: Date.now(),
        metadata,
      });
      return;
    }

    // ─── User input (prompt echo) ───
    if (trimmed.startsWith('❯ ') || trimmed.startsWith('> ') || trimmed.startsWith('Human: ')) {
      this.flushCurrentBlock();
      const content = trimmed.replace(/^[❯>]\s+/, '').replace(/^Human:\s*/, '');
      if (content.trim()) {
        this.emitBlock({
          id: nextBlockId(),
          type: 'user_input',
          content,
          timestamp: Date.now(),
        });
      }
      return;
    }

    // ─── Thinking block ───
    if (trimmed.match(/^(Thinking|💭|🤔)/i) || trimmed === '<thinking>') {
      this.flushCurrentBlock();
      this.state = 'thinking';
      this.currentBlock = {
        id: nextBlockId(),
        type: 'thinking',
        content: '',
        timestamp: Date.now(),
      };
      return;
    }
    if (trimmed === '</thinking>' && this.state === 'thinking') {
      this.flushCurrentBlock();
      return;
    }
    if (this.state === 'thinking' && this.currentBlock) {
      this.currentBlock.content += (this.currentBlock.content ? '\n' : '') + line;
      this.onBlockUpdate(this.currentBlock.id, this.currentBlock.content);
      return;
    }

    // ─── Tool call start ───
    const toolStartMatch =
      trimmed.match(/^[⏳⚡🔧]\s*(?:Running\s+)?(\w[\w.-]+)/i) ||
      trimmed.match(/^╭[─┬]\s*(\w[\w.-]+)/i) ||
      trimmed.match(/^(\w[\w.]+)\s*\(/);
    if (toolStartMatch && this.isKnownToolPattern(toolStartMatch[1])) {
      this.flushCurrentBlock();
      this.currentToolName = toolStartMatch[1];
      this.state = 'tool_call';
      this.currentBlock = {
        id: nextBlockId(),
        type: 'tool_call',
        content: line,
        timestamp: Date.now(),
        metadata: {
          toolName: this.currentToolName,
          status: 'running',
        } as ToolCallMetadata,
      };
      this.onBlock(this.currentBlock);
      this.state = 'tool_result';
      this.toolResultBuffer = '';
      return;
    }

    // ─── Tool result end / completion ───
    const toolCompleteMatch = trimmed.match(/^[✅✓☑]\s*(?:(?:Done|completed|success)(?:\s|$))/i) ||
      trimmed.match(/^╰[─┴]/);
    const toolErrorMatch = trimmed.match(/^[❌✗✘]\s*(.*)/);
    if ((toolCompleteMatch || toolErrorMatch) && this.state === 'tool_result') {
      if (this.toolResultBuffer.trim()) {
        this.emitBlock({
          id: nextBlockId(),
          type: 'tool_result',
          content: this.toolResultBuffer.trim(),
          timestamp: Date.now(),
          metadata: {
            toolName: this.currentToolName,
            status: toolErrorMatch ? 'failed' : 'completed',
          },
        });
      }
      if (this.currentBlock?.type === 'tool_call') {
        (this.currentBlock.metadata as ToolCallMetadata).status = toolErrorMatch ? 'failed' : 'completed';
        this.onBlockUpdate(this.currentBlock.id, this.currentBlock.content);
      }
      this.toolResultBuffer = '';
      this.currentToolName = '';
      this.currentBlock = null;
      this.state = 'idle';
      return;
    }

    // ─── Accumulate tool result content ───
    if (this.state === 'tool_result') {
      this.toolResultBuffer += (this.toolResultBuffer ? '\n' : '') + line;
      return;
    }

    // ─── System messages ───
    if (trimmed.match(/^(System:|Warning:|Error:|⚠️|🔴|🟡|ℹ️)/i)) {
      this.flushCurrentBlock();
      this.emitBlock({
        id: nextBlockId(),
        type: 'system',
        content: trimmed,
        timestamp: Date.now(),
        metadata: {
          variant: trimmed.match(/error|🔴/i) ? 'error' :
            trimmed.match(/warning|⚠️|🟡/i) ? 'warning' : 'info',
        },
      });
      return;
    }

    // ─── OTP / Input prompt detection ───
    if (this.isPromptWaiting(trimmed)) {
      this.flushCurrentBlock();
      this.emitBlock({
        id: nextBlockId(),
        type: 'prompt_waiting',
        content: trimmed,
        timestamp: Date.now(),
        metadata: {
          isOtp: this.isOtpPrompt(trimmed),
        },
      });
      return;
    }

    // ─── create_finding detection ───
    if (this.isCreateFindingCall(trimmed)) {
      this.detectFinding(trimmed);
    }

    // ─── Default: assistant text ───
    if (this.state !== 'assistant_text') {
      this.flushCurrentBlock();
      this.state = 'assistant_text';
      this.currentBlock = {
        id: nextBlockId(),
        type: 'assistant_text',
        content: line,
        timestamp: Date.now(),
      };
      this.onBlock(this.currentBlock);
    } else if (this.currentBlock) {
      this.currentBlock.content += '\n' + line;
      this.onBlockUpdate(this.currentBlock.id, this.currentBlock.content);
    }
  }

  /** Flush the current in-progress block */
  private flushCurrentBlock(): void {
    if (this.state === 'tool_result' && this.toolResultBuffer.trim()) {
      this.emitBlock({
        id: nextBlockId(),
        type: 'tool_result',
        content: this.toolResultBuffer.trim(),
        timestamp: Date.now(),
        metadata: {
          toolName: this.currentToolName,
          status: 'completed',
        },
      });
      this.toolResultBuffer = '';
    }
    this.currentBlock = null;
    this.state = 'idle';
  }

  /** Emit a new block */
  private emitBlock(block: ParsedBlock): void {
    if (block.type === 'tool_result' || block.type === 'tool_call') {
      this.detectFinding(block.content);
    }
    this.onBlock(block);
  }

  /** Check if a tool name matches known MCP or Claude Code tool patterns */
  private isKnownToolPattern(name: string): boolean {
    const knownPrefixes = [
      'mcp__', 'scan_', 'run_', 'test_', 'check_', 'enumerate_',
      'discover_', 'fuzz_', 'crawl_', 'analyze_', 'generate_',
      'create_', 'browser_', 'detect_', 'map_', 'trace_',
      'fingerprint_', 'search_', 'validate_', 'import_',
      // Claude Code built-in tools
      'Read', 'Write', 'Edit', 'Bash', 'Glob', 'Grep',
      'WebFetch', 'WebSearch', 'TodoWrite', 'TodoRead',
    ];
    return knownPrefixes.some((p) => name.startsWith(p)) || name.includes('__');
  }

  /** Detect OTP/MFA prompt patterns */
  private isOtpPrompt(text: string): boolean {
    const lower = text.toLowerCase();
    return (
      lower.includes('otp') ||
      lower.includes('one-time') ||
      lower.includes('verification code') ||
      lower.includes('mfa') ||
      lower.includes('2fa') ||
      lower.includes('enter the code') ||
      lower.includes('enter code')
    );
  }

  /** Detect any prompt-waiting patterns */
  private isPromptWaiting(text: string): boolean {
    const lower = text.toLowerCase();
    return (
      this.isOtpPrompt(text) ||
      lower.includes('please enter') ||
      lower.includes('waiting for input') ||
      lower.includes('user input required') ||
      lower.includes('press enter') ||
      lower.includes('confirm (y/n)') ||
      (lower.includes('?') && (lower.includes('would you like') || lower.includes('do you want')))
    );
  }

  /** Check if a line/content contains a create_finding call */
  private isCreateFindingCall(text: string): boolean {
    return text.includes('create_finding') || text.includes('create-finding');
  }

  /** Try to extract finding metadata from content */
  private detectFinding(content: string): void {
    if (!this.isCreateFindingCall(content)) return;

    const titleMatch = content.match(/"title"\s*:\s*"([^"]+)"/);
    const severityMatch = content.match(/"severity"\s*:\s*"([^"]+)"/);
    const targetMatch = content.match(/"target"\s*:\s*"([^"]+)"/);
    const assessmentIdMatch = content.match(/"assessment_id"\s*:\s*"([^"]+)"/);

    // Cloud-shaped fields. Cloud-recon and cloud-exploit agents include
    // these in their create_finding payloads when applicable. The target
    // field also commonly holds an ARN for AWS findings — sniff that
    // pattern as a fallback so we still surface provider branding even
    // when the agent didn't set arn explicitly.
    const arnMatch = content.match(/"arn"\s*:\s*"([^"]+)"/);
    const providerMatch = content.match(/"cloud_provider"\s*:\s*"([^"]+)"/);
    const accountIdMatch = content.match(/"account_id"\s*:\s*"([^"]+)"/);
    const regionMatch = content.match(/"region"\s*:\s*"([^"]+)"/);
    const resourceTypeMatch = content.match(/"resource_type"\s*:\s*"([^"]+)"/);
    const k8sClusterMatch = content.match(/"k8s_cluster"\s*:\s*"([^"]+)"/);
    const k8sNamespaceMatch = content.match(/"k8s_namespace"\s*:\s*"([^"]+)"/);
    const evidenceTypeMatch = content.match(/"evidence_type"\s*:\s*"(json|text|http|kubectl)"/);

    const target = targetMatch?.[1] || '';
    const arn = arnMatch?.[1] || (target.startsWith('arn:') ? target : undefined);

    // Infer provider from ARN prefix or k8s_cluster presence when the
    // agent didn't set it explicitly. arn:aws:* / arn:aws-cn:* are AWS;
    // a k8s_cluster value alone is enough to mark provider=k8s.
    let cloudProvider = providerMatch?.[1] as FindingMetadata['cloud_provider'];
    if (!cloudProvider) {
      if (arn?.startsWith('arn:aws')) cloudProvider = 'aws';
      else if (k8sClusterMatch?.[1]) cloudProvider = 'k8s';
    }

    if (titleMatch || severityMatch) {
      this.onBlock({
        id: nextBlockId(),
        type: 'finding_detected',
        content: titleMatch?.[1] || 'Finding detected',
        timestamp: Date.now(),
        metadata: {
          title: titleMatch?.[1] || 'Unknown',
          severity: severityMatch?.[1] || 'info',
          target,
          assessmentId: assessmentIdMatch?.[1],
          arn,
          cloud_provider: cloudProvider,
          account_id: accountIdMatch?.[1],
          region: regionMatch?.[1],
          resource_type: resourceTypeMatch?.[1],
          k8s_cluster: k8sClusterMatch?.[1],
          k8s_namespace: k8sNamespaceMatch?.[1],
          evidence_type: evidenceTypeMatch?.[1] as FindingMetadata['evidence_type'],
        } as FindingMetadata,
      });
    }
  }

  /** Reset parser state */
  reset(): void {
    this.state = 'idle';
    this.buffer = '';
    this.lineBuffer = '';
    this.currentBlock = null;
    this.currentToolName = '';
    this.toolResultBuffer = '';
    this.startupDone = false;
  }
}
