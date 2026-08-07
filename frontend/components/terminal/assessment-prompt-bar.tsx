'use client';

import { useTerminalStore } from '@/lib/stores/terminal-store';
import { useIsReadOnly } from '@/lib/read-only';
import type { Assessment } from '@/lib/types';
import {
  Shield,
  HelpCircle,
  Eraser,
  Bot,
  ListChecks,
} from 'lucide-react';
import { cn } from '@/lib/utils';

// Compact bar of common slash commands. Click → the command (with a trailing
// space when it takes args) is written into the active claude PTY, where the
// user finishes typing. We deliberately don't auto-press Enter for argful
// commands so users can choose the profile / target before submitting.
//
// Slash commands fall into two categories:
//   - Project: live in .claude/commands/ (e.g. /assess) — discovered by claude
//     when the pane is launched in the project root, which the cd-in-spawn
//     change in v0.1.5 set up. The Help page has the full list.
//   - Built-ins: /help, /clear, /agents — provided by claude itself.

interface SlashCommand {
  command: string;          // typed verbatim into the PTY (without leading space)
  label: string;            // short button label
  icon: typeof Shield;
  takesArgs: boolean;       // when true, paste with trailing space; when false, paste with newline
  hint?: string;            // tooltip / aria-label
}

const COMMON_COMMANDS: SlashCommand[] = [
  {
    command: '/assess',
    label: 'Assess',
    icon: Shield,
    takesArgs: true,
    hint: 'Run a full team-based security assessment (web, code, cloud & identity). Specify a profile from config/assessments.yml',
  },
  {
    command: '/agents',
    label: 'Agents',
    icon: Bot,
    takesArgs: false,
    hint: 'List specialized agents available in this session',
  },
  {
    command: '/help',
    label: 'Help',
    icon: HelpCircle,
    takesArgs: false,
    hint: 'Show all available slash commands',
  },
  {
    command: '/status',
    label: 'Status',
    icon: ListChecks,
    takesArgs: false,
    hint: 'Health check of the dev environment',
  },
  {
    command: '/clear',
    label: 'Clear',
    icon: Eraser,
    takesArgs: false,
    hint: 'Clear the conversation context',
  },
];

interface AssessmentPromptBarProps {
  sessionKey: string;
  /** Kept for compatibility with the parent component's prop shape; the new
   *  bar doesn't create assessment records (that happens inside `/assess`). */
  onAssessmentCreated?: (assessment: Assessment, prompt: string) => void;
  disabled?: boolean;
}

export function AssessmentPromptBar({
  sessionKey,
  disabled: disabledProp,
}: AssessmentPromptBarProps) {
  const readOnly = useIsReadOnly();
  // Read-only users can watch the terminal but can't issue slash commands.
  const disabled = disabledProp || readOnly;

  const handleClick = (cmd: SlashCommand) => {
    if (disabled) return;
    const session = useTerminalStore.getState().sessions.get(sessionKey);
    if (!session?.ptyProcess) return;
    const pty = session.ptyProcess as { write: (data: string) => void };
    // Argful commands → trailing space, no newline (user fills in args).
    // Argless commands → trailing newline, fires immediately.
    pty.write(cmd.takesArgs ? `${cmd.command} ` : `${cmd.command}\n`);
  };

  return (
    <div className="flex items-center gap-1.5 px-3 py-1.5 border-b bg-background/95 backdrop-blur-sm">
      <span className="text-[10px] font-medium text-muted-foreground mr-1 uppercase tracking-wider">
        Commands:
      </span>
      {COMMON_COMMANDS.map((cmd) => {
        const Icon = cmd.icon;
        return (
          <button
            key={cmd.command}
            type="button"
            disabled={disabled}
            onClick={() => handleClick(cmd)}
            title={cmd.hint}
            aria-label={cmd.hint}
            className={cn(
              'inline-flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-medium transition-colors border',
              'border-border bg-muted/40 text-muted-foreground',
              'hover:text-foreground hover:bg-muted/70',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
          >
            <Icon className="h-3 w-3" />
            <span className="font-mono">{cmd.command}</span>
          </button>
        );
      })}
      <span className="ml-auto text-[10px] text-muted-foreground">
        See all in{' '}
        <a href="/help" className="underline hover:text-foreground">
          Help
        </a>
      </span>
    </div>
  );
}
