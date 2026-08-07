'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { useTerminalStore } from '@/lib/stores/terminal-store';
import { useParsedOutputStore } from '@/lib/stores/parsed-output-store';
import { useIsReadOnly } from '@/lib/read-only';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Send, KeyRound, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

const EMPTY_BLOCKS: never[] = [];

interface UnifiedInputBarProps {
  sessionKey: string;
  /** Whether to show styled chat input (structured view) or hide (terminal view handles input) */
  visible: boolean;
  className?: string;
}

/**
 * Unified input bar that writes directly to the PTY process.
 * In structured view: styled chat-like input with send button.
 * In terminal view: hidden (xterm handles input directly).
 * Detects OTP prompts from the parser and shows specialized code input.
 */
export function UnifiedInputBar({ sessionKey, visible, className }: UnifiedInputBarProps) {
  const [input, setInput] = useState('');
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const otpInputRef = useRef<HTMLInputElement>(null);
  const session = useTerminalStore((s) => s.sessions.get(sessionKey));
  const blocks = useParsedOutputStore((s) => s.sessions.get(sessionKey)) ?? EMPTY_BLOCKS;
  const readOnly = useIsReadOnly();

  // Check if the latest block is a prompt_waiting (OTP or other input request)
  const lastBlock = blocks.length > 0 ? blocks[blocks.length - 1] : null;
  const isOtpWaiting = lastBlock?.type === 'prompt_waiting' &&
    (lastBlock.metadata as { isOtp?: boolean })?.isOtp === true;
  const isPromptWaiting = lastBlock?.type === 'prompt_waiting';

  // Auto-focus OTP input when detected
  useEffect(() => {
    if (isOtpWaiting && otpInputRef.current && visible) {
      otpInputRef.current.focus();
    }
  }, [isOtpWaiting, visible]);

  const writeToPty = useCallback((text: string) => {
    if (readOnly) return; // read-only users cannot drive the terminal
    if (!session?.ptyProcess) return;
    try {
      (session.ptyProcess as { write: (data: string) => void }).write(text + '\n');
    } catch {
      // Ignore write errors
    }
  }, [session?.ptyProcess, readOnly]);

  const handleSubmit = useCallback(() => {
    const text = input.trim();
    if (!text) return;
    writeToPty(text);
    setInput('');
    // Reset textarea height
    if (inputRef.current) {
      inputRef.current.style.height = 'auto';
    }
  }, [input, writeToPty]);

  const handleOtpSubmit = useCallback((code: string) => {
    if (!code.trim()) return;
    writeToPty(code.trim());
  }, [writeToPty]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    // Auto-resize
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  };

  if (!visible) return null;

  const isRunning = session?.status === 'running';
  const isExited = session?.status === 'exited';

  // OTP-specific input
  if (isOtpWaiting && isRunning) {
    return (
      <OtpInputBar onSubmit={handleOtpSubmit} ref={otpInputRef} className={className} />
    );
  }

  return (
    <div className={cn('border-t bg-background/95 backdrop-blur-sm', className)}>
      <div className="max-w-4xl mx-auto flex items-end gap-2 p-3">
        <div className="flex-1 min-w-0">
          <textarea
            ref={inputRef}
            value={input}
            onChange={handleInput}
            onKeyDown={handleKeyDown}
            placeholder={
              readOnly ? 'Read-only access — input disabled' :
              isExited ? 'Session ended' :
              isPromptWaiting ? 'Type your response...' :
              isRunning ? 'Type a message...' : 'Waiting for session...'
            }
            disabled={!isRunning || readOnly}
            rows={1}
            className={cn(
              'w-full resize-none rounded-lg border bg-muted/50 px-4 py-2.5 text-sm',
              'placeholder:text-muted-foreground',
              'focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              'max-h-[120px]'
            )}
          />
        </div>
        <Button
          size="icon"
          className="h-9 w-9 flex-shrink-0"
          onClick={handleSubmit}
          disabled={!isRunning || !input.trim() || readOnly}
        >
          <Send className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

// ─── OTP Input Bar ──────────────────────────────────────────────────────────

import { forwardRef } from 'react';

const OtpInputBar = forwardRef<HTMLInputElement, {
  onSubmit: (code: string) => void;
  className?: string;
}>(function OtpInputBar({ onSubmit, className }, ref) {
  const [code, setCode] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = () => {
    if (!code.trim() || submitted) return;
    setSubmitted(true);
    onSubmit(code.trim());
  };

  return (
    <div className={cn('border-t bg-amber-500/5 backdrop-blur-sm', className)}>
      <div className="max-w-4xl mx-auto flex items-center gap-3 p-3">
        <div className="h-8 w-8 rounded-full bg-amber-500/20 flex items-center justify-center animate-pulse flex-shrink-0">
          <KeyRound className="h-4 w-4 text-amber-500" />
        </div>
        <span className="text-sm font-medium text-amber-400 flex-shrink-0">OTP:</span>
        <Input
          ref={ref}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          placeholder="Enter code..."
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, ''))}
          disabled={submitted}
          className="font-mono text-lg tracking-[0.3em] text-center max-w-[180px] h-10"
          maxLength={8}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              handleSubmit();
            }
          }}
        />
        <Button
          onClick={handleSubmit}
          disabled={!code.trim() || submitted}
          className="h-10"
        >
          {submitted ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <>
              <Send className="h-4 w-4 mr-2" />
              Submit
            </>
          )}
        </Button>
      </div>
    </div>
  );
});
