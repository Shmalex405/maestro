'use client';

import { Button } from '@/components/ui/button';
import { AlertTriangle, Terminal, Key, RefreshCw } from 'lucide-react';

interface TerminalErrorProps {
  type: 'claude-not-installed' | 'api-key-missing' | 'spawn-failed';
  message?: string;
  onRetry?: () => void;
}

export function TerminalError({ type, message, onRetry }: TerminalErrorProps) {
  return (
    <div className="flex-1 flex items-center justify-center bg-background p-8">
      <div className="max-w-md text-center space-y-6">
        {type === 'claude-not-installed' && (
          <>
            <div className="mx-auto w-16 h-16 rounded-full bg-yellow-500/10 flex items-center justify-center">
              <Terminal className="h-8 w-8 text-yellow-500" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-semibold">Claude Code Not Found</h3>
              <p className="text-sm text-muted-foreground">
                The Claude Code CLI needs to be installed to use the terminal.
              </p>
            </div>
            <div className="text-left bg-muted/50 rounded-lg p-4 space-y-2">
              <p className="text-sm font-medium">Install via npm:</p>
              <code className="block text-sm bg-background rounded px-3 py-2 font-mono">
                npm install -g @anthropic-ai/claude-code
              </code>
              <p className="text-xs text-muted-foreground mt-2">
                Then restart the application and try again.
              </p>
            </div>
          </>
        )}

        {type === 'api-key-missing' && (
          <>
            <div className="mx-auto w-16 h-16 rounded-full bg-orange-500/10 flex items-center justify-center">
              <Key className="h-8 w-8 text-orange-500" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-semibold">API Key Not Configured</h3>
              <p className="text-sm text-muted-foreground">
                Set your Anthropic API key to use Claude Code.
              </p>
            </div>
            <div className="text-left bg-muted/50 rounded-lg p-4 space-y-2">
              <p className="text-sm font-medium">Set the environment variable:</p>
              <code className="block text-sm bg-background rounded px-3 py-2 font-mono">
                export ANTHROPIC_API_KEY=sk-ant-...
              </code>
              <p className="text-xs text-muted-foreground mt-2">
                Or configure it in Settings &gt; LLM Configuration.
              </p>
            </div>
          </>
        )}

        {type === 'spawn-failed' && (
          <>
            <div className="mx-auto w-16 h-16 rounded-full bg-red-500/10 flex items-center justify-center">
              <AlertTriangle className="h-8 w-8 text-red-500" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-semibold">Terminal Failed to Start</h3>
              <p className="text-sm text-muted-foreground">
                {message || 'An unexpected error occurred while spawning the terminal.'}
              </p>
            </div>
          </>
        )}

        {onRetry && (
          <Button onClick={onRetry} variant="outline" className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}
