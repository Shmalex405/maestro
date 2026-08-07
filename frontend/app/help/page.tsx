'use client';

import { useMemo, useState } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { Search, Terminal as TerminalIcon, Bot, FolderOpen } from 'lucide-react';
import { isTauri } from '@/lib/tauri-api';

export default function HelpPage() {
  const [filter, setFilter] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['help-resources'],
    queryFn: () => api.help.listResources(),
    // Filesystem read — fast, but no point thrashing the disk on every focus.
    staleTime: 60_000,
    enabled: isTauri(),
  });

  const filteredCommands = useMemo(() => {
    if (!data) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data.commands;
    return data.commands.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q)
    );
  }, [data, filter]);

  const filteredAgents = useMemo(() => {
    if (!data) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data.agents;
    return data.agents.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q)
    );
  }, [data, filter]);

  if (!isTauri()) {
    return (
      <div className="p-6">
        <Card>
          <CardHeader>
            <CardTitle>Help</CardTitle>
            <CardDescription>
              The slash commands and agents reference is only available in the
              Maestro desktop app.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <PageHeader
        title="Help"
        description={
          <>
            Slash commands and specialized agents available in your terminal session.
            Type <code className="px-1.5 py-0.5 rounded bg-muted text-foreground text-xs">/</code>{' '}
            inside any Claude session to see them autocomplete.
          </>
        }
      />

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search commands and agents…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="pl-9"
        />
      </div>

      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      )}

      {error && (
        <Card>
          <CardContent className="pt-6 text-destructive text-sm">
            Failed to load help resources: {String((error as Error).message ?? error)}
          </CardContent>
        </Card>
      )}

      {data && (
        <>
          <section className="space-y-3">
            <div className="flex items-center gap-2">
              <TerminalIcon className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">Slash Commands</h2>
              <Badge variant="secondary" className="ml-auto">
                {filteredCommands.length}/{data.commands.length}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Project commands you can invoke directly. Type{' '}
              <code className="px-1.5 py-0.5 rounded bg-muted text-xs">/&lt;name&gt;</code>{' '}
              followed by any arguments.
            </p>

            {filteredCommands.length === 0 && (
              <p className="text-sm text-muted-foreground italic px-2">
                No commands match &quot;{filter}&quot;.
              </p>
            )}

            <div className="grid gap-3">
              {filteredCommands.map((cmd) => (
                <Card key={cmd.name}>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base font-mono flex items-center gap-2">
                      <span className="text-primary">/{cmd.name}</span>
                    </CardTitle>
                    <CardDescription>{cmd.description || '(no description)'}</CardDescription>
                  </CardHeader>
                </Card>
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <div className="flex items-center gap-2">
              <Bot className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">Specialized Agents</h2>
              <Badge variant="secondary" className="ml-auto">
                {filteredAgents.length}/{data.agents.length}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Workers that handle specific phases of an assessment. Most are spawned
              by the team lead automatically when you run{' '}
              <code className="px-1.5 py-0.5 rounded bg-muted text-xs">/assess</code>;
              user-invocable ones can also be called via{' '}
              <code className="px-1.5 py-0.5 rounded bg-muted text-xs">/agents:&lt;name&gt;</code>.
            </p>

            {filteredAgents.length === 0 && (
              <p className="text-sm text-muted-foreground italic px-2">
                No agents match &quot;{filter}&quot;.
              </p>
            )}

            <div className="grid gap-3">
              {filteredAgents.map((agent) => (
                <Card key={agent.name}>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base font-mono flex items-center gap-2">
                      <span className="text-primary">{agent.name}</span>
                      {agent.team_only ? (
                        <Badge variant="outline" className="text-xs">team-only</Badge>
                      ) : (
                        <Badge variant="secondary" className="text-xs">/agents:{agent.name}</Badge>
                      )}
                    </CardTitle>
                    <CardDescription>{agent.description}</CardDescription>
                  </CardHeader>
                </Card>
              ))}
            </div>
          </section>

          <section className="text-xs text-muted-foreground border-t pt-4 flex items-center gap-2">
            <FolderOpen className="h-3 w-3" />
            Definitions read from{' '}
            <code className="px-1.5 py-0.5 rounded bg-muted text-foreground">
              {data.project_root}/.claude/
            </code>
          </section>
        </>
      )}
    </div>
  );
}
