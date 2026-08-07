'use client';

// Scheduled DAST → Reports. Export the DAST-only vulnerability set (CSV / JSON /
// Markdown), and manage scheduled delivery subscriptions (delivery pending an
// external email integration).

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { FileText, Download, Mail, Plus, Trash2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { api } from '@/lib/tauri-api';
import { ExportFindingsButton } from '@/components/scheduled/dast-shared';

function DeliveryCard() {
  const queryClient = useQueryClient();
  const { data: subs, isLoading } = useQuery({
    queryKey: ['report-subscriptions'],
    queryFn: () => api.reportSubscriptions.list(),
  });
  const [recipients, setRecipients] = useState('');
  const [cadence, setCadence] = useState('weekly');

  const create = useMutation({
    mutationFn: () =>
      api.reportSubscriptions.create({
        recipients: recipients.split(',').map((r) => r.trim()).filter(Boolean),
        cadence,
      }),
    onSuccess: () => {
      toast.success('Subscription added.');
      setRecipients('');
      queryClient.invalidateQueries({ queryKey: ['report-subscriptions'] });
    },
    onError: (e) => toast.error(`Couldn't add: ${e instanceof Error ? e.message : String(e)}`),
  });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.reportSubscriptions.update(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['report-subscriptions'] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.reportSubscriptions.remove(id),
    onSuccess: () => {
      toast.success('Subscription removed.');
      queryClient.invalidateQueries({ queryKey: ['report-subscriptions'] });
    },
  });

  return (
    <Card className="glass-card">
      <CardContent className="p-0">
        <div className="border-b border-border/40 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-semibold">
            <Mail className="h-4 w-4 text-primary/70" /> Scheduled delivery
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Email the DAST report on a cadence. <span className="text-amber-400">Delivery is pending an
            email integration</span> — subscriptions are saved and managed here now.
          </p>
        </div>

        <div className="flex flex-wrap items-end gap-2 p-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Recipients (comma-separated)</label>
            <Input value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="sec@acme.com, lead@acme.com" className="h-8 w-[280px] text-sm" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Cadence</label>
            <Select value={cadence} onValueChange={setCadence}>
              <SelectTrigger className="h-8 w-[120px] text-sm"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button size="sm" className="h-8" disabled={!recipients.trim() || create.isPending} onClick={() => create.mutate()}>
            <Plus className="mr-1.5 h-3.5 w-3.5" /> Add
          </Button>
        </div>

        <div className="px-4 pb-4">
          {isLoading ? (
            <Skeleton className="h-10 w-full" />
          ) : (subs?.length ?? 0) === 0 ? (
            <p className="text-xs text-muted-foreground/60">No delivery subscriptions.</p>
          ) : (
            <div className="divide-y divide-border/40 rounded-lg border border-border/40">
              {(subs ?? []).map((s) => (
                <div key={s.id} className="flex items-center gap-3 px-3 py-2">
                  <Switch checked={s.enabled} onCheckedChange={(enabled) => toggle.mutate({ id: s.id, enabled })} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">{s.recipients.join(', ')}</p>
                    <p className="text-[10px] capitalize text-muted-foreground">{s.cadence}{s.last_sent_at ? ` · last sent ${s.last_sent_at.slice(0, 10)}` : ' · never sent'}</p>
                  </div>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400" onClick={() => remove.mutate(s.id)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function ScheduledReportsPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Reports</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Export the scheduled-DAST vulnerability set for sharing or ticketing.
        </p>
      </div>

      <Card className="glass-card">
        <CardContent className="flex flex-col items-start gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <FileText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-sm font-semibold">DAST vulnerability export</p>
              <p className="mt-0.5 max-w-md text-xs text-muted-foreground">
                All findings produced by scheduled / on-demand DAST scans, across every target —
                excluding the LLM exploitation and validation findings.
              </p>
            </div>
          </div>
          <ExportFindingsButton />
        </CardContent>
      </Card>

      <DeliveryCard />

      <Card className="glass-card">
        <CardContent className="p-6">
          <p className="flex items-center gap-2 text-sm font-medium">
            <Download className="h-4 w-4 text-muted-foreground" /> Formats
          </p>
          <ul className="mt-2 space-y-1.5 text-xs text-muted-foreground">
            <li><span className="font-medium text-foreground">CSV</span> — spreadsheet-friendly, one row per vulnerability.</li>
            <li><span className="font-medium text-foreground">JSON</span> — full structured records for downstream tooling.</li>
            <li><span className="font-medium text-foreground">Markdown</span> — readable report you can paste into a ticket or doc.</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
