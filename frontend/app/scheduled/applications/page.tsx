'use client';

// Scheduled DAST → Applications. The grouping layer above targets: each app
// carries ownership + business context (team, criticality, environment).
// Assign targets to an app from the Targets page.

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Boxes, Plus, Pencil, Trash2, Globe } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Skeleton } from '@/components/ui/skeleton';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import type { Application } from '@/lib/types';

const CRITICALITIES = ['low', 'medium', 'high', 'critical'] as const;

function critClass(c: string) {
  return (
    {
      critical: 'bg-red-500/15 text-red-400',
      high: 'bg-orange-500/15 text-orange-400',
      medium: 'bg-yellow-500/15 text-yellow-400',
      low: 'bg-sky-500/15 text-sky-400',
    }[c] ?? 'bg-muted text-muted-foreground'
  );
}

function AppDialog({
  app,
  open,
  onOpenChange,
}: {
  app: Application | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const editing = !!app;
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [team, setTeam] = useState('');
  const [criticality, setCriticality] = useState('medium');
  const [environment, setEnvironment] = useState('');
  const [hydratedFor, setHydratedFor] = useState<string | null | undefined>(undefined);

  // Hydrate when the dialog opens for a (different) app, or reset for create.
  const key = app?.id ?? '__new__';
  if (open && hydratedFor !== key) {
    setName(app?.name ?? '');
    setDescription(app?.description ?? '');
    setTeam(app?.team ?? '');
    setCriticality(app?.criticality ?? 'medium');
    setEnvironment(app?.environment ?? '');
    setHydratedFor(key);
  }
  if (!open && hydratedFor !== undefined) setHydratedFor(undefined);

  const save = useMutation({
    mutationFn: () => {
      const body = { name, description, team, criticality, environment };
      return editing ? api.applications.update(app!.id, body) : api.applications.create(body);
    },
    onSuccess: () => {
      toast.success(editing ? 'Application updated.' : 'Application created.');
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      onOpenChange(false);
    },
    onError: (e) => toast.error(`Couldn't save: ${e instanceof Error ? e.message : String(e)}`),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>{editing ? 'Edit application' : 'New application'}</DialogTitle>
          <DialogDescription>Group targets under an owned, business-context unit.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Name</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Billing API" className="h-8 text-sm" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Description</label>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} className="min-h-[60px] text-sm" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Team / owner</label>
              <Input value={team} onChange={(e) => setTeam(e.target.value)} placeholder="Payments" className="h-8 text-sm" />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Environment</label>
              <Input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="production" className="h-8 text-sm" />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Business criticality</label>
            <Select value={criticality} onValueChange={setCriticality}>
              <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
              <SelectContent>
                {CRITICALITIES.map((c) => (
                  <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : editing ? 'Save' : 'Create'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ScheduledApplicationsPage() {
  const queryClient = useQueryClient();
  const { data: apps, isLoading } = useQuery({
    queryKey: ['applications'],
    queryFn: () => api.applications.list(),
  });
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editApp, setEditApp] = useState<Application | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => api.applications.remove(id),
    onSuccess: () => {
      toast.success('Application deleted.');
      queryClient.invalidateQueries({ queryKey: ['applications'] });
    },
    onError: (e) => toast.error(`Couldn't delete: ${e instanceof Error ? e.message : String(e)}`),
  });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Applications</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Group targets by owned business unit — drives ownership, criticality, and reporting.
            Assign targets from the Targets page.
          </p>
        </div>
        <Button onClick={() => { setEditApp(null); setDialogOpen(true); }}>
          <Plus className="mr-1.5 h-4 w-4" /> New application
        </Button>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32 w-full" />)}
        </div>
      ) : (apps?.length ?? 0) === 0 ? (
        <Card className="glass-card">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <div className="mb-3 rounded-xl bg-muted/50 p-3">
              <Boxes className="h-7 w-7 text-muted-foreground/50" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No applications yet</p>
            <p className="mt-1 max-w-md text-xs text-muted-foreground/70">
              Create one to group your DAST targets under an owner + business criticality.
            </p>
            <Button className="mt-4" onClick={() => { setEditApp(null); setDialogOpen(true); }}>
              <Plus className="mr-1.5 h-4 w-4" /> New application
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {(apps ?? []).map((a) => (
            <Card key={a.id} className="glass-card">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold">{a.name}</p>
                    {a.team && <p className="text-[11px] text-muted-foreground">{a.team}</p>}
                  </div>
                  <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold capitalize', critClass(a.criticality))}>
                    {a.criticality}
                  </span>
                </div>
                {a.description && (
                  <p className="mt-2 line-clamp-2 text-xs text-muted-foreground/90">{a.description}</p>
                )}
                <div className="mt-3 flex items-center justify-between">
                  <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Globe className="h-3 w-3" /> {a.target_count ?? 0} targets
                    </span>
                    {a.environment && <span className="capitalize">{a.environment}</span>}
                  </div>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-primary" onClick={() => { setEditApp(a); setDialogOpen(true); }}>
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400" aria-label={`Delete application ${a.name}`}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Delete application &quot;{a.name}&quot;?</AlertDialogTitle>
                          <AlertDialogDescription>
                            This removes the application and its grouping. Assigned targets are not deleted but will be unassigned. This cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction onClick={() => remove.mutate(a.id)}>Delete</AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <AppDialog app={editApp} open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}
