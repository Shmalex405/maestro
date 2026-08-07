'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { ScopeConfig } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  ArrowLeft,
  Plus,
  Trash2,
  Network,
  Globe,
  ShieldAlert,
  Save,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react';
import { toast } from 'sonner';

export default function ScopeEditorPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [testTarget, setTestTarget] = useState('');
  const [testResult, setTestResult] = useState<{ valid: boolean; reason?: string } | null>(null);

  // Dialog states
  const [networkDialogOpen, setNetworkDialogOpen] = useState(false);
  const [domainDialogOpen, setDomainDialogOpen] = useState(false);
  const [exclusionDialogOpen, setExclusionDialogOpen] = useState(false);

  // Form states
  const [newNetwork, setNewNetwork] = useState({ cidr: '', environment: 'staging', notes: '' });
  const [newDomain, setNewDomain] = useState({ pattern: '', environment: 'staging' });
  const [newExclusion, setNewExclusion] = useState({ pattern: '', reason: '' });

  const { data: scope, isLoading } = useQuery({
    queryKey: ['scope'],
    queryFn: () => api.config.scope.get(),
  });

  const updateMutation = useMutation({
    mutationFn: (data: ScopeConfig) => api.config.scope.update(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scope'] });
      toast.success('Scope configuration saved');
    },
    onError: () => {
      toast.error('Failed to save scope configuration');
    },
  });

  const validateMutation = useMutation({
    mutationFn: (target: string) => api.config.scope.validate(target),
    onSuccess: (result) => {
      setTestResult(result);
    },
    onError: () => {
      toast.error('Failed to validate target');
    },
  });

  const addNetwork = () => {
    if (!scope || !newNetwork.cidr) return;
    const updated = {
      ...scope,
      networks: [...(scope.networks || []), newNetwork],
    };
    updateMutation.mutate(updated);
    setNewNetwork({ cidr: '', environment: 'staging', notes: '' });
    setNetworkDialogOpen(false);
  };

  const removeNetwork = (index: number) => {
    if (!scope) return;
    const updated = {
      ...scope,
      networks: scope.networks.filter((_, i) => i !== index),
    };
    updateMutation.mutate(updated);
  };

  const addDomain = () => {
    if (!scope || !newDomain.pattern) return;
    const updated = {
      ...scope,
      domains: [...(scope.domains || []), newDomain],
    };
    updateMutation.mutate(updated);
    setNewDomain({ pattern: '', environment: 'staging' });
    setDomainDialogOpen(false);
  };

  const removeDomain = (index: number) => {
    if (!scope) return;
    const updated = {
      ...scope,
      domains: scope.domains.filter((_, i) => i !== index),
    };
    updateMutation.mutate(updated);
  };

  const addExclusion = () => {
    if (!scope || !newExclusion.pattern) return;
    const updated = {
      ...scope,
      exclusions: [...(scope.exclusions || []), newExclusion],
    };
    updateMutation.mutate(updated);
    setNewExclusion({ pattern: '', reason: '' });
    setExclusionDialogOpen(false);
  };

  const removeExclusion = (index: number) => {
    if (!scope) return;
    const updated = {
      ...scope,
      exclusions: scope.exclusions.filter((_, i) => i !== index),
    };
    updateMutation.mutate(updated);
  };


  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/config')}
          className="mb-2 -ml-2"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Configuration
        </Button>
        <h1 className="text-3xl font-bold">Scope Configuration</h1>
        <p className="text-muted-foreground">Define allowed testing targets and exclusions</p>
      </div>

      {/* Test Target */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Test Scope Validation</CardTitle>
          <CardDescription>Check if a target is within the defined scope</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter IP, domain, or URL to test"
              value={testTarget}
              onChange={(e) => {
                setTestTarget(e.target.value);
                setTestResult(null);
              }}
              className="flex-1"
            />
            <Button
              onClick={() => validateMutation.mutate(testTarget)}
              disabled={!testTarget || validateMutation.isPending}
            >
              {validateMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                'Test'
              )}
            </Button>
          </div>
          {testResult && (
            <div
              className={`mt-4 p-3 rounded-lg flex items-center gap-2 ${
                testResult.valid ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
              }`}
            >
              {testResult.valid ? (
                <CheckCircle className="h-5 w-5" />
              ) : (
                <XCircle className="h-5 w-5" />
              )}
              <span>
                {testResult.valid
                  ? 'Target is within scope'
                  : testResult.reason || 'Target is not in scope'}
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scope Tabs */}
      <Tabs defaultValue="networks">
        <TabsList>
          <TabsTrigger value="networks" className="flex items-center gap-2">
            <Network className="h-4 w-4" />
            Networks ({scope?.networks?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="domains" className="flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Domains ({scope?.domains?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="exclusions" className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            Exclusions ({scope?.exclusions?.length || 0})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="networks" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Networks</CardTitle>
                <CardDescription>CIDR ranges allowed for testing</CardDescription>
              </div>
              <Dialog open={networkDialogOpen} onOpenChange={setNetworkDialogOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="mr-2 h-4 w-4" />
                    Add Network
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Network</DialogTitle>
                    <DialogDescription>Add a CIDR range to the scope</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label>CIDR Range</Label>
                      <Input
                        placeholder="e.g., 192.168.100.0/24"
                        value={newNetwork.cidr}
                        onChange={(e) => setNewNetwork({ ...newNetwork, cidr: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Environment</Label>
                      <Select
                        value={newNetwork.environment}
                        onValueChange={(v) => setNewNetwork({ ...newNetwork, environment: v })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="development">Development</SelectItem>
                          <SelectItem value="staging">Staging</SelectItem>
                          <SelectItem value="production">Production</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Notes (Optional)</Label>
                      <Input
                        placeholder="Description or notes"
                        value={newNetwork.notes}
                        onChange={(e) => setNewNetwork({ ...newNetwork, notes: e.target.value })}
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setNetworkDialogOpen(false)}>
                      Cancel
                    </Button>
                    <Button onClick={addNetwork} disabled={!newNetwork.cidr}>
                      Add Network
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CIDR Range</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead>Notes</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scope?.networks?.length ? (
                    scope.networks.map((network, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{network.cidr}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{network.environment}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {network.notes || '-'}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeNetwork(index)}
                            className="text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                        No networks configured
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="domains" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Domains</CardTitle>
                <CardDescription>Domain patterns allowed for testing</CardDescription>
              </div>
              <Dialog open={domainDialogOpen} onOpenChange={setDomainDialogOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="mr-2 h-4 w-4" />
                    Add Domain
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Domain</DialogTitle>
                    <DialogDescription>Add a domain pattern to the scope</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label>Domain Pattern</Label>
                      <Input
                        placeholder="e.g., *.staging.example.com"
                        value={newDomain.pattern}
                        onChange={(e) => setNewDomain({ ...newDomain, pattern: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Environment</Label>
                      <Select
                        value={newDomain.environment}
                        onValueChange={(v) => setNewDomain({ ...newDomain, environment: v })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="development">Development</SelectItem>
                          <SelectItem value="staging">Staging</SelectItem>
                          <SelectItem value="production">Production</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setDomainDialogOpen(false)}>
                      Cancel
                    </Button>
                    <Button onClick={addDomain} disabled={!newDomain.pattern}>
                      Add Domain
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Pattern</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scope?.domains?.length ? (
                    scope.domains.map((domain, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{domain.pattern}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{domain.environment}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeDomain(index)}
                            className="text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center py-8 text-muted-foreground">
                        No domains configured
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="exclusions" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Exclusions</CardTitle>
                <CardDescription>Targets that should never be tested</CardDescription>
              </div>
              <Dialog open={exclusionDialogOpen} onOpenChange={setExclusionDialogOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="mr-2 h-4 w-4" />
                    Add Exclusion
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Exclusion</DialogTitle>
                    <DialogDescription>Add a target to exclude from testing</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label>Pattern</Label>
                      <Input
                        placeholder="e.g., production.example.com"
                        value={newExclusion.pattern}
                        onChange={(e) =>
                          setNewExclusion({ ...newExclusion, pattern: e.target.value })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Reason</Label>
                      <Input
                        placeholder="Why is this excluded?"
                        value={newExclusion.reason}
                        onChange={(e) =>
                          setNewExclusion({ ...newExclusion, reason: e.target.value })
                        }
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setExclusionDialogOpen(false)}>
                      Cancel
                    </Button>
                    <Button onClick={addExclusion} disabled={!newExclusion.pattern}>
                      Add Exclusion
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Pattern</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scope?.exclusions?.length ? (
                    scope.exclusions.map((exclusion, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{exclusion.pattern}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {exclusion.reason || '-'}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeExclusion(index)}
                            className="text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center py-8 text-muted-foreground">
                        No exclusions configured
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

      </Tabs>
    </div>
  );
}
