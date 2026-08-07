'use client';

import { TeamOnlyNotice } from '@/components/layout/team-only-notice';
import { isFeatureAvailable } from '@/lib/deployment-mode';

import { useState, useMemo } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
import { toast } from 'sonner';
import {
  UserPlus,
  Mail,
  Shield,
  UserX,
  Loader2,
  RefreshCw,
  Eye,
} from 'lucide-react';
import {
  listUsers,
  inviteUser,
  disableUser,
  resendInvite,
  setUserRole,
  type UserListItem,
  type UserRole,
} from '@/lib/users-api';
import { ADMIN_GROUPS, READONLY_GROUPS } from '@/lib/read-only';
import { useAuthStore } from '@/lib/stores/auth-store';

function statusBadge(status: string): { label: string; variant: 'default' | 'secondary' | 'outline' | 'destructive' } {
  switch (status) {
    case 'CONFIRMED':
      return { label: 'Active', variant: 'default' };
    case 'FORCE_CHANGE_PASSWORD':
      return { label: 'Invited', variant: 'secondary' };
    case 'RESET_REQUIRED':
      return { label: 'Password Reset', variant: 'outline' };
    case 'UNCONFIRMED':
      return { label: 'Unconfirmed', variant: 'outline' };
    case 'DISABLED':
      return { label: 'Disabled', variant: 'destructive' };
    default:
      return { label: status, variant: 'outline' };
  }
}

/** Derive the user's effective role from their Cognito group membership.
 *  Admin wins over read-only; everyone else is a plain member. */
function roleOf(user: UserListItem): UserRole {
  const lower = user.roles.map((r) => r.toLowerCase());
  if (lower.some((r) => ADMIN_GROUPS.has(r))) return 'admin';
  if (lower.some((r) => READONLY_GROUPS.has(r))) return 'read_only';
  return 'user';
}

const ROLE_LABELS: Record<UserRole, string> = {
  admin: 'Admin',
  user: 'User',
  read_only: 'Read-only',
};

function UsersPageInner() {
  const queryClient = useQueryClient();
  const currentEmail = useAuthStore((s) => s.user?.email);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<UserRole>('user');

  const { data: users, isLoading, isError, error } = useQuery({
    queryKey: ['users'],
    queryFn: listUsers,
    refetchInterval: 30_000,
  });

  const inviteMutation = useMutation({
    mutationFn: () => inviteUser({ email: inviteEmail.trim(), role: inviteRole }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success(`Invite sent to ${inviteEmail}`);
      setInviteEmail('');
      setInviteRole('user');
      setInviteOpen(false);
    },
    onError: (e: unknown) => {
      toast.error(`Invite failed: ${e instanceof Error ? e.message : String(e)}`);
    },
  });

  const disableMutation = useMutation({
    mutationFn: (idOrEmail: string) => disableUser(idOrEmail),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success('User disabled');
    },
    onError: (e: unknown) => {
      toast.error(`Disable failed: ${e instanceof Error ? e.message : String(e)}`);
    },
  });

  const resendMutation = useMutation({
    mutationFn: (idOrEmail: string) => resendInvite(idOrEmail),
    onSuccess: () => toast.success('Invite resent'),
    onError: (e: unknown) => {
      toast.error(`Resend failed: ${e instanceof Error ? e.message : String(e)}`);
    },
  });

  const roleMutation = useMutation({
    mutationFn: ({ idOrEmail, role }: { idOrEmail: string; role: UserRole }) =>
      setUserRole(idOrEmail, role),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success(`Role updated to ${ROLE_LABELS[vars.role]}`);
    },
    onError: (e: unknown) => {
      toast.error(`Role update failed: ${e instanceof Error ? e.message : String(e)}`);
    },
  });

  const sortedUsers = useMemo(() => {
    if (!users) return [];
    return [...users].sort((a, b) => a.email.localeCompare(b.email));
  }, [users]);

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <PageHeader
        title="Users"
        description="Manage members of your organization. Invitees receive an email with a temporary password and set their own on first login."
        actions={
        <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
          <DialogTrigger asChild>
            <Button>
              <UserPlus className="mr-2 h-4 w-4" />
              Invite user
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Invite a user</DialogTitle>
              <DialogDescription>
                They&apos;ll get a welcome email with a temporary password and
                be prompted to set a permanent one on first login.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="invite-email">Email</Label>
                <Input
                  id="invite-email"
                  type="email"
                  placeholder="user@yourcompany.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  disabled={inviteMutation.isPending}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-role">Role</Label>
                <Select
                  value={inviteRole}
                  onValueChange={(v) => setInviteRole(v as UserRole)}
                  disabled={inviteMutation.isPending}
                >
                  <SelectTrigger id="invite-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">User</SelectItem>
                    <SelectItem value="admin">Admin</SelectItem>
                    <SelectItem value="read_only">Read-only</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-muted-foreground text-xs">
                  Admins can invite and manage other users. Read-only users can
                  view everything but can&apos;t make changes.
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setInviteOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => inviteMutation.mutate()}
                disabled={
                  !inviteEmail.trim() ||
                  !inviteEmail.includes('@') ||
                  inviteMutation.isPending
                }
              >
                {inviteMutation.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Send invite
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Members</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading…' : `${sortedUsers.length} users in your organization`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isError ? (
            <div className="text-destructive text-sm">
              Failed to load users: {error instanceof Error ? error.message : String(error)}
            </div>
          ) : isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead className="w-[320px] text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedUsers.map((u) => {
                  const badge = statusBadge(u.status);
                  const self = currentEmail === u.email;
                  const role = roleOf(u);
                  return (
                    <TableRow key={u.id}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <Mail className="text-muted-foreground h-4 w-4" />
                          {u.email}
                          {self && (
                            <span className="text-muted-foreground text-xs">(you)</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={badge.variant}>{badge.label}</Badge>
                      </TableCell>
                      <TableCell>
                        {role === 'admin' ? (
                          <span className="inline-flex items-center gap-1 text-sm font-medium">
                            <Shield className="h-3.5 w-3.5" /> Admin
                          </span>
                        ) : role === 'read_only' ? (
                          <span className="inline-flex items-center gap-1 text-sm font-medium text-amber-600 dark:text-amber-400">
                            <Eye className="h-3.5 w-3.5" /> Read-only
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-sm">User</span>
                        )}
                      </TableCell>
                      <TableCell className="space-x-2 text-right">
                        {u.status === 'FORCE_CHANGE_PASSWORD' && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => resendMutation.mutate(u.email)}
                            disabled={resendMutation.isPending}
                          >
                            <RefreshCw className="mr-1 h-3.5 w-3.5" />
                            Resend
                          </Button>
                        )}
                        {!self && (
                          <Select
                            value={role}
                            onValueChange={(v) =>
                              roleMutation.mutate({ idOrEmail: u.email, role: v as UserRole })
                            }
                            disabled={roleMutation.isPending}
                          >
                            <SelectTrigger className="inline-flex h-8 w-[130px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="user">User</SelectItem>
                              <SelectItem value="admin">Admin</SelectItem>
                              <SelectItem value="read_only">Read-only</SelectItem>
                            </SelectContent>
                          </Select>
                        )}
                        {!self && u.enabled !== false && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            onClick={() => {
                              if (confirm(`Disable ${u.email}? They'll lose access immediately.`)) {
                                disableMutation.mutate(u.email);
                              }
                            }}
                            disabled={disableMutation.isPending}
                          >
                            <UserX className="mr-1 h-3.5 w-3.5" />
                            Disable
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}


// Local mode has no user management backing store, so render the
// explanation instead of letting the page fire cloud requests that cannot
// succeed. See lib/deployment-mode.ts for why this is absent rather than broken.
export default function UsersPage() {
  if (!isFeatureAvailable('user-management')) {
    return (
      <TeamOnlyNotice
        feature="user-management"
        title="Users"
        description="Invite teammates and manage roles"
      />
    );
  }
  return <UsersPageInner />;
}
