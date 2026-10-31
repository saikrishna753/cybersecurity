import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { KeyRound, Save, ServerCog, ShieldCheck, Users } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loading, ErrorState } from '@/components/ui/toast-reexports';
import { timeAgo, cn } from '@/lib/utils';
import type { Role } from '@/types/contract';

interface Setting { key: string; value: string; updated_at: string }
interface UserRow { id: string; email: string; username: string; full_name: string; role: Role; is_active: boolean; created_at: string }

export default function SettingsPage() {
  const { hasRole, user } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string>>({});

  const { data: settings, isLoading, isError, refetch } = useQuery<Setting[]>({
    queryKey: ['settings'],
    queryFn: () => api.get<Setting[]>('/settings'),
    enabled: hasRole('analyst'),
  });

  useEffect(() => {
    if (settings) {
      setDraft(Object.fromEntries(settings.map((s) => [s.key, s.value])));
    }
  }, [settings]);

  const { data: users } = useQuery<UserRow[]>({
    queryKey: ['users'],
    queryFn: () => api.get<UserRow[]>('/auth/users'),
    enabled: hasRole('admin'),
  });

  const save = useMutation({
    mutationFn: () => api.put('/settings', { settings: draft }),
    onSuccess: () => {
      toast.success('Settings saved');
      qc.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (e: Error) => toast.error('Save failed', e.message),
  });

  const updateRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) =>
      api.patch(`/auth/users/${id}`, { role }),
    onSuccess: () => {
      toast.success('Role updated');
      qc.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (e: Error) => toast.error('Role change failed', e.message),
  });

  if (!hasRole('analyst')) {
    return (
      <div className="space-y-4 animate-fade-in">
        <h1 className="page-title">Settings</h1>
        <Card>
          <CardContent className="p-6 text-sm text-slate-500">
            Your role (viewer) has read-only access. Ask an administrator for analyst/admin privileges to change settings.
          </CardContent>
        </Card>
      </div>
    );
  }

  const bool = (key: string) => draft[key] === 'true';

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Detection thresholds, notifications, threat intel and access control</p>
        </div>
        <Button onClick={() => save.mutate()} disabled={save.isPending}>
          <Save className="h-4 w-4" /> {save.isPending ? 'Saving…' : 'Save changes'}
        </Button>
      </div>

      {isLoading && <Loading label="Loading settings…" />}
      {isError && <ErrorState message="Failed to load settings." onRetry={() => refetch()} />}

      {settings && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-accent-soft" /> Detection engine</CardTitle>
              <CardDescription>Confidence and anomaly thresholds</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="thr">Default confidence threshold</Label>
                <Input
                  id="thr"
                  value={draft.default_confidence_threshold ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, default_confidence_threshold: e.target.value }))}
                  className="font-mono"
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-navy-950/50 px-3 py-2.5">
                <div>
                  <Label>Anomaly detection enabled</Label>
                  <p className="text-[10px] text-slate-600">IsolationForest score alongside classifier</p>
                </div>
                <Switch
                  checked={bool('anomaly_detection_enabled')}
                  onCheckedChange={(v) => setDraft((d) => ({ ...d, anomaly_detection_enabled: String(v) }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="an-thr">Anomaly score threshold</Label>
                <Input
                  id="an-thr"
                  value={draft.anomaly_score_threshold ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, anomaly_score_threshold: e.target.value }))}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dedup">Alert dedup window (minutes)</Label>
                <Input
                  id="dedup"
                  value={draft.alert_dedup_window_minutes ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, alert_dedup_window_minutes: e.target.value }))}
                  className="font-mono"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ServerCog className="h-4 w-4 text-accent-soft" /> Notifications &amp; intel</CardTitle>
              <CardDescription>Optional integrations — app works fine without them</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-navy-950/50 px-3 py-2.5">
                <div>
                  <Label>Email alerts (SMTP)</Label>
                  <p className="text-[10px] text-slate-600">Send new high-severity alerts by email</p>
                </div>
                <Switch
                  checked={bool('alert_email_enabled')}
                  onCheckedChange={(v) => setDraft((d) => ({ ...d, alert_email_enabled: String(v) }))}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="smtph">SMTP host</Label>
                  <Input id="smtph" value={draft.smtp_host ?? ''} onChange={(e) => setDraft((d) => ({ ...d, smtp_host: e.target.value }))} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="smtpo">SMTP port</Label>
                  <Input id="smtpo" value={draft.smtp_port ?? ''} onChange={(e) => setDraft((d) => ({ ...d, smtp_port: e.target.value }))} className="font-mono" />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>Threat intel provider</Label>
                <Select
                  value={draft.ti_provider ?? 'none'}
                  onValueChange={(v) => setDraft((d) => ({ ...d, ti_provider: v }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None (offline, private IPs only)</SelectItem>
                    <SelectItem value="abuseipdb">AbuseIPDB (needs API key)</SelectItem>
                    <SelectItem value="virustotal">VirusTotal (needs API key)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="tik">TI API key {draft.ti_api_key ? <Badge variant="success" className="ml-1.5 ring-inset">set</Badge> : null}</Label>
                <Input
                  id="tik"
                  type="password"
                  value={draft.ti_api_key ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, ti_api_key: e.target.value }))}
                  placeholder="leave blank for none"
                  className="font-mono"
                />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {hasRole('admin') && users && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Users className="h-4 w-4 text-accent-soft" /> User management</CardTitle>
            <CardDescription>Role-based access control: admin &gt; analyst &gt; viewer (read-only)</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium text-slate-200">
                      {u.full_name || u.username}
                      {u.email === user?.email && <Badge variant="outline" className="ml-1.5">you</Badge>}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-500">{u.email}</TableCell>
                    <TableCell>
                      <Select
                        value={u.role}
                        onValueChange={(role) => updateRole.mutate({ id: u.id, role: role as Role })}
                      >
                        <SelectTrigger className="h-7 w-28 text-xs" aria-label={`Role for ${u.username}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="admin">admin</SelectItem>
                          <SelectItem value="analyst">analyst</SelectItem>
                          <SelectItem value="viewer">viewer</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      <Badge variant={u.is_active ? 'success' : 'destructive'} className="ring-inset">
                        {u.is_active ? 'active' : 'disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">{timeAgo(u.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><KeyRound className="h-4 w-4 text-amber-400" /> Security posture</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2.5 text-xs text-slate-500 sm:grid-cols-2">
          {[
            ['Passwords', 'PBKDF2-HMAC-SHA256 · 260k iterations · per-user salt'],
            ['Sessions', 'JWT (HS256) with expiry; token stored client-side only'],
            ['Uploads', 'Extension allowlist + size cap + no execution + traversal-safe names'],
            ['Rate limiting', 'Sliding-window per IP (stricter bucket on login)'],
            ['Audit trail', 'Login, uploads, capture, training, settings actions recorded'],
            ['Data egress', 'Private IPs never leave the host; TI integrations optional'],
          ].map(([k, v]) => (
            <div key={k} className="rounded-lg border border-white/[0.05] bg-navy-950/40 p-3">
              <p className="font-medium text-slate-400">{k}</p>
              <p className="mt-0.5 leading-relaxed">{v}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
