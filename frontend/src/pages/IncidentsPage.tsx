import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { GitBranch, Link2, Plus, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { severityClass, severityDot, statusClass } from '@/lib/tokens';
import { timeAgo, cn, fmtInt } from '@/lib/utils';
import type { Incident, Page, Severity } from '@/types/contract';

const INCIDENT_STATUS = ['Open', 'Investigating', 'Contained', 'Resolved', 'Closed'] as const;

export default function IncidentsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [detail, setDetail] = useState<Incident | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('High');
  const [note, setNote] = useState('');

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Page<Incident>>({
    queryKey: ['incidents'],
    queryFn: () => api.get<Page<Incident>>('/incidents?size=50'),
    refetchInterval: 30_000,
  });

  const create = useMutation({
    mutationFn: () => api.post<Incident>('/incidents', { title, description, severity }),
    onSuccess: (inc) => {
      toast.success('Incident created', inc.id.slice(0, 8));
      setCreateOpen(false);
      setTitle('');
      setDescription('');
      qc.invalidateQueries({ queryKey: ['incidents'] });
    },
    onError: (e: Error) => toast.error('Create failed', e.message),
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, any> }) =>
      api.patch<Incident>(`/incidents/${id}`, body),
    onSuccess: (inc) => {
      toast.success('Incident updated', `Status → ${inc.status}`);
      qc.invalidateQueries({ queryKey: ['incidents'] });
      qc.invalidateQueries({ queryKey: ['incident', inc.id] });
      setDetail((d) => (d ? { ...d, ...inc } : d));
    },
    onError: (e: Error) => toast.error('Update failed', e.message),
  });

  const addNote = useMutation({
    mutationFn: ({ id, body }: { id: string; body: string }) =>
      api.post(`/incidents/${id}/notes`, { body }),
    onSuccess: () => {
      toast.success('Note added');
      setNote('');
      if (detail) {
        qc.invalidateQueries({ queryKey: ['incident', detail.id] });
        qc.invalidateQueries({ queryKey: ['incidents'] });
      }
    },
    onError: (e: Error) => toast.error('Note failed', e.message),
  });

  const { data: timeline } = useQuery<{ events: any[] }>({
    queryKey: ['incident', detail?.id ?? '', 'timeline'],
    queryFn: () => api.get(`/incidents/${detail!.id}/timeline`),
    enabled: !!detail,
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Incident Management</h1>
          <p className="page-subtitle">Investigate, assign, annotate and close security incidents</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
          </Button>
          <Button size="sm" disabled={!hasRole('analyst')} onClick={() => setCreateOpen(true)}>
            <Plus className="h-3.5 w-3.5" /> New incident
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><GitBranch className="h-4 w-4 text-accent-soft" /> Incidents</CardTitle>
          <CardDescription>{data ? `${fmtInt(data.total)} incidents` : '…'}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading incidents…" />
          ) : isError ? (
            <ErrorState message="Failed to load incidents." onRetry={() => refetch()} />
          ) : items.length === 0 ? (
            <EmptyState
              title="No incidents yet"
              description="Create an incident to group related alerts and record investigation notes."
              icon={<GitBranch className="h-6 w-6" />}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Alerts</TableHead>
                  <TableHead className="text-right">Notes</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((inc) => (
                  <TableRow key={inc.id} className="cursor-pointer" onClick={() => setDetail(inc)}>
                    <TableCell className="font-medium text-slate-200">{inc.title}</TableCell>
                    <TableCell><Badge className={cn('ring-inset', severityClass[inc.severity])}>{inc.severity}</Badge></TableCell>
                    <TableCell><Badge className={cn('ring-inset', statusClass[inc.status as keyof typeof statusClass] ?? 'bg-slate-500/15 text-slate-300 ring-slate-500/40')}>{inc.status}</Badge></TableCell>
                    <TableCell className="text-right font-mono text-xs">{inc.alert_count}</TableCell>
                    <TableCell className="text-right font-mono text-xs">{inc.notes.length}</TableCell>
                    <TableCell className="text-xs text-slate-500">{timeAgo(inc.updated_at)}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); setDetail(inc); }}>
                        Open
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New incident</DialogTitle>
            <DialogDescription>Group alerts and document the investigation.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="inc-title">Title</Label>
              <Input id="inc-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Sustained DDoS from 192.168.1.10" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="inc-desc">Description</Label>
              <Textarea id="inc-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={3} placeholder="Initial scope, affected assets…" />
            </div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {(['Critical', 'High', 'Medium', 'Low', 'Informational'] as Severity[]).map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => create.mutate()} disabled={title.trim().length < 3 || create.isPending}>
              {create.isPending ? 'Creating…' : 'Create incident'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail dialog */}
      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-w-2xl">
          {detail && (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-2">
                  {detail.title}
                  <Badge className={cn('ring-inset', severityClass[detail.severity])}>{detail.severity}</Badge>
                </DialogTitle>
                <DialogDescription>{detail.description || 'No description.'}</DialogDescription>
              </DialogHeader>

              <div className="flex flex-wrap gap-1.5">
                {INCIDENT_STATUS.map((s) => (
                  <Button
                    key={s}
                    size="sm"
                    variant={detail.status === s ? 'default' : 'outline'}
                    disabled={!hasRole('analyst') || update.isPending || detail.status === s}
                    onClick={() => update.mutate({ id: detail.id, body: { status: s } })}
                  >
                    {s}
                  </Button>
                ))}
              </div>

              <div>
                <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-400">
                  <Link2 className="h-3 w-3" /> Activity timeline ({timeline?.events.length ?? 0})
                </p>
                <div className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
                  {!timeline && <Loading label="Loading timeline…" className="py-4" />}
                  {timeline?.events.map((ev, i) => (
                    <div key={i} className="flex gap-2.5 rounded border border-white/[0.05] bg-navy-950/50 px-2.5 py-2 text-xs">
                      <span className={cn('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', ev.kind === 'alert' ? 'bg-red-400' : 'bg-accent')} />
                      <div className="min-w-0">
                        <p className="text-slate-400">{ev.body}</p>
                        <p className="mt-0.5 text-[10px] text-slate-600">
                          {ev.actor} · {new Date(ev.at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (note.trim()) addNote.mutate({ id: detail.id, body: note.trim() });
                }}
              >
                <Textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Add investigation note…"
                  rows={2}
                  className="flex-1 text-sm"
                  aria-label="Investigation note"
                />
                <Button type="submit" disabled={!note.trim() || addNote.isPending || !hasRole('analyst')} className="self-end">
                  Add note
                </Button>
              </form>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
