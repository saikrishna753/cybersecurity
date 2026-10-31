import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertTriangle, Check, Eye, Filter, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { severityClass, statusClass, severityDot } from '@/lib/tokens';
import { fmtInt, timeAgo, cn } from '@/lib/utils';
import type { AlertStatus, ExplainResponse, Page, SecurityAlert, Severity } from '@/types/contract';

const STATUSES: (AlertStatus | 'all')[] = ['all', 'New', 'Acknowledged', 'Investigating', 'Resolved', 'False Positive'];
const SEVERITIES: (Severity | 'all')[] = ['all', 'Critical', 'High', 'Medium', 'Low', 'Informational'];

export default function AlertsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [search, setSearch] = useState(sp.get('search') ?? '');
  const [applied, setApplied] = useState(sp.get('search') ?? '');
  const [selected, setSelected] = useState<SecurityAlert | null>(null);
  const [explain, setExplain] = useState<ExplainResponse | null>(null);

  const params = new URLSearchParams({ page: String(page), size: '20' });
  if (status !== 'all') params.set('status', status);
  if (severity !== 'all') params.set('severity', severity);
  if (applied) params.set('search', applied);

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Page<SecurityAlert>>({
    queryKey: ['alerts', 'list', applied, status, severity, page],
    queryFn: () => api.get<Page<SecurityAlert>>(`/alerts?${params}`),
    refetchInterval: 20_000,
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, any> }) =>
      api.patch<SecurityAlert>(`/alerts/${id}`, body),
    onSuccess: (updated) => {
      toast.success('Alert updated', `Status → ${updated.status}`);
      setSelected(null);
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
    onError: (e: Error) => toast.error('Update failed', e.message),
  });

  const runExplain = useMutation({
    mutationFn: (a: SecurityAlert) =>
      api.post<ExplainResponse>('/explain/prediction', { flow_id: a.flow_id, top_k: 8 }),
    onSuccess: (res) => setExplain(res),
    onError: (e: Error) => toast.error('Explanation unavailable', e.message),
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.size)) : 1;
  const summary = useQuery<{ by_status: Record<string, number> }>({
    queryKey: ['alert-summary'],
    queryFn: () => api.get('/alerts/summary'),
  });

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Security Alerts</h1>
          <p className="page-subtitle">Triage queue — acknowledge, investigate, resolve, or mark false positives</p>
        </div>
        <div className="flex gap-2">
          {summary.data?.by_status?.New != null && (
            <Badge variant="destructive" className="ring-inset px-2.5 py-1">
              {fmtInt(summary.data.by_status.New)} new
            </Badge>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
          </Button>
        </div>
      </div>

      {/* status quick filters */}
      <div className="flex flex-wrap gap-1.5">
        {STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => { setStatus(s); setPage(1); }}
            className={cn(
              'rounded-full px-3 py-1 text-xs ring-1 transition',
              status === s
                ? 'bg-accent/20 text-accent-soft ring-accent/50'
                : 'text-slate-500 ring-white/10 hover:bg-navy-800 hover:text-slate-300',
            )}
          >
            {s}
            {s !== 'all' && summary.data?.by_status?.[s] != null && (
              <span className="ml-1.5 text-[10px] opacity-70">{summary.data.by_status[s]}</span>
            )}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" /> Alert queue
            </CardTitle>
            <CardDescription>{data ? `${fmtInt(data.total)} alerts match current filters` : '…'}</CardDescription>
          </div>
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => { e.preventDefault(); setPage(1); setApplied(search.trim()); setSp(search.trim() ? { search: search.trim() } : {}); }}
          >
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="IP, attack type, alert ID…"
                className="h-8 w-48 pl-8 text-xs"
                aria-label="Search alerts"
              />
            </div>
            <Select value={severity} onValueChange={(v) => { setSeverity(v); setPage(1); }}>
              <SelectTrigger className="h-8 w-32 text-xs" aria-label="Severity"><SelectValue /></SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s === 'all' ? 'All severities' : s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button type="submit" size="sm" variant="secondary"><Filter className="h-3.5 w-3.5" /> Filter</Button>
          </form>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading alerts…" />
          ) : isError ? (
            <ErrorState message="Failed to load alerts." onRetry={() => refetch()} />
          ) : !data?.items.length ? (
            <EmptyState
              title="No alerts match"
              description="Suspicious detections appear here automatically with deduplication of repeats."
              icon={<AlertTriangle className="h-6 w-6" />}
            />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Source → Destination</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Conf</TableHead>
                    <TableHead>Seen</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((a) => (
                    <TableRow key={a.id} className="cursor-pointer" onClick={() => setSelected(a)}>
                      <TableCell>
                        <Badge className={cn('ring-inset', severityClass[a.severity])}>
                          <span className={cn('mr-1 h-1.5 w-1.5 rounded-full', severityDot[a.severity])} />
                          {a.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium text-slate-200">
                        {a.attack_type}
                        {a.dedup_count > 1 && (
                          <Badge variant="secondary" className="ml-1.5 font-mono">×{a.dedup_count}</Badge>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">
                        {a.source_ip} <span className="text-slate-600">→</span> {a.destination_ip}
                        <span className="text-accent-soft">:{a.destination_port}</span>
                      </TableCell>
                      <TableCell><Badge className={cn('ring-inset', statusClass[a.status])}>{a.status}</Badge></TableCell>
                      <TableCell className="text-right font-mono text-xs">{(a.confidence * 100).toFixed(1)}%</TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-slate-500">{timeAgo(a.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                          <Button
                            size="sm" variant="ghost" aria-label="Explain"
                            title="Explain with AI"
                            onClick={() => runExplain.mutate(a)}
                            disabled={!hasRole('viewer')}
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </Button>
                          {a.status === 'New' && hasRole('analyst') && (
                            <Button size="sm" variant="secondary" onClick={() => update.mutate({ id: a.alert_id, body: { status: 'Acknowledged' } })}>
                              <Check className="h-3.5 w-3.5" /> ACK
                            </Button>
                          )}
                          <Button size="sm" variant="outline" onClick={() => setSelected(a)}>Open</Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                <span>Page {page} of {totalPages}</span>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
                  <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Alert detail / triage dialog */}
      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-2xl">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Badge className={cn('ring-inset', severityClass[selected.severity])}>{selected.severity}</Badge>
                  {selected.attack_type}
                  <Badge className={cn('ml-auto ring-inset', statusClass[selected.status])}>{selected.status}</Badge>
                </DialogTitle>
                <DialogDescription className="font-mono text-xs">
                  {selected.alert_id}
                </DialogDescription>
              </DialogHeader>
              <div className="grid grid-cols-2 gap-2.5 text-xs sm:grid-cols-3">
                {[
                  ['Source', `${selected.source_ip}`],
                  ['Destination', `${selected.destination_ip}:${selected.destination_port}`],
                  ['Protocol', selected.protocol],
                  ['Confidence', `${(selected.confidence * 100).toFixed(2)}%`],
                  ['Model', selected.model_version || '—'],
                  ['First seen', new Date(selected.first_seen_at).toLocaleString()],
                  ['Occurrences', `×${selected.dedup_count}`],
                  ['Flow ID', selected.flow_id.slice(0, 13) + '…'],
                  ['Incident', selected.incident_id ? selected.incident_id.slice(0, 8) : 'unlinked'],
                ].map(([k, v]) => (
                  <div key={k} className="rounded bg-navy-950/70 p-2.5">
                    <p className="text-[10px] uppercase tracking-wider text-slate-600">{k}</p>
                    <p className="mt-0.5 font-mono text-slate-300">{v}</p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-2">
                {(['Acknowledged', 'Investigating', 'Resolved', 'False Positive'] as AlertStatus[])
                  .filter((s) => s !== selected.status)
                  .map((s) => (
                    <Button
                      key={s}
                      size="sm"
                      variant={s === 'False Positive' ? 'ghost' : s === 'Resolved' ? 'success' : 'secondary'}
                      disabled={update.isPending || !hasRole('analyst')}
                      onClick={() => update.mutate({ id: selected.alert_id, body: { status: s } })}
                    >
                      Mark {s}
                    </Button>
                  ))}
                <Button
                  size="sm" variant="outline"
                  onClick={() => runExplain.mutate(selected)}
                  disabled={runExplain.isPending}
                >
                  <Eye className="h-3.5 w-3.5" />
                  {runExplain.isPending ? 'Explaining…' : 'Explain decision'}
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Explainability dialog */}
      <Dialog open={!!explain} onOpenChange={(o) => !o && setExplain(null)}>
        <DialogContent className="max-w-xl">
          {explain && (
            <>
              <DialogHeader>
                <DialogTitle>Why was this classified “{explain.prediction}”?</DialogTitle>
                <DialogDescription>
                  Method: <span className="font-mono">{explain.method}</span> · confidence{' '}
                  {(explain.confidence * 100).toFixed(1)}%
                </DialogDescription>
              </DialogHeader>
              <p className="rounded-lg border border-accent/25 bg-accent/5 p-3 text-sm leading-relaxed text-slate-300">
                {explain.narrative}
              </p>
              <div className="space-y-1.5">
                {explain.features.slice(0, 8).map((f) => {
                  const max = Math.max(...explain.features.map((x) => Math.abs(x.attribution)), 1e-9);
                  const pos = f.attribution >= 0;
                  return (
                    <div key={f.feature} className="flex items-center gap-2 text-xs">
                      <span className="w-48 truncate text-slate-400" title={f.feature}>{f.feature}</span>
                      <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-navy-800">
                        <div
                          className={cn('absolute top-0 h-full rounded-full', pos ? 'bg-red-500/80 left-1/2' : 'bg-emerald-500/80 right-1/2')}
                          style={{ width: `${(Math.abs(f.attribution) / max) * 50}%` }}
                        />
                        <div className="absolute left-1/2 top-0 h-full w-px bg-white/25" />
                      </div>
                      <span className={cn('w-20 text-right font-mono', pos ? 'text-red-400' : 'text-emerald-400')}>
                        {f.attribution > 0 ? '+' : ''}{f.attribution.toExponential(1)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
