import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Eye, Radar, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { severityClass, severityDot } from '@/lib/tokens';
import { fmtInt, timeAgo, cn } from '@/lib/utils';
import type { DetectionResult, ExplainResponse, Page } from '@/types/contract';

export default function DetectionPage() {
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState('all');
  const [explain, setExplain] = useState<ExplainResponse | null>(null);

  const params = new URLSearchParams({ page: String(page), size: '20' });
  if (filter === 'malicious') params.set('malicious', 'true');
  if (filter === 'benign') params.set('malicious', 'false');

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Page<DetectionResult>>({
    queryKey: ['detections', filter, page],
    queryFn: () => api.get<Page<DetectionResult>>(`/predict/detections?${params}`),
    refetchInterval: 15_000,
  });

  const explainMut = useMutation({
    mutationFn: (id: string) =>
      api.post<ExplainResponse>('/explain/prediction', { detection_id: id, top_k: 8 }),
    onSuccess: setExplain,
    onError: (e: Error) => toast.error('Explanation failed', e.message),
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.size)) : 1;

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Attack Detection</h1>
          <p className="page-subtitle">
            Classification results from the active model — confidence values are model scores, not
            calibrated probabilities.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {[
          ['all', 'All detections'],
          ['malicious', 'Malicious only'],
          ['benign', 'Benign only'],
        ].map(([v, label]) => (
          <button
            key={v}
            onClick={() => { setFilter(v); setPage(1); }}
            className={cn(
              'rounded-full px-3 py-1 text-xs ring-1 transition',
              filter === v
                ? 'bg-accent/20 text-accent-soft ring-accent/50'
                : 'text-slate-500 ring-white/10 hover:bg-navy-800 hover:text-slate-300',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Radar className="h-4 w-4 text-accent-soft" /> Detection stream</CardTitle>
          <CardDescription>{data ? `${fmtInt(data.total)} detections` : '…'}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading detections…" />
          ) : isError ? (
            <ErrorState message="Failed to load detections." onRetry={() => refetch()} />
          ) : !data?.items.length ? (
            <EmptyState
              title="No detections yet"
              description="Run a PCAP analysis, live capture, or use the API prediction endpoint to generate detections."
              icon={<Radar className="h-6 w-6" />}
            />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Prediction</TableHead>
                    <TableHead>Flow</TableHead>
                    <TableHead>Malicious</TableHead>
                    <TableHead className="text-right">Confidence</TableHead>
                    <TableHead className="text-right">Anomaly</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Model</TableHead>
                    <TableHead className="text-right">Explain</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((d) => (
                    <TableRow key={d.id ?? d.flow_id}>
                      <TableCell className="whitespace-nowrap text-xs text-slate-500">
                        {d.timestamp ? timeAgo(d.timestamp) : '—'}
                      </TableCell>
                      <TableCell className={cn('font-medium', d.is_malicious ? 'text-red-400' : 'text-emerald-400')}>
                        {d.prediction}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-slate-600">{d.flow_id.slice(0, 8)}…</TableCell>
                      <TableCell>
                        {d.is_malicious ? (
                          <Badge variant="destructive" className="ring-inset">YES</Badge>
                        ) : (
                          <Badge variant="success" className="ring-inset">no</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <div className="h-1.5 w-12 overflow-hidden rounded-full bg-navy-800">
                            <div className="h-full bg-accent" style={{ width: `${Math.min(d.confidence * 100, 100)}%` }} />
                          </div>
                          <span className="font-mono text-xs">{(d.confidence * 100).toFixed(1)}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-slate-500">
                        {d.anomaly_score != null ? d.anomaly_score.toFixed(3) : '—'}
                      </TableCell>
                      <TableCell>
                        <Badge className={cn('ring-inset', severityClass[d.severity])}>
                          <span className={cn('mr-1 h-1.5 w-1.5 rounded-full', severityDot[d.severity])} />
                          {d.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-[10px] text-slate-600">{d.model_version}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm" variant="ghost" aria-label="Explain detection"
                          onClick={() => explainMut.mutate(d.id!)}
                          disabled={!d.id || explainMut.isPending}
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
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

      <Dialog open={!!explain} onOpenChange={(o) => !o && setExplain(null)}>
        <DialogContent className="max-w-xl">
          {explain && (
            <>
              <DialogHeader>
                <DialogTitle>AI explanation — {explain.prediction}</DialogTitle>
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
