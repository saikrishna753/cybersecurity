import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Activity, Award, Cpu, Play, RefreshCw, TrendingUp } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { fmtInt, timeAgo, cn } from '@/lib/utils';
import type { MlModel, Page, TrainingJob } from '@/types/contract';

const ALGO_LABEL: Record<string, string> = {
  decision_tree: 'Decision Tree',
  random_forest: 'Random Forest',
  xgboost: 'XGBoost',
  isolation_forest: 'Isolation Forest',
};

function Metric({ label, value, tone }: { label: string; value?: number | null; tone?: 'good' | 'warn' | 'bad' }) {
  const cls = tone === 'good' ? 'text-emerald-400' : tone === 'bad' ? 'text-red-400' : tone === 'warn' ? 'text-amber-400' : 'text-white';
  return (
    <div className="rounded bg-navy-950/70 p-2 text-center">
      <p className={cn('text-base font-bold tabular-nums', cls)}>
        {value == null || Number.isNaN(value) ? '—' : value.toFixed(4)}
      </p>
      <p className="text-[9px] uppercase tracking-wider text-slate-600">{label}</p>
    </div>
  );
}

export default function ModelsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [trainOpen, setTrainOpen] = useState(false);
  const [detail, setDetail] = useState<MlModel | null>(null);

  const { data: models, isLoading, isError, refetch, isFetching } = useQuery<Page<MlModel>>({
    queryKey: ['models'],
    queryFn: () => api.get<Page<MlModel>>('/models?size=50'),
    refetchInterval: 15_000,
  });

  const { data: jobs } = useQuery<Page<TrainingJob>>({
    queryKey: ['training-jobs'],
    queryFn: () => api.get<Page<TrainingJob>>('/models/training-jobs?size=10'),
    refetchInterval: 4_000,
  });

  const { data: registryInfo } = useQuery<Record<string, any>>({
    queryKey: ['registry'],
    queryFn: () => api.get('/models/registry'),
    refetchInterval: 15_000,
  });

  const train = useMutation({
    mutationFn: () =>
      api.post<{ job_id: string }>('/models/train', {
        task: 'multiclass',
        algorithms: ['decision_tree', 'random_forest', 'xgboost', 'isolation_forest'],
        max_rows: 300000,
        activate_best: true,
      }),
    onSuccess: (res) => {
      toast.success('Training job queued', `Job ${res.job_id.slice(0, 8)} — progress below.`);
      setTrainOpen(false);
      qc.invalidateQueries({ queryKey: ['training-jobs'] });
    },
    onError: (e: Error) => toast.error('Could not start training', e.message),
  });

  const activate = useMutation({
    mutationFn: (id: string) => api.post<MlModel>(`/models/${id}/activate`),
    onSuccess: (m) => {
      toast.success('Model activated', `${ALGO_LABEL[m.algorithm] ?? m.algorithm} v${m.version}`);
      qc.invalidateQueries({ queryKey: ['models'] });
      qc.invalidateQueries({ queryKey: ['registry'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
    onError: (e: Error) => toast.error('Activation failed', e.message),
  });

  const items = models?.items ?? [];
  const activeJob = jobs?.items?.find((j) => j.status === 'running' || j.status === 'pending');

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">ML Model Management</h1>
          <p className="page-subtitle">
            Train, evaluate and activate classifiers — metrics shown are measured on a held-out test set.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
          </Button>
          <Button size="sm" disabled={!hasRole('analyst') || !!activeJob} onClick={() => setTrainOpen(true)}>
            <Play className="h-3.5 w-3.5" /> Train new models
          </Button>
        </div>
      </div>

      {/* active registry */}
      <div className="grid gap-3 sm:grid-cols-3">
        {(['binary', 'multiclass', 'anomaly'] as const).map((slot) => {
          const m = registryInfo?.[slot];
          return (
            <Card key={slot}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500">{slot} slot</p>
                  {m && <Badge variant="success" className="ring-inset">loaded</Badge>}
                </div>
                {m ? (
                  <div className="mt-2">
                    <p className="font-mono text-sm text-white">{m.name}</p>
                    <p className="mt-0.5 text-[11px] text-slate-500">v{m.version} · {m.feature_count} features</p>
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-slate-600">No model loaded</p>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* training job progress */}
      {activeJob && (
        <Card className="border-accent/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-accent-soft">
              <TrendingUp className="h-4 w-4 animate-pulse" /> Training in progress
            </CardTitle>
            <CardDescription>
              Job {activeJob.id.slice(0, 8)} · {activeJob.stage} · {activeJob.task}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-2 overflow-hidden rounded-full bg-navy-800">
              <div className="h-full rounded-full bg-gradient-to-r from-accent to-emerald-400 transition-all" style={{ width: `${activeJob.progress}%` }} />
            </div>
            <p className="mt-1.5 text-right text-xs tabular-nums text-slate-500">{activeJob.progress}%</p>
          </CardContent>
        </Card>
      )}
      {jobs?.items?.filter((j) => j.status === 'failed').slice(0, 1).map((j) => (
        <Card key={j.id} className="border-red-500/30">
          <CardContent className="p-4 text-xs text-red-300">
            <strong>Training job failed:</strong> {j.error}
          </CardContent>
        </Card>
      ))}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Cpu className="h-4 w-4 text-accent-soft" /> Registered models</CardTitle>
          <CardDescription>{models ? `${models.total} model artifacts` : '…'}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading models…" />
          ) : isError ? (
            <ErrorState message="Failed to load models." onRetry={() => refetch()} />
          ) : items.length === 0 ? (
            <EmptyState
              title="No models registered"
              description="Upload CIC-IDS2017 CSVs, then start a training run."
              icon={<Cpu className="h-6 w-6" />}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead>Task</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead className="text-right">Accuracy</TableHead>
                  <TableHead className="text-right">F1</TableHead>
                  <TableHead className="text-right">FPR</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((m) => {
                  const acc = m.metrics?.accuracy as number | undefined;
                  const f1 = (m.metrics?.f1 ?? m.metrics?.f1_macro) as number | undefined;
                  const fpr = m.metrics?.fpr as number | undefined;
                  return (
                    <TableRow key={m.id} className="cursor-pointer" onClick={() => setDetail(m)}>
                      <TableCell className="font-medium text-slate-200">
                        {ALGO_LABEL[m.algorithm] ?? m.algorithm}
                        <span className="ml-1.5 font-mono text-[10px] text-slate-600">{m.feature_count} feats</span>
                      </TableCell>
                      <TableCell><Badge variant="secondary">{m.task}</Badge></TableCell>
                      <TableCell className="font-mono text-xs text-slate-500">{m.version}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{acc != null ? acc.toFixed(4) : '—'}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{f1 != null ? f1.toFixed(4) : '—'}</TableCell>
                      <TableCell className={cn('text-right font-mono text-xs', fpr != null && fpr > 0.05 ? 'text-red-400' : 'text-emerald-400')}>
                        {fpr != null ? fpr.toFixed(4) : '—'}
                      </TableCell>
                      <TableCell>
                        {m.is_active ? (
                          <Badge variant="success" className="ring-inset"><Award className="mr-1 h-3 w-3" />active</Badge>
                        ) : (
                          <Badge variant="outline">standby</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        {!m.is_active && hasRole('analyst') && (
                          <Button size="sm" variant="secondary" onClick={() => activate.mutate(m.id)} disabled={activate.isPending}>
                            Activate
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

      {/* train dialog */}
      <Dialog open={trainOpen} onOpenChange={setTrainOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Start training run</DialogTitle>
            <DialogDescription>
              Trains Decision Tree, Random Forest, XGBoost and Isolation Forest on all uploaded CSV
              datasets with one consistent holdout split (multiclass labels). Best F1 model is
              activated automatically.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300">
            Requires at least one uploaded CSV dataset (Dataset Management). Large datasets are
            subsampled to 300k rows for tractable training on this host.
          </div>
          <Button onClick={() => train.mutate()} disabled={train.isPending}>
            {train.isPending ? 'Queueing…' : 'Start training'}
          </Button>
        </DialogContent>
      </Dialog>

      {/* metrics detail */}
      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-w-2xl">
          {detail && (
            <>
              <DialogHeader>
                <DialogTitle>
                  {ALGO_LABEL[detail.algorithm] ?? detail.algorithm} · {detail.task}
                </DialogTitle>
                <DialogDescription className="font-mono">
                  {detail.name} v{detail.version} · created {timeAgo(detail.created_at)}
                </DialogDescription>
              </DialogHeader>
              <div className="grid grid-cols-3 gap-2">
                <Metric label="Accuracy" value={detail.metrics?.accuracy} tone="good" />
                <Metric label="Precision" value={detail.metrics?.precision ?? detail.metrics?.precision_macro} />
                <Metric label="Recall" value={detail.metrics?.recall ?? detail.metrics?.recall_macro} />
                <Metric label="F1" value={detail.metrics?.f1 ?? detail.metrics?.f1_macro} tone="good" />
                <Metric label="FPR" value={detail.metrics?.fpr} tone={detail.metrics?.fpr > 0.05 ? 'bad' : 'good'} />
                <Metric label="ROC-AUC" value={detail.metrics?.roc_auc ?? detail.metrics?.roc_auc_ovr_macro} />
              </div>
              {detail.metrics?.confusion_matrix && (
                <div>
                  <p className="mb-1.5 text-xs font-medium text-slate-400">Confusion matrix (test set)</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-center text-[11px] font-mono">
                      <tbody>
                        {detail.metrics.confusion_matrix.map((row: number[], i: number) => (
                          <tr key={i}>
                            {row.map((v: number, j: number) => (
                              <td
                                key={j}
                                className={cn(
                                  'border border-white/[0.06] px-2 py-1.5',
                                  i === j ? 'bg-emerald-500/15 text-emerald-300' : 'bg-navy-950/60 text-slate-400',
                                )}
                              >
                                {fmtInt(v)}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {detail.metrics?.classification_report && typeof detail.metrics.classification_report === 'object' && (
                <div>
                  <p className="mb-1.5 text-xs font-medium text-slate-400">Per-class report</p>
                  <div className="max-h-52 overflow-y-auto rounded bg-navy-950/60 p-2">
                    <table className="w-full text-[11px]">
                      <thead>
                        <tr className="text-left text-slate-600">
                          <th className="px-1.5 py-1">Class</th>
                          <th className="px-1.5 py-1 text-right">Precision</th>
                          <th className="px-1.5 py-1 text-right">Recall</th>
                          <th className="px-1.5 py-1 text-right">F1</th>
                          <th className="px-1.5 py-1 text-right">Support</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(detail.metrics.classification_report as Record<string, any>)
                          .filter(([k]) => !['accuracy', 'macro avg', 'weighted avg'].includes(k))
                          .map(([cls, m]) => (
                            <tr key={cls} className="border-t border-white/[0.04] text-slate-400">
                              <td className="px-1.5 py-1 font-medium text-slate-300">{cls}</td>
                              <td className="px-1.5 py-1 text-right">{typeof m.precision === 'number' ? m.precision.toFixed(3) : '—'}</td>
                              <td className="px-1.5 py-1 text-right">{typeof m.recall === 'number' ? m.recall.toFixed(3) : '—'}</td>
                              <td className="px-1.5 py-1 text-right">{typeof m['f1-score'] === 'number' ? m['f1-score'].toFixed(3) : '—'}</td>
                              <td className="px-1.5 py-1 text-right">{m.support}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {detail.metrics?.note && (
                <p className="text-[11px] italic text-slate-500">{detail.metrics.note}</p>
              )}
              <p className="flex items-center gap-1.5 text-[10px] text-slate-600">
                <Activity className="h-3 w-3" /> Metrics measured on the held-out test split at
                training time — not recomputed or adjusted.
              </p>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
