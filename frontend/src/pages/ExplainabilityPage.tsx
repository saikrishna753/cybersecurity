import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { BrainCircuit, RefreshCw, Sparkles } from 'lucide-react';
import { api } from '@/lib/api';
import type { DetectionResult, ExplainResponse, GlobalImportance, Page } from '@/types/contract';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { cn, fmtInt } from '@/lib/utils';

const tooltipStyle = {
  backgroundColor: '#0d1529', border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8, fontSize: 12, color: '#e2e8f0',
};

export default function ExplainabilityPage() {
  const [selected, setSelected] = useState<string>('');
  const [selectedLabel, setSelectedLabel] = useState<string>('');

  const { data: detections, isLoading: dLoading, isError, refetch, isFetching } = useQuery<Page<DetectionResult>>({
    queryKey: ['detections', 'explain-pool'],
    queryFn: () => api.get<Page<DetectionResult>>('/predict/detections?size=50&malicious=true'),
    refetchInterval: 30_000,
  });

  const { data: global, isLoading: gLoading, refetch: refetchGlobal } = useQuery<GlobalImportance>({
    queryKey: ['explain', 'global'],
    queryFn: () => api.get<GlobalImportance>('/explain/global?top_k=15'),
  });

  const { data: local, isLoading: lLoading } = useQuery<ExplainResponse>({
    queryKey: ['explain', 'local', selected],
    queryFn: () => api.post<ExplainResponse>('/explain/prediction', { detection_id: selected, top_k: 8 }),
    enabled: !!selected,
  });

  const items = detections?.items ?? [];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">AI Explainability</h1>
          <p className="page-subtitle">
            SHAP-based attributions for individual predictions plus global feature importance —
            why the model decided what it decided.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => { refetch(); refetchGlobal(); }} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Global importance */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-accent-soft" />
              Global feature importance
            </CardTitle>
            <CardDescription>
              {global ? (
                <>
                  Method <span className="font-mono">{global.method}</span> · model{' '}
                  <span className="font-mono">{global.model_version || '—'}</span>
                </>
              ) : '…'}
            </CardDescription>
          </CardHeader>
          <CardContent className="h-80">
            {gLoading ? (
              <Loading label="Computing importance…" />
            ) : !global?.features.length ? (
              <EmptyState
                title="No model importance available"
                description="Train and activate a tree-based model first."
                icon={<Sparkles className="h-6 w-6" />}
              />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={[...global.features].reverse()}
                  layout="vertical"
                  margin={{ left: 8, right: 16, top: 4, bottom: 4 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis
                    type="category"
                    dataKey="feature"
                    width={150}
                    tick={{ fontSize: 10, fill: '#94a3b8' }}
                    interval={0}
                  />
                  <Tooltip
                    contentStyle={tooltipStyle}
                    formatter={(v: number) => [v.toFixed(5), 'importance']}
                  />
                  <Bar dataKey="importance" fill="#3b82f6" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Local explanation */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-purple-400" />
              Per-detection explanation
            </CardTitle>
            <CardDescription>Pick a malicious detection to see its attributions</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Select
                value={selected}
                onValueChange={(v) => {
                  setSelected(v);
                  const opt = items.find((d) => d.id === v);
                  setSelectedLabel(opt ? `${opt.prediction} · ${new Date(opt.timestamp ?? Date.now()).toLocaleTimeString()}` : '');
                }}
              >
                <SelectTrigger aria-label="Select detection">
                  <SelectValue placeholder={dLoading ? 'Loading…' : 'Select a detection…'} />
                </SelectTrigger>
                <SelectContent>
                  {items.map((d) => (
                    <SelectItem key={d.id} value={d.id!}>
                      {d.prediction} · conf {(d.confidence * 100).toFixed(1)}% · {d.id!.slice(0, 8)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {items.length === 0 && !dLoading && (
              <EmptyState
                title="No malicious detections"
                description="Generate detections first (PCAP analysis / prediction)."
              />
            )}

            {lLoading && <Loading label="Computing SHAP attributions…" />}

            {local && !lLoading && (
              <div className="space-y-3 animate-fade-in">
                <div className="flex items-center gap-2">
                  <Badge variant="destructive" className="ring-inset">{local.prediction}</Badge>
                  <span className="text-xs text-slate-500">
                    method <span className="font-mono text-accent-soft">{local.method}</span>
                  </span>
                </div>
                <p className="rounded-lg border border-accent/25 bg-accent/5 p-3 text-sm leading-relaxed text-slate-300">
                  {local.narrative}
                </p>
                <div className="space-y-1.5">
                  {local.features.map((f) => {
                    const max = Math.max(...local.features.map((x) => Math.abs(x.attribution)), 1e-9);
                    const pos = f.attribution >= 0;
                    return (
                      <div key={f.feature} className="flex items-center gap-2 text-xs">
                        <span className="w-44 truncate text-slate-400" title={f.feature}>{f.feature}</span>
                        <span className="w-20 text-right font-mono text-slate-600">
                          {f.value != null ? fmtInt(Math.round(f.value)) : '—'}
                        </span>
                        <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-navy-800">
                          <div
                            className={cn('absolute top-0 h-full rounded-full', pos ? 'bg-red-500/80 left-1/2' : 'bg-emerald-500/80 right-1/2')}
                            style={{ width: `${(Math.abs(f.attribution) / max) * 50}%` }}
                          />
                          <div className="absolute left-1/2 top-0 h-full w-px bg-white/25" />
                        </div>
                        <span className={cn('w-16 text-right font-mono', pos ? 'text-red-400' : 'text-emerald-400')}>
                          {f.attribution > 0 ? '+' : ''}{f.attribution.toExponential(1)}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <p className="text-[10px] text-slate-600">
                  Red = pushes toward the predicted class · green = pushes away. Attribution
                  direction depends on the method shown.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>How to read these explanations</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 text-xs leading-relaxed text-slate-500 sm:grid-cols-3">
          <div className="rounded-lg border border-white/[0.06] bg-navy-950/50 p-3">
            <p className="font-medium text-slate-400">SHAP (TreeExplainer)</p>
            <p className="mt-1">Exact additive attributions for tree ensembles. Preferred when the active model is a Decision Tree, Random Forest or XGBoost.</p>
          </div>
          <div className="rounded-lg border border-white/[0.06] bg-navy-950/50 p-3">
            <p className="font-medium text-slate-400">Perturbation</p>
            <p className="mt-1">Model-agnostic fallback: feature contribution estimated by zeroing each feature and observing the score change.</p>
          </div>
          <div className="rounded-lg border border-white/[0.06] bg-navy-950/50 p-3">
            <p className="font-medium text-slate-400">Tree importance fallback</p>
            <p className="mt-1">Global impurity-based importance when neither SHAP nor perturbation is possible; labeled clearly in the UI.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
