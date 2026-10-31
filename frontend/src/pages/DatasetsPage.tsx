import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { Database, FileSpreadsheet, RefreshCw, Trash2, Upload } from 'lucide-react';
import { api, getToken } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { fmtBytes, fmtInt, timeAgo, cn } from '@/lib/utils';
import type { DatasetRecord, Page } from '@/types/contract';

const statusVariant: Record<string, 'success' | 'warning' | 'destructive' | 'secondary'> = {
  ready: 'success',
  validated: 'success',
  uploaded: 'secondary',
  analyzing: 'warning',
  failed: 'destructive',
};

export default function DatasetsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState<DatasetRecord | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Page<DatasetRecord>>({
    queryKey: ['datasets', 'csv'],
    queryFn: () => api.get<Page<DatasetRecord>>('/datasets?size=50'),
    refetchInterval: 10_000,
  });

  const upload = async (file: File) => {
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/datasets/upload', {
        method: 'POST',
        headers: { Authorization: `Bearer ${getToken()}` },
        body: fd,
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail ?? `HTTP ${res.status}`);
      }
      const rec = (await res.json()) as DatasetRecord;
      toast.success('Dataset uploaded', `${rec.name} queued for validation.`);
      qc.invalidateQueries({ queryKey: ['datasets'] });
    } catch (e: any) {
      toast.error('Upload failed', e.message);
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const analyze = useMutation({
    mutationFn: (id: string) => api.post<{ report: any; class_balance_pct: Record<string, number> }>(`/datasets/${id}/analyze`),
    onSuccess: (res) => {
      toast.success('Dataset analyzed', `Cleaned rows: ${fmtInt(res.report.rows_out)}`);
      setDetail(null);
      qc.invalidateQueries({ queryKey: ['datasets'] });
    },
    onError: (e: Error) => toast.error('Analysis failed', e.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/datasets/${id}`),
    onSuccess: () => {
      toast.info('Dataset deleted');
      qc.invalidateQueries({ queryKey: ['datasets'] });
    },
    onError: (e: Error) => toast.error('Delete failed', e.message),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Dataset Management</h1>
          <p className="page-subtitle">
            Upload labeled CIC-IDS2017-style CSVs for training, or PCAP captures for analysis.
            Uploads are validated, size-limited and never executed.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
          </Button>
          <Button size="sm" disabled={busy || !hasRole('analyst')} onClick={() => fileRef.current?.click()}>
            <Upload className="h-3.5 w-3.5" /> Upload dataset
          </Button>
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) upload(f);
            }}
          />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Database className="h-4 w-4 text-accent-soft" /> Stored datasets</CardTitle>
          <CardDescription>CSV files feed the training pipeline; PCAP files feed the packet analyzer</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading datasets…" />
          ) : isError ? (
            <ErrorState message="Failed to load datasets." onRetry={() => refetch()} />
          ) : items.length === 0 ? (
            <EmptyState
              title="No datasets uploaded"
              description="Upload the CIC-IDS2017 CSV exports (e.g. Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv) to enable model training."
              icon={<FileSpreadsheet className="h-6 w-6" />}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead className="text-right">Rows</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Uploaded</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="max-w-[240px] truncate font-medium text-slate-200">{d.name}</TableCell>
                    <TableCell><Badge variant={d.kind === 'csv' ? 'default' : 'secondary'}>{d.kind.toUpperCase()}</Badge></TableCell>
                    <TableCell className="text-right font-mono text-xs">{fmtBytes(d.size_bytes)}</TableCell>
                    <TableCell className="text-right font-mono text-xs">{d.rows != null ? fmtInt(d.rows) : '—'}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[d.status] ?? 'secondary'} className="ring-inset">
                        {d.status}
                      </Badge>
                      {d.error && <p className="mt-0.5 max-w-[180px] truncate text-[10px] text-red-400">{d.error}</p>}
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">{timeAgo(d.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1.5">
                        {d.kind === 'csv' && hasRole('analyst') && (
                          <Button size="sm" variant="secondary" onClick={() => setDetail(d)}>Profile</Button>
                        )}
                        {hasRole('admin') && (
                          <Button
                            size="sm" variant="ghost"
                            aria-label="Delete"
                            className="text-slate-500 hover:text-red-400"
                            onClick={() => remove.mutate(d.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Dataset profile — {detail?.name}</DialogTitle>
            <DialogDescription>
              Validation report: duplicates removed, label balance, feature count.
            </DialogDescription>
          </DialogHeader>
          {detail && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="rounded bg-navy-950/60 p-2.5">
                  <p className="text-slate-500">Stored rows</p>
                  <p className="text-lg font-semibold text-white">{detail.rows != null ? fmtInt(detail.rows) : '—'}</p>
                </div>
                <div className="rounded bg-navy-950/60 p-2.5">
                  <p className="text-slate-500">Status</p>
                  <p className="text-lg font-semibold text-white">{detail.status}</p>
                </div>
              </div>
              {detail.label_distribution && (
                <div>
                  <p className="mb-1.5 text-xs font-medium text-slate-400">Label distribution (sampled)</p>
                  <div className="max-h-40 space-y-1 overflow-y-auto rounded bg-navy-950/60 p-2.5">
                    {Object.entries(detail.label_distribution)
                      .sort((a, b) => b[1] - a[1])
                      .map(([label, count]) => (
                        <div key={label} className="flex items-center justify-between text-xs">
                          <span className={cn(label.toUpperCase() === 'BENIGN' ? 'text-emerald-400' : 'text-red-400')}>{label}</span>
                          <span className="font-mono text-slate-500">{fmtInt(count)}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
              <Button
                className="w-full"
                disabled={analyze.isPending}
                onClick={() => analyze.mutate(detail.id)}
              >
                {analyze.isPending ? 'Profiling…' : 'Run full validation & profiling'}
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
