import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Download, FileBarChart, FileSpreadsheet, FileText, RefreshCw } from 'lucide-react';
import { api, getToken } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { EmptyState, Loading } from '@/components/ui/toast-reexports';
import { fmtBytes, timeAgo, cn } from '@/lib/utils';

interface ReportItem {
  filename: string;
  url: string;
  size_bytes: number;
  generated_at: string;
  format: string;
}

export default function ReportsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const [type, setType] = useState('daily');
  const [format, setFormat] = useState('pdf');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  const { data, isLoading, refetch, isFetching } = useQuery<{ items: ReportItem[] }>({
    queryKey: ['reports'],
    queryFn: () => api.get<{ items: ReportItem[] }>('/reports/list'),
  });

  const generate = useMutation({
    mutationFn: async () => {
      const body: Record<string, any> = { report_type: type, format };
      if (from) body.date_from = new Date(from).toISOString();
      if (to) body.date_to = new Date(to).toISOString();
      const rep = await api.post<{ filename: string; url: string; rows: number | null }>('/reports/generate', body);
      // immediately trigger download
      const res = await fetch(`/api${rep.url.replace('/api', '')}`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (res.ok) {
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = rep.filename;
        a.click();
        URL.revokeObjectURL(a.href);
      }
      return rep;
    },
    onSuccess: (rep) => {
      toast.success('Report generated', rep.filename);
      refetch();
    },
    onError: (e: Error) => toast.error('Report failed', e.message),
  });

  const download = async (item: ReportItem) => {
    try {
      const res = await fetch(`/api${item.url.replace('/api', '')}`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = item.filename;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e: any) {
      toast.error('Download failed', e.message);
    }
  };

  const items = data?.items ?? [];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">
            PDF and CSV exports generated from live database records with charts, tables and
            measured model metrics.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><FileBarChart className="h-4 w-4 text-accent-soft" /> Generate report</CardTitle>
          <CardDescription>Choose type, optional date range, and export format</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-4">
            <div className="space-y-1.5">
              <Label>Report type</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily summary</SelectItem>
                  <SelectItem value="weekly">Weekly summary</SelectItem>
                  <SelectItem value="investigation">Attack investigation</SelectItem>
                  <SelectItem value="custom">Custom range</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Format</Label>
              <Select value={format} onValueChange={setFormat}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="pdf">PDF (charts + tables)</SelectItem>
                  <SelectItem value="csv">CSV (alert rows)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rep-from">From (optional)</Label>
              <Input id="rep-from" type="date" value={from} onChange={(e) => setFrom(e.target.value)} className="text-xs" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rep-to">To (optional)</Label>
              <Input id="rep-to" type="date" value={to} onChange={(e) => setTo(e.target.value)} className="text-xs" />
            </div>
          </div>
          <Button
            className="mt-3"
            onClick={() => generate.mutate()}
            disabled={generate.isPending || !hasRole('analyst')}
          >
            <Download className="h-4 w-4" />
            {generate.isPending ? 'Generating…' : 'Generate & download'}
          </Button>
          {!hasRole('analyst') && (
            <p className="mt-2 text-[11px] text-amber-400">Analyst or admin role required.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><FileText className="h-4 w-4 text-accent-soft" /> Generated reports</CardTitle>
          <CardDescription>Stored server-side, downloadable any time</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading reports…" />
          ) : items.length === 0 ? (
            <EmptyState
              title="No reports yet"
              description="Generate your first daily summary above."
              icon={<FileText className="h-6 w-6" />}
            />
          ) : (
            <div className="space-y-2">
              {items.map((r) => (
                <div
                  key={r.filename}
                  className="flex flex-wrap items-center gap-3 rounded-lg border border-white/[0.05] bg-navy-950/40 px-3 py-2.5 text-xs"
                >
                  {r.format === 'pdf' ? (
                    <FileText className="h-4 w-4 text-red-400" />
                  ) : (
                    <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
                  )}
                  <span className="font-mono text-slate-300">{r.filename}</span>
                  <Badge variant="secondary" className="uppercase">{r.format}</Badge>
                  <span className="text-slate-600">{fmtBytes(r.size_bytes)}</span>
                  <span className="ml-auto text-slate-500">{timeAgo(r.generated_at)}</span>
                  <Button size="sm" variant="outline" onClick={() => download(r)}>
                    <Download className="h-3.5 w-3.5" /> Download
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
