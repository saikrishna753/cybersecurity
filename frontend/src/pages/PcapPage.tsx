import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { FileCheck2, FileUp, Play, ShieldCheck } from 'lucide-react';
import { api, getToken } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { EmptyState, Loading } from '@/components/ui/toast-reexports';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { fmtBytes, fmtInt, cn } from '@/lib/utils';
import type { DatasetRecord, Page } from '@/types/contract';

interface PcapResult {
  dataset_id: string;
  filename: string;
  flows_extracted: number;
  detections: number;
  malicious: number;
  alerts_created: number;
  top_attacks: Record<string, number>;
  preview: Record<string, any>[];
}

export default function PcapPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState('');
  const [result, setResult] = useState<PcapResult | null>(null);
  const [uploading, setUploading] = useState(false);

  const { data: datasets, isLoading } = useQuery<Page<DatasetRecord>>({
    queryKey: ['datasets', 'pcap'],
    queryFn: () => api.get<Page<DatasetRecord>>('/datasets?kind=pcap&size=50'),
  });

  const upload = async (file: File) => {
    setUploading(true);
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
      toast.success('PCAP uploaded', `${rec.name} (${fmtBytes(rec.size_bytes)}) — validating…`);
      qc.invalidateQueries({ queryKey: ['datasets'] });
      setSelected(rec.id);
    } catch (e: any) {
      toast.error('Upload failed', e.message);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const analyze = useMutation({
    mutationFn: () => api.post<PcapResult>('/pcap/analyze', { dataset_id: selected }),
    onSuccess: (res) => {
      setResult(res);
      toast.success('Analysis complete',
        `${res.flows_extracted} flows → ${res.malicious} malicious, ${res.alerts_created} alerts.`);
      qc.invalidateQueries({ queryKey: ['stats'] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['flows'] });
      qc.invalidateQueries({ queryKey: ['datasets'] });
    },
    onError: (e: Error) => toast.error('Analysis failed', e.message),
  });

  const pcaps = datasets?.items ?? [];
  const uploadDisabled = !hasRole('analyst');

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="page-title">PCAP Analyzer</h1>
        <p className="page-subtitle">
          Offline, read-only packet capture analysis: upload → validate → aggregate flows → classify.
          Files are never executed.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FileUp className="h-4 w-4 text-accent-soft" /> 1 · Upload PCAP</CardTitle>
            <CardDescription>Accepted: .pcap, .pcapng, .cap — size limit enforced server-side</CardDescription>
          </CardHeader>
          <CardContent>
            <label
              className={cn(
                'flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-slate-700/70 bg-navy-950/40 px-6 py-10 text-center transition hover:border-accent/50 cursor-pointer',
                uploadDisabled && 'pointer-events-none opacity-50',
              )}
            >
              <FileUp className="h-8 w-8 text-slate-600" />
              <p className="text-sm text-slate-400">
                <span className="text-accent-soft">Click to upload</span> or drop a capture here
              </p>
              <p className="text-[11px] text-slate-600">Lab / authorized captures only</p>
              <input
                ref={fileRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                disabled={uploadDisabled}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) upload(f);
                }}
              />
            </label>
            {uploading && <div className="mt-3"><Loading label="Uploading…" className="py-4" /></div>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Play className="h-4 w-4 text-emerald-400" /> 2 · Run analysis</CardTitle>
            <CardDescription>Select a stored PCAP and extract flows for classification</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {isLoading ? (
              <Loading label="Loading captures…" className="py-6" />
            ) : pcaps.length === 0 ? (
              <EmptyState title="No PCAP files yet" description="Upload a capture to begin." icon={<FileCheck2 className="h-6 w-6" />} />
            ) : (
              <Select value={selected} onValueChange={setSelected}>
                <SelectTrigger aria-label="Select PCAP"><SelectValue placeholder="Choose a PCAP file" /></SelectTrigger>
                <SelectContent>
                  {pcaps.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name} · {fmtBytes(p.size_bytes)}
                      {p.status === 'ready' ? ' ✓' : p.status === 'failed' ? ' ✗' : ' …'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Button
              className="w-full"
              disabled={!selected || analyze.isPending || !hasRole('analyst')}
              onClick={() => analyze.mutate()}
            >
              <ShieldCheck className="h-4 w-4" />
              {analyze.isPending ? 'Analyzing packets…' : 'Extract flows & classify'}
            </Button>
            {!hasRole('analyst') && (
              <p className="text-[11px] text-amber-400">Analyst or admin role required to run analysis.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {analyze.isPending && (
        <Card>
          <CardContent><Loading label="Parsing packets, aggregating flows, running inference…" /></CardContent>
        </Card>
      )}

      {result && !analyze.isPending && (
        <Card className="animate-fade-in">
          <CardHeader>
            <CardTitle>Results — {result.filename}</CardTitle>
            <CardDescription>Complete pipeline output for this capture</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              {[
                ['Flows extracted', fmtInt(result.flows_extracted), 'text-white'],
                ['Detections', fmtInt(result.detections), 'text-white'],
                ['Malicious', fmtInt(result.malicious), 'text-red-400'],
                ['Alerts created', fmtInt(result.alerts_created), 'text-amber-400'],
                ['Attack types', fmtInt(Object.keys(result.top_attacks).length), 'text-accent-soft'],
              ].map(([label, value, cls]) => (
                <div key={label} className="rounded-lg border border-white/[0.06] bg-navy-950/50 p-3 text-center">
                  <p className={cn('text-xl font-bold tabular-nums', cls)}>{value}</p>
                  <p className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
                </div>
              ))}
            </div>

            {Object.keys(result.top_attacks).length > 0 && (
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.top_attacks).map(([k, v]) => (
                  <Badge key={k} variant="destructive" className="ring-inset">
                    {k}: {v}
                  </Badge>
                ))}
              </div>
            )}

            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Flow</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Proto</TableHead>
                  <TableHead className="text-right">Duration</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.preview.map((f) => (
                  <TableRow key={f.flow_id}>
                    <TableCell className="font-mono text-[11px] text-slate-600">{String(f.flow_id).slice(0, 8)}…</TableCell>
                    <TableCell className="font-mono text-xs">{f.src_ip}</TableCell>
                    <TableCell className="font-mono text-xs">{f.dst_ip}:{f.dst_port}</TableCell>
                    <TableCell><Badge variant="secondary">{f.protocol}</Badge></TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {Number(f.flow_duration).toFixed(4)}s
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
