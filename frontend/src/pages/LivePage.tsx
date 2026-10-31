import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import {
  CircleStop, MonitorPlay, Network, PlayCircle, Radio, RefreshCw, ServerOff,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { fmtInt, timeAgo, cn } from '@/lib/utils';
import type { NetworkFlow, Page } from '@/types/contract';

interface CaptureStatus {
  running: boolean;
  interface: string | null;
  started_at: string | null;
  packets_captured: number;
  flows_emitted: number;
  queue_size: number;
  error: string | null;
  mode: 'offline' | 'live';
}
interface Iface {
  name: string;
  description: string;
  is_up: boolean;
  is_authorized: boolean;
  capture_permission: string;
}

export default function LivePage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [iface, setIface] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [bpf, setBpf] = useState('');

  const { data: status, isLoading: statusLoading } = useQuery<CaptureStatus>({
    queryKey: ['capture'],
    queryFn: () => api.get<CaptureStatus>('/monitoring/capture/status'),
    refetchInterval: 5_000,
  });

  const { data: ifaces, isLoading: ifacesLoading, isError: ifacesError, refetch: refetchIfaces } = useQuery<Iface[]>({
    queryKey: ['interfaces'],
    queryFn: () => api.get<Iface[]>('/monitoring/interfaces'),
    enabled: hasRole('admin'),
    retry: 0,
  });

  const { data: flows, isLoading: flowsLoading, isError: flowsError, refetch: refetchFlows } = useQuery<Page<NetworkFlow>>({
    queryKey: ['flows', 'live'],
    queryFn: () => api.get<Page<NetworkFlow>>('/monitoring/flows?size=25&source=live'),
    refetchInterval: status?.running ? 6_000 : 15_000,
  });

  const authorize = useMutation({
    mutationFn: (name: string) => api.post<Iface>(`/monitoring/interfaces/${encodeURIComponent(name)}/authorize`),
    onSuccess: () => {
      toast.success('Interface authorized', 'Administrator authorization recorded in the audit log.');
      refetchIfaces();
    },
    onError: (e: Error) => toast.error('Authorization failed', e.message),
  });

  const start = useMutation({
    mutationFn: () =>
      api.post<CaptureStatus>('/monitoring/capture/start', {
        interface: iface, authorized: authorized || undefined, bpf_filter: bpf, batch_size: 100,
      }),
    onSuccess: (res) => {
      if (res.mode === 'live') {
        toast.success('Live capture started', `Capturing on ${res.interface}.`);
      } else {
        toast.warning('Capture unavailable — offline mode', res.error ?? 'Permission or dependency missing.');
      }
      qc.invalidateQueries({ queryKey: ['capture'] });
    },
    onError: (e: Error) => toast.error('Failed to start capture', e.message),
  });

  const stop = useMutation({
    mutationFn: () => api.post<CaptureStatus>('/monitoring/capture/stop'),
    onSuccess: () => {
      toast.info('Capture stopped');
      qc.invalidateQueries({ queryKey: ['capture'] });
    },
    onError: (e: Error) => toast.error('Stop failed', e.message),
  });

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="page-title">Live Network Monitoring</h1>
        <p className="page-subtitle">
          Authorized real-time capture with bounded batching — falls back gracefully when packet
          capture permissions are unavailable.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-accent-soft" /> Capture control
            </CardTitle>
            <CardDescription>Requires an administrator-authorized interface</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {statusLoading ? (
              <Loading label="Reading capture status…" />
            ) : (
              <div
                className={cn(
                  'flex items-center justify-between rounded-lg border px-3 py-2.5 text-xs',
                  status?.running
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                    : 'border-slate-700/70 bg-navy-950/60 text-slate-500',
                )}
              >
                <span className="flex items-center gap-2">
                  {status?.running ? <Radio className="h-3.5 w-3.5 animate-pulse" /> : <ServerOff className="h-3.5 w-3.5" />}
                  {status?.running ? `Live on ${status.interface}` : 'Offline mode'}
                </span>
                <span className="font-mono text-[10px]">
                  {status?.running ? `${fmtInt(status.packets_captured)} pkts` : 'PCAP/CSV only'}
                </span>
              </div>
            )}

            {status?.error && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-300">
                {status.error}
              </div>
            )}

            <div className="space-y-1.5">
              <Label>Interface</Label>
              <Select value={iface} onValueChange={setIface}>
                <SelectTrigger aria-label="Interface">
                  <SelectValue placeholder={ifacesLoading ? 'Loading…' : 'Select interface'} />
                </SelectTrigger>
                <SelectContent>
                  {(ifaces ?? []).map((i) => (
                    <SelectItem key={i.name} value={i.name}>
                      {i.name} {i.is_up ? '🟢' : '⚪'} {i.is_authorized ? '· authorized' : ''}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {ifacesError && (
                <p className="text-[11px] text-amber-400">Interface enumeration needs admin role.</p>
              )}
            </div>

            {iface && ifaces?.find((i) => i.name === iface) && !ifaces.find((i) => i.name === iface)?.is_authorized && (
              <div className="flex items-center justify-between rounded-lg border border-accent/30 bg-accent/10 px-3 py-2.5">
                <div>
                  <Label htmlFor="authz" className="text-accent-soft">Monitor authorization</Label>
                  <p className="text-[10px] text-slate-500">I confirm this interface may be monitored.</p>
                </div>
                <Switch id="authz" checked={authorized} onCheckedChange={setAuthorized} />
              </div>
            )}
            {iface && hasRole('admin') && ifaces?.find((i) => i.name === iface) && !ifaces.find((i) => i.name === iface)?.is_authorized && (
              <Button variant="secondary" size="sm" className="w-full" onClick={() => authorize.mutate(iface)}>
                <Network className="h-3.5 w-3.5" /> Authorize interface (admin)
              </Button>
            )}

            <div className="space-y-1.5">
              <Label>BPF filter (optional)</Label>
              <Input value={bpf} onChange={(e) => setBpf(e.target.value)} placeholder="e.g. tcp port 443" className="font-mono text-xs" />
            </div>

            <div className="flex gap-2">
              {!status?.running ? (
                <Button
                  className="flex-1"
                  disabled={!iface || !hasRole('admin') || start.isPending}
                  onClick={() => start.mutate()}
                >
                  <PlayCircle className="h-4 w-4" /> Start capture
                </Button>
              ) : (
                <Button variant="destructive" className="flex-1" onClick={() => stop.mutate()}>
                  <CircleStop className="h-4 w-4" /> Stop capture
                </Button>
              )}
              <Button variant="outline" size="icon" onClick={() => qc.invalidateQueries({ queryKey: ['capture'] })} aria-label="Refresh status">
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>

            {status?.running && (
              <div className="grid grid-cols-3 gap-2 text-center text-[11px]">
                <div className="rounded bg-navy-950/70 p-2">
                  <p className="tabular-nums text-white">{fmtInt(status.packets_captured)}</p>
                  <p className="text-slate-600">packets</p>
                </div>
                <div className="rounded bg-navy-950/70 p-2">
                  <p className="tabular-nums text-white">{fmtInt(status.flows_emitted)}</p>
                  <p className="text-slate-600">flows</p>
                </div>
                <div className="rounded bg-navy-950/70 p-2">
                  <p className="tabular-nums text-white">{fmtInt(status.queue_size)}</p>
                  <p className="text-slate-600">queued</p>
                </div>
              </div>
            )}

            <p className="text-[10px] leading-relaxed text-slate-600">
              Safety: capture never starts without explicit authorization; when privileges are
              missing the platform stays in documented offline PCAP mode.
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <MonitorPlay className="h-4 w-4 text-emerald-400" /> Live flow stream
              </CardTitle>
              <CardDescription>Flows ingested from the capture pipeline</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => refetchFlows()}>
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </Button>
          </CardHeader>
          <CardContent>
            {flowsError ? (
              <ErrorState message="Failed to load flows." onRetry={() => refetchFlows()} />
            ) : flowsLoading ? (
              <Loading label="Loading flows…" />
            ) : !flows?.items.length ? (
              <EmptyState
                title="No live flows yet"
                description="Start an authorized capture, or analyze a PCAP file to populate the stream."
                icon={<MonitorPlay className="h-6 w-6" />}
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead className="text-right">Pkts (f/b)</TableHead>
                    <TableHead className="text-right">Bytes/s</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {flows.items.map((f) => (
                    <TableRow key={f.id}>
                      <TableCell className="text-slate-500">{timeAgo(f.timestamp)}</TableCell>
                      <TableCell className="font-mono text-xs">{f.src_ip}:{f.src_port}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {f.dst_ip}:<span className="text-accent-soft">{f.dst_port}</span>
                      </TableCell>
                      <TableCell><Badge variant="secondary">{f.protocol}</Badge></TableCell>
                      <TableCell className="text-right font-mono text-xs">
                        {f.total_fwd_packets}/{f.total_bwd_packets}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtInt(Math.round(f.flow_bytes_per_sec))}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
