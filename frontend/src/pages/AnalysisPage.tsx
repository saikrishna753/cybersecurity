import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Activity, Filter, RefreshCw, Search } from 'lucide-react';
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts';
import { api } from '@/lib/api';
import type { NetworkFlow, Page } from '@/types/contract';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { CHART_COLORS } from '@/lib/tokens';
import { fmtInt, timeAgo, cn } from '@/lib/utils';

const tooltipStyle = {
  backgroundColor: '#0d1529', border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8, fontSize: 12, color: '#e2e8f0',
};

export default function AnalysisPage() {
  const [page, setPage] = useState(1);
  const [srcIp, setSrcIp] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [malicious, setMalicious] = useState('all');
  const [appliedSearch, setAppliedSearch] = useState({ src: '', proto: 'all', mal: 'all' });

  const params = new URLSearchParams({ page: String(page), size: '20' });
  if (appliedSearch.src) params.set('src_ip', appliedSearch.src);
  if (appliedSearch.proto !== 'all') params.set('protocol', appliedSearch.proto);
  if (appliedSearch.mal !== 'all') params.set('malicious', appliedSearch.mal);

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Page<NetworkFlow>>({
    queryKey: ['flows', 'analysis', appliedSearch, page],
    queryFn: () => api.get<Page<NetworkFlow>>(`/monitoring/flows?${params}`),
  });

  const { data: stats } = useQuery<{ by_attack: Record<string, number>; by_severity: Record<string, number> }>({
    queryKey: ['alerts', 'summary'],
    queryFn: () => api.get('/alerts/summary'),
  });

  const attackData = stats
    ? Object.entries(stats.by_attack ?? {}).map(([name, count]) => ({ name, count }))
    : [];
  const sevData = stats
    ? Object.entries(stats.by_severity ?? {}).map(([name, count]) => ({ name, count }))
    : [];

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.size)) : 1;

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Traffic Analysis</h1>
          <p className="page-subtitle">Browse and filter stored network flows with alert aggregates</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Alerts by attack type</CardTitle></CardHeader>
          <CardContent className="h-52">
            {attackData.length === 0 ? (
              <EmptyState title="No alerts yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackData} margin={{ left: -14, right: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#64748b' }} interval={0} angle={-18} height={44} textAnchor="end" />
                  <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {attackData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Alerts by severity</CardTitle></CardHeader>
          <CardContent className="h-52">
            {sevData.length === 0 ? (
              <EmptyState title="No alerts yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} dataKey="count" nameKey="name" innerRadius={44} outerRadius={74} paddingAngle={2}>
                    {sevData.map((entry, i) => (
                      <Cell key={i} fill={{ Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b', Low: '#0ea5e9', Informational: '#64748b' }[entry.name] ?? CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between flex-wrap gap-3">
          <div>
            <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4 text-accent-soft" /> Stored flows</CardTitle>
            <CardDescription>{data ? `${fmtInt(data.total)} flows match` : '…'}</CardDescription>
          </div>
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setPage(1);
              setAppliedSearch({ src: srcIp.trim(), proto: protocol, mal: malicious });
            }}
          >
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
              <Input
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="Source IP"
                className="h-8 w-36 pl-8 font-mono text-xs"
                aria-label="Filter by source IP"
              />
            </div>
            <Select value={protocol} onValueChange={setProtocol}>
              <SelectTrigger className="h-8 w-28 text-xs" aria-label="Protocol"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All protos</SelectItem>
                <SelectItem value="TCP">TCP</SelectItem>
                <SelectItem value="UDP">UDP</SelectItem>
                <SelectItem value="ICMP">ICMP</SelectItem>
              </SelectContent>
            </Select>
            <Select value={malicious} onValueChange={setMalicious}>
              <SelectTrigger className="h-8 w-32 text-xs" aria-label="Classification"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All flows</SelectItem>
                <SelectItem value="true">Malicious</SelectItem>
                <SelectItem value="false">Benign</SelectItem>
              </SelectContent>
            </Select>
            <Button type="submit" size="sm" variant="secondary"><Filter className="h-3.5 w-3.5" /> Apply</Button>
          </form>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading flows…" />
          ) : isError ? (
            <ErrorState message="Failed to load flows." onRetry={() => refetch()} />
          ) : !data?.items.length ? (
            <EmptyState title="No flows match" description="Adjust the filters or ingest traffic data first." />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead className="text-right">Duration</TableHead>
                    <TableHead className="text-right">Fwd pkts</TableHead>
                    <TableHead className="text-right">Bwd pkts</TableHead>
                    <TableHead className="text-right">Bytes/s</TableHead>
                    <TableHead>Origin</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((f) => (
                    <TableRow key={f.id}>
                      <TableCell className="whitespace-nowrap font-mono text-[11px] text-slate-500">
                        {new Date(f.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{f.src_ip}:{f.src_port}</TableCell>
                      <TableCell className="font-mono text-xs">{f.dst_ip}:<span className="text-accent-soft">{f.dst_port}</span></TableCell>
                      <TableCell><Badge variant="secondary">{f.protocol}</Badge></TableCell>
                      <TableCell className="text-right font-mono text-xs">{f.flow_duration.toFixed(4)}s</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtInt(f.total_fwd_packets)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtInt(f.total_bwd_packets)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtInt(Math.round(f.flow_bytes_per_sec))}</TableCell>
                      <TableCell><Badge variant="outline">{f.source}</Badge></TableCell>
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
    </div>
  );
}
