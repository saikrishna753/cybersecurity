import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Activity, AlertOctagon, AlertTriangle, ArrowUpRight, Clock, Cpu,
  Eye, GitBranch, Radar, ShieldCheck, Waves,
} from 'lucide-react';
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis, Legend,
} from 'recharts';
import { api } from '@/lib/api';
import type { DashboardStats, SecurityAlert } from '@/types/contract';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { StatSkeleton, EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { CHART_COLORS, severityClass, statusClass, severityDot } from '@/lib/tokens';
import { fmtInt, fmtPct, timeAgo, cn } from '@/lib/utils';

function StatCard({
  label, value, sub, icon: Icon, tone = 'default', hint,
}: {
  label: string; value: string | number; sub?: string; icon: any;
  tone?: 'default' | 'good' | 'warn' | 'bad'; hint?: string;
}) {
  const tones = {
    default: 'from-accent/15 to-transparent text-accent-soft',
    good: 'from-emerald-500/15 to-transparent text-emerald-400',
    warn: 'from-amber-500/15 to-transparent text-amber-400',
    bad: 'from-red-500/15 to-transparent text-red-400',
  };
  return (
    <Card className="relative overflow-hidden">
      <div className={cn('absolute inset-0 bg-gradient-to-br pointer-events-none', tones[tone])} />
      <CardContent className="relative p-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
            <p className="mt-2 text-2xl font-bold tabular-nums text-white">{value}</p>
            {sub && <p className="mt-1 text-[11px] text-slate-500">{sub}</p>}
          </div>
          <div className="rounded-lg bg-navy-950/70 p-2 ring-1 ring-white/[0.06]">
            <Icon className="h-4 w-4 opacity-80" />
          </div>
        </div>
        {hint && <p className="mt-2 text-[10px] text-slate-600">{hint}</p>}
      </CardContent>
    </Card>
  );
}

const tooltipStyle = {
  backgroundColor: '#0d1529',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  fontSize: 12,
  color: '#e2e8f0',
};

export default function DashboardPage() {
  const { data, isLoading, isError, refetch } = useQuery<DashboardStats>({
    queryKey: ['stats'],
    queryFn: () => api.get<DashboardStats>('/dashboard/stats'),
    refetchInterval: 20_000,
  });

  if (isLoading && !data) return <div className="space-y-5"><StatSkeleton /><Loading label="Loading SOC overview…" /></div>;
  if (isError && !data) return <ErrorState message="Failed to load dashboard statistics." onRetry={() => refetch()} />;
  if (!data) return <EmptyState title="No data yet" description="Upload a dataset or start an analysis to populate the dashboard." />;

  const recentAlerts = (data.recent_alerts ?? []) as unknown as SecurityAlert[];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Security Operations Overview</h1>
          <p className="page-subtitle">
            Live statistics from the AI-IDS database · model{' '}
            <span className="font-mono text-accent-soft">{data.active_model ?? 'not active'}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-500">
          <span className={cn('h-2 w-2 rounded-full', data.data_sources.live_capture ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600')} />
          {data.data_sources.live_capture ? 'Live capture active' : 'Offline analysis mode'}
          <span className="text-slate-700">·</span>
          <Waves className="h-3 w-3" />
          {data.data_sources.ws_clients} live clients
        </div>
      </div>

      {/* KPI row */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total flows analyzed" value={fmtInt(data.total_flows)} sub={`${fmtInt(data.flows_last_hour)} in last hour`} icon={Activity} tone="default" />
        <StatCard label="Attacks detected" value={fmtInt(data.total_attacks)} sub={`${fmtInt(data.attacks_last_hour)} in last hour`} icon={AlertOctagon} tone="bad" />
        <StatCard label="Normal traffic" value={fmtInt(data.total_normal)} sub={`${fmtPct(data.total_flows ? data.total_normal / data.total_flows : 0)} of flows`} icon={ShieldCheck} tone="good" />
        <StatCard label="Suspicious traffic" value={fmtInt(data.total_suspicious)} sub={`Detection rate ${fmtPct(data.detection_rate)}`} icon={Radar} tone="warn" />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total alerts" value={fmtInt(data.total_alerts)} sub={`${fmtInt(data.open_alerts)} open`} icon={AlertTriangle} tone="warn" />
        <StatCard label="Critical open" value={fmtInt(data.critical_alerts)} sub="Requires immediate triage" icon={AlertOctagon} tone="bad" />
        <StatCard label="Active model" value={data.active_model ?? '—'} sub="Registered classifier" icon={Cpu} tone="default" />
        <StatCard label="Observation window" value={`${data.uptime_hours.toFixed(1)} h`} sub="Since first stored flow" icon={Clock} tone="default" />
      </div>

      {/* Charts row 1 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Flows analyzed over the last 24 hours</CardTitle>
            <CardDescription>Hourly flow volume persisted by the platform (UTC)</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {data.traffic_timeline.length === 0 ? (
              <EmptyState title="No flow data in window" description="Run a PCAP analysis or CSV ingest to populate the timeline." />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.traffic_timeline} margin={{ left: -18, right: 8, top: 6 }}>
                  <defs>
                    <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.55} />
                      <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={(t) => t.slice(11, 16)} minTickGap={40} />
                  <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => `Time ${String(l).slice(11)} UTC`} />
                  <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fill="url(#trafficGrad)" name="Flows" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Attack distribution</CardTitle>
            <CardDescription>Malicious classifications by category</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {data.attack_distribution.length === 0 ? (
              <EmptyState title="No attacks recorded" description="All classified flows so far are benign." icon={<ShieldCheck className="h-6 w-6" />} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={data.attack_distribution} dataKey="count" nameKey="attack" innerRadius={52} outerRadius={80} paddingAngle={2}>
                    {data.attack_distribution.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
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

      {/* Charts row 2 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Detection timeline</CardTitle>
            <CardDescription>Malicious detections per hour</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            {data.detection_timeline.length === 0 ? (
              <EmptyState title="No detections yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.detection_timeline} margin={{ left: -18, right: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={(t) => t.slice(11, 16)} minTickGap={40} />
                  <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  <Bar dataKey="count" fill="#ef4444" radius={[3, 3, 0, 0]} name="Detections" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Protocol distribution</CardTitle>
            <CardDescription>Transport protocol mix of stored flows</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            {data.protocol_distribution.length === 0 ? (
              <EmptyState title="No protocols recorded" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.protocol_distribution} layout="vertical" margin={{ left: 30, right: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#64748b' }} width={44} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Bar dataKey="count" fill="#22c55e" radius={[0, 3, 3, 0]} name="Flows" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Model confidence distribution</CardTitle>
            <CardDescription>Confidence buckets of stored detections</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.confidence_distribution} margin={{ left: -14, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                <Bar dataKey="count" fill="#a855f7" radius={[3, 3, 0, 0]} name="Detections" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Severity + tops */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Severity distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 pt-1">
            {data.severity_distribution.length === 0 && <EmptyState title="No detections yet" />}
            {data.severity_distribution.map((s) => {
              const max = Math.max(...data.severity_distribution.map((x) => x.count), 1);
              return (
                <div key={s.name} className="flex items-center gap-2.5">
                  <span className={cn('h-2 w-2 shrink-0 rounded-full', severityDot[s.name as keyof typeof severityDot] ?? 'bg-slate-500')} />
                  <span className="w-24 text-xs text-slate-400">{s.name}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-navy-800">
                    <div className="h-full rounded-full bg-accent/70" style={{ width: `${(s.count / max) * 100}%` }} />
                  </div>
                  <span className="w-12 text-right text-xs tabular-nums text-slate-500">{fmtInt(s.count)}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top source IPs</CardTitle>
            <CardDescription>Most active flow origins</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 pt-1">
            {data.top_source_ips.length === 0 && <EmptyState title="No flows recorded" />}
            {data.top_source_ips.map((s, i) => (
              <div key={s.ip} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-2">
                  <span className="w-4 text-slate-600">{i + 1}</span>
                  <span className="font-mono text-slate-300">{s.ip}</span>
                </span>
                <span className="tabular-nums text-slate-500">{fmtInt(s.count)}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top destination ports</CardTitle>
            <CardDescription>Most targeted services</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 pt-1">
            {data.top_destination_ports.length === 0 && <EmptyState title="No flows recorded" />}
            {data.top_destination_ports.map((s) => (
              <div key={s.port} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-2">
                  <span className="rounded bg-navy-800 px-1.5 py-0.5 font-mono text-accent-soft">{s.port}</span>
                  <span className="text-slate-500">{portLabel(s.port)}</span>
                </span>
                <span className="tabular-nums text-slate-500">{fmtInt(s.count)}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Recent alerts */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Recent security alerts</CardTitle>
            <CardDescription>Latest malicious events requiring attention</CardDescription>
          </div>
          <Link to="/alerts" className="flex items-center gap-1 text-xs text-accent-soft hover:underline">
            View all <ArrowUpRight className="h-3 w-3" />
          </Link>
        </CardHeader>
        <CardContent>
          {recentAlerts.length === 0 ? (
            <EmptyState
              title="No security alerts"
              description="Alerts appear here when the detection engine classifies traffic as malicious."
              icon={<ShieldCheck className="h-6 w-6" />}
            />
          ) : (
            <div className="space-y-2">
              {recentAlerts.slice(0, 8).map((a, i) => (
                <div
                  key={a.alert_id ?? i}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-white/[0.05] bg-navy-950/40 px-3 py-2.5 text-xs transition hover:border-accent/30"
                >
                  <span className={cn('h-2 w-2 rounded-full shrink-0', severityDot[a.severity] ?? 'bg-slate-500')} />
                  <Badge className={cn('ring-inset', severityClass[a.severity])}>{a.severity}</Badge>
                  <span className="font-medium text-slate-200">{a.attack_type}</span>
                  <span className="font-mono text-slate-500">
                    {a.source_ip} → {a.destination_ip}:{a.destination_port}
                  </span>
                  <span className="ml-auto text-slate-600">{timeAgo(a.created_at)}</span>
                  <Badge className={cn('ring-inset', statusClass[a.status])}>{a.status}</Badge>
                  {a.dedup_count > 1 && (
                    <Badge variant="secondary" className="font-mono">×{a.dedup_count}</Badge>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function portLabel(port: number): string {
  const known: Record<number, string> = {
    22: 'SSH', 21: 'FTP', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
    8080: 'HTTP-Proxy', 3306: 'MySQL', 8443: 'HTTPS-alt',
  };
  return known[port] ?? '';
}
