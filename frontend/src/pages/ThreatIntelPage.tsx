import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Globe, Lock, RefreshCw, Search, ShieldQuestion } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, Loading } from '@/components/ui/toast-reexports';
import { timeAgo, cn } from '@/lib/utils';

interface TiRecord {
  id: string;
  ip: string;
  provider: string;
  is_malicious: boolean;
  score: number | null;
  categories: string[] | null;
  is_private_ip: boolean;
  fetched_at: string;
  error: string | null;
}

export default function ThreatIntelPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const [ip, setIp] = useState('');

  const { data, isLoading, isError, refetch, isFetching } = useQuery<{ items: TiRecord[] }>({
    queryKey: ['threat-intel'],
    queryFn: () => api.get<{ items: TiRecord[] }>('/threat-intel/recent'),
    refetchInterval: 30_000,
  });

  const lookup = useMutation({
    mutationFn: (target: string) => api.get<TiRecord>(`/threat-intel/ip/${encodeURIComponent(target)}?force=true`),
    onSuccess: (rec) => {
      toast.success(`Lookup: ${rec.ip}`,
        rec.is_private_ip
          ? 'Private address — classified locally, never sent to external providers.'
          : rec.error
            ? `Provider issue: ${rec.error}`
            : rec.is_malicious ? 'Marked malicious by provider.' : 'No threat verdict from provider.');
      qc.invalidateQueries({ queryKey: ['threat-intel'] });
    },
    onError: (e: Error) => toast.error('Lookup failed', e.message),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-subtitle">
            Optional IP reputation enrichment with caching. Private addresses are never sent
            externally. Works without API keys.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Search className="h-4 w-4 text-accent-soft" /> IP lookup</CardTitle>
          <CardDescription>Force-refresh a reputation lookup (respects provider configuration)</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (ip.trim()) lookup.mutate(ip.trim());
            }}
          >
            <Input
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="e.g. 8.8.8.8 or 192.168.1.10"
              className="max-w-xs font-mono"
              aria-label="IP address"
            />
            <Button type="submit" disabled={!ip.trim() || lookup.isPending}>
              {lookup.isPending ? 'Looking up…' : 'Look up'}
            </Button>
          </form>
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-sky-500/25 bg-sky-500/5 p-3 text-[11px] text-sky-300/90">
            <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              Privacy guard: RFC1918 / loopback / link-local addresses are resolved from a local
              record only. Configure a provider and API key in Settings → Threat intel to enable
              external reputation lookups (AbuseIPDB, VirusTotal).
            </span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4 text-accent-soft" /> Recent enrichment records</CardTitle>
          <CardDescription>Cached responses with fetch timestamps and expiry</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loading label="Loading records…" />
          ) : isError ? (
            <ErrorState message="Failed to load threat intelligence records." onRetry={() => refetch()} />
          ) : items.length === 0 ? (
            <EmptyState
              title="No lookups yet"
              description="Records appear when alerts trigger enrichment or you run a manual lookup."
              icon={<ShieldQuestion className="h-6 w-6" />}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Categories</TableHead>
                  <TableHead>Fetched</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-mono text-xs">
                      {r.ip}
                      {r.is_private_ip && <Badge variant="secondary" className="ml-1.5">private</Badge>}
                    </TableCell>
                    <TableCell><Badge variant="outline">{r.provider}</Badge></TableCell>
                    <TableCell>
                      {r.error ? (
                        <Badge variant="warning" className="ring-inset">error</Badge>
                      ) : r.is_malicious ? (
                        <Badge variant="destructive" className="ring-inset">malicious</Badge>
                      ) : r.is_private_ip ? (
                        <Badge variant="secondary" className="ring-inset">local</Badge>
                      ) : (
                        <Badge variant="success" className="ring-inset">clean</Badge>
                      )}
                    </TableCell>
                    <TableCell className="max-w-[260px] truncate text-xs text-slate-500" title={(r.categories ?? []).join(', ')}>
                      {r.categories?.length ? r.categories.join(', ') : '—'}
                      {r.score != null && <span className="ml-2 font-mono">score {r.score}</span>}
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">{timeAgo(r.fetched_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
