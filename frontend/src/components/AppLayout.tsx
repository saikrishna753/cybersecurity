import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity, AlertOctagon, AlertTriangle, BarChart3, BrainCircuit, Cpu,
  FileBarChart, FileSearch, Gauge, GitBranch, Globe, LayoutDashboard,
  LogOut, Menu, Radio, Search, ServerCog, Shield, ShieldAlert, X,
} from 'lucide-react';
import { useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { useToast } from '@/components/ui/toast';

type NavEntry =
  | { section: string }
  | { to: string; label: string; icon: any; badge?: string };

const NAV: NavEntry[] = [
  { section: 'Monitor' },
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/live', label: 'Live Monitoring', icon: Radio },
  { to: '/analysis', label: 'Traffic Analysis', icon: Activity },
  { to: '/pcap', label: 'PCAP Analyzer', icon: FileSearch },
  { section: 'Detect' },
  { to: '/detection', label: 'Attack Detection', icon: ShieldAlert },
  { to: '/alerts', label: 'Security Alerts', icon: AlertTriangle, badge: 'openAlerts' },
  { to: '/incidents', label: 'Incidents', icon: GitBranch },
  { section: 'Intelligence' },
  { to: '/models', label: 'ML Models', icon: Cpu },
  { to: '/explainability', label: 'AI Explainability', icon: BrainCircuit },
  { to: '/threat-intel', label: 'Threat Intelligence', icon: Globe },
  { section: 'Manage' },
  { to: '/datasets', label: 'Dataset Management', icon: ServerCog },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
  { to: '/settings', label: 'Settings', icon: Gauge },
] as const;

export function AppLayout() {
  const { user, logout, hasRole } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [q, setQ] = useState('');

  const { data: alertSummary } = useQuery({
    queryKey: ['alert-summary'],
    queryFn: () => api.get<{ by_status: Record<string, number> }>('/alerts/summary'),
    refetchInterval: 30_000,
  });
  const openAlerts = alertSummary?.by_status?.New ?? 0;

  const globalSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!q.trim()) return;
    navigate(`/alerts?search=${encodeURIComponent(q.trim())}`);
    setMobileOpen(false);
  };

  const navItems = (
    <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-3">
      {NAV.map((item, i) =>
        'section' in item ? (
          <p key={`s${i}`} className="px-3 pb-1 pt-4 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-600">
            {item.section}
          </p>
        ) : (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              cn(
                'group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                isActive
                  ? 'bg-accent/15 text-accent-soft font-medium ring-1 ring-accent/30'
                  : 'text-slate-400 hover:bg-navy-800 hover:text-slate-200',
              )
            }
          >
            <item.icon className="h-4 w-4 shrink-0" />
            <span className="flex-1">{item.label}</span>
            {item.badge === 'openAlerts' && openAlerts > 0 && (
              <span className="rounded-full bg-red-500/90 px-1.5 py-0.5 text-[10px] font-bold text-white">
                {openAlerts}
              </span>
            )}
          </NavLink>
        ),
      )}
    </nav>
  );

  const brand = (
    <div className="flex items-center gap-2.5 border-b border-white/[0.06] px-4 py-4">
      <div className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-accent to-accent-dim shadow-lg shadow-accent/30">
        <Shield className="h-5 w-5 text-white" />
        <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 ring-2 ring-navy-900 animate-pulse-slow" />
      </div>
      <div>
        <p className="text-sm font-bold tracking-wider text-white">AI-IDS</p>
        <p className="text-[10px] text-slate-500">Threat Monitoring Platform</p>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden bg-navy-950 text-slate-200">
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r border-white/[0.06] bg-navy-900 lg:flex">
        {brand}
        {navItems}
        <div className="border-t border-white/[0.06] p-3">
          <div className="flex items-center gap-3 rounded-lg bg-navy-950/60 px-3 py-2.5 ring-1 ring-white/[0.05]">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-accent/20 text-xs font-bold text-accent-soft">
              {(user?.username || 'U')[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium text-slate-300">{user?.username}</p>
              <p className="truncate text-[10px] uppercase text-slate-600">{user?.role}</p>
            </div>
            <button
              aria-label="Sign out"
              onClick={() => {
                logout();
                navigate('/login');
              }}
              className="rounded p-1 text-slate-500 hover:bg-red-500/10 hover:text-red-400"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute left-0 top-0 flex h-full w-64 flex-col bg-navy-900 shadow-2xl">
            <div className="flex items-center justify-between pr-3">
              {brand}
              <button onClick={() => setMobileOpen(false)} aria-label="Close menu" className="text-slate-400">
                <X className="h-5 w-5" />
              </button>
            </div>
            {navItems}
          </aside>
        </div>
      )}

      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Topbar */}
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-white/[0.06] bg-navy-900/70 px-4 backdrop-blur">
          <button className="lg:hidden text-slate-400" aria-label="Open menu" onClick={() => setMobileOpen(true)}>
            <Menu className="h-5 w-5" />
          </button>
          <form onSubmit={globalSearch} className="relative hidden max-w-sm flex-1 sm:block">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search alerts by IP, type, ID…"
              className="h-8 pl-8 text-xs"
              aria-label="Global search"
            />
          </form>
          <div className="ml-auto flex items-center gap-2">
            <QueryStatusPill />
            {hasRole('analyst') && (
              <Badge variant="outline" className="hidden font-mono text-[10px] sm:inline-flex">
                {user?.role}
              </Badge>
            )}
            <button
              onClick={() => {
                logout();
                navigate('/login');
              }}
              className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs text-slate-400 hover:bg-navy-800 hover:text-white lg:hidden"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1600px] p-4 sm:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

function QueryStatusPill() {
  const { data, isError, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<{ status: string; models: Record<string, any> }>('/health'),
    refetchInterval: 15_000,
    retry: 1,
  });
  const model = data?.models?.binary?.name;
  const ok = data?.status === 'ok' && !isError;
  return (
    <div className="hidden items-center gap-1.5 rounded-full bg-navy-950/80 px-2.5 py-1 ring-1 ring-white/[0.06] md:flex">
      <span
        className={cn(
          'h-1.5 w-1.5 rounded-full',
          isLoading ? 'bg-amber-400' : ok ? 'bg-emerald-400' : 'bg-red-500',
        )}
      />
      <span className="text-[10px] text-slate-500">
        {isLoading ? 'connecting…' : ok ? (model ? `model: ${model}` : 'online') : 'offline'}
      </span>
    </div>
  );
}

export default AppLayout;
