/** Severity → tailwind classes (single source of truth for visual tokens). */
import type { Severity, AlertStatus } from '@/types/contract';

export const severityClass: Record<Severity, string> = {
  Critical: 'bg-red-500/15 text-red-400 ring-red-500/40',
  High: 'bg-orange-500/15 text-orange-400 ring-orange-500/40',
  Medium: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  Low: 'bg-sky-500/15 text-sky-400 ring-sky-500/40',
  Informational: 'bg-slate-500/15 text-slate-400 ring-slate-500/40',
};

export const severityDot: Record<Severity, string> = {
  Critical: 'bg-red-500',
  High: 'bg-orange-500',
  Medium: 'bg-amber-500',
  Low: 'bg-sky-500',
  Informational: 'bg-slate-400',
};

export const statusClass: Record<AlertStatus, string> = {
  New: 'bg-red-500/15 text-red-300 ring-red-500/40',
  Acknowledged: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  Investigating: 'bg-blue-500/15 text-blue-300 ring-blue-500/40',
  Resolved: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  'False Positive': 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
};

export const CHART_COLORS = [
  '#3b82f6', '#ef4444', '#f59e0b', '#22c55e', '#a855f7',
  '#06b6d4', '#ec4899', '#84cc16', '#f97316', '#64748b',
];
