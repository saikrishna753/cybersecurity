import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle, X } from 'lucide-react';
import { cn } from '@/lib/utils';

type ToastKind = 'success' | 'error' | 'info' | 'warning';
interface ToastItem {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
}
interface ToastCtx {
  push: (kind: ToastKind, title: string, description?: string) => void;
  success: (t: string, d?: string) => void;
  error: (t: string, d?: string) => void;
  info: (t: string, d?: string) => void;
  warning: (t: string, d?: string) => void;
}

const Ctx = createContext<ToastCtx | null>(null);
let nextId = 1;

const icons: Record<ToastKind, ReactNode> = {
  success: <CheckCircle2 className="h-4 w-4 text-emerald-400" />,
  error: <XCircle className="h-4 w-4 text-red-400" />,
  warning: <AlertTriangle className="h-4 w-4 text-amber-400" />,
  info: <Info className="h-4 w-4 text-sky-400" />,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const push = useCallback((kind: ToastKind, title: string, description?: string) => {
    const id = nextId++;
    setItems((prev) => [...prev.slice(-4), { id, kind, title, description }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const value: ToastCtx = {
    push,
    success: (t, d) => push('success', t, d),
    error: (t, d) => push('error', t, d),
    info: (t, d) => push('info', t, d),
    warning: (t, d) => push('warning', t, d),
  };

  return (
    <Ctx.Provider value={value}>
      {children}
      <div aria-live="polite" className="fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            role="status"
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-lg border bg-navy-900 p-3.5 shadow-2xl animate-fade-in',
              t.kind === 'success' && 'border-emerald-500/30',
              t.kind === 'error' && 'border-red-500/40',
              t.kind === 'warning' && 'border-amber-500/40',
              t.kind === 'info' && 'border-sky-500/30',
            )}
          >
            <div className="mt-0.5 shrink-0">{icons[t.kind]}</div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-100">{t.title}</p>
              {t.description && <p className="mt-0.5 text-xs text-slate-400 break-words">{t.description}</p>}
            </div>
            <button
              aria-label="Dismiss"
              onClick={() => setItems((prev) => prev.filter((x) => x.id !== t.id))}
              className="text-slate-500 hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}
