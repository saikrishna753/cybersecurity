import { FormEvent, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, AlertTriangle } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

export default function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password) {
      setError('Email and password are required.');
      return;
    }
    setBusy(true);
    try {
      await login(email.trim(), password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err?.message || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-navy-950 px-4">
      {/* ambient grid */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(59,130,246,.13) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,.13) 1px, transparent 1px)',
          backgroundSize: '42px 42px',
          maskImage: 'radial-gradient(ellipse at center, black 30%, transparent 75%)',
        }}
      />
      <div className="absolute -top-32 left-1/2 h-64 w-[36rem] -translate-x-1/2 rounded-full bg-accent/10 blur-3xl" />

      <Card className="relative w-full max-w-md border-white/10 bg-navy-900/90 backdrop-blur">
        <CardHeader className="items-center pb-2 text-center">
          <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-accent to-accent-dim shadow-lg shadow-accent/40">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <CardTitle className="text-xl font-bold tracking-wide text-white">AI-IDS</CardTitle>
          <CardDescription>AI-Powered Network Intrusion Detection &amp; Threat Monitoring</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-4" noValidate>
            {error && (
              <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-xs text-red-300">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="admin@ai-ids.local"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-8"
                  required
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-8"
                  required
                />
              </div>
            </div>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in to console'}
            </Button>
          </form>

          <div className="mt-5 rounded-lg border border-white/[0.06] bg-navy-950/60 p-3">
            <p className="text-[11px] font-medium text-slate-500">Default bootstrap credentials</p>
            <p className="mt-1 font-mono text-[11px] text-slate-400">
              admin@ai-ids.local · ChangeMe!123
            </p>
            <p className="mt-1.5 text-[10px] text-slate-600">
              Change the admin password after first login (Settings → Profile). Roles:
              admin &gt; analyst &gt; viewer.
            </p>
          </div>
          <p className="mt-4 text-center text-[10px] leading-relaxed text-slate-700">
            Defensive monitoring tool — only monitor networks you are authorized to inspect.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
