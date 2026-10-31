import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { KeyRound, Save, UserCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/ui/toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Loading } from '@/components/ui/toast-reexports';
import { timeAgo, cn } from '@/lib/utils';

interface Me {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
}

export default function ProfilePage() {
  const toast = useToast();
  const { user, logout } = useAuth();
  const [fullName, setFullName] = useState('');
  const [pwd, setPwd] = useState('');
  const [pwd2, setPwd2] = useState('');

  const { data: me, isLoading } = useQuery<Me>({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('/auth/me'),
  });

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, any> = {};
      if (fullName.trim()) body.full_name = fullName.trim();
      if (pwd) body.password = pwd;
      return api.put('/auth/me', body);
    },
    onSuccess: () => {
      toast.success('Profile updated');
      setPwd('');
      setPwd2('');
    },
    onError: (e: Error) => toast.error('Update failed', e.message),
  });

  const mismatch = pwd && pwd2 && pwd !== pwd2;
  const weak = pwd && pwd.length < 8;

  return (
    <div className="mx-auto max-w-2xl space-y-5 animate-fade-in">
      <div>
        <h1 className="page-title">User Profile</h1>
        <p className="page-subtitle">Account details and credential management</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserCircle className="h-4 w-4 text-accent-soft" /> Account
          </CardTitle>
          <CardDescription>Session: {user?.email}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoading ? (
            <Loading label="Loading profile…" className="py-6" />
          ) : me ? (
            <div className="grid grid-cols-2 gap-2.5 text-xs sm:grid-cols-3">
              {[
                ['Username', me.username],
                ['Email', me.email],
                ['Role', me.role],
                ['Full name', me.full_name || '—'],
                ['Member since', new Date(me.created_at).toLocaleDateString()],
                ['Last login', me.last_login_at ? timeAgo(me.last_login_at) : '—'],
              ].map(([k, v]) => (
                <div key={k} className="rounded bg-navy-950/60 p-2.5">
                  <p className="text-[10px] uppercase tracking-wider text-slate-600">{k}</p>
                  <p className="mt-0.5 font-mono text-slate-300">{v}</p>
                </div>
              ))}
              <div className="col-span-2 flex items-center gap-2 rounded bg-navy-950/60 p-2.5 sm:col-span-3">
                <Badge variant={me.role === 'admin' ? 'destructive' : me.role === 'analyst' ? 'default' : 'secondary'} className="ring-inset">
                  {me.role}
                </Badge>
                <span className="text-[11px] text-slate-500">
                  {me.role === 'admin' && 'Full control: users, settings, capture, destructive ops'}
                  {me.role === 'analyst' && 'Operational: alerts, incidents, uploads, training, reports'}
                  {me.role === 'viewer' && 'Read-only dashboards and lists'}
                </span>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><KeyRound className="h-4 w-4 text-amber-400" /> Update profile &amp; password</CardTitle>
          <CardDescription>Passwords are hashed with PBKDF2-SHA256 (260k iterations)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="fn">Display name</Label>
            <Input id="fn" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder={me?.full_name || 'Your name'} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="np">New password</Label>
              <Input id="np" type="password" value={pwd} onChange={(e) => setPwd(e.target.value)} placeholder="min 8 characters" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="np2">Confirm password</Label>
              <Input id="np2" type="password" value={pwd2} onChange={(e) => setPwd2(e.target.value)} />
            </div>
          </div>
          {mismatch && <p className="text-xs text-red-400">Passwords do not match.</p>}
          {weak && <p className="text-xs text-amber-400">Password must be at least 8 characters.</p>}
          <div className="flex gap-2">
            <Button
              onClick={() => save.mutate()}
              disabled={save.isPending || !!(pwd && (weak || mismatch)) || (!pwd && !fullName.trim())}
            >
              <Save className="h-4 w-4" /> {save.isPending ? 'Saving…' : 'Save'}
            </Button>
            <Button variant="ghost" onClick={() => logout()}>
              Sign out
            </Button>
          </div>
          {pwd && (
            <p className={cn('text-[11px]', weak || mismatch ? 'text-red-400' : 'text-emerald-400')}>
              {weak || mismatch ? 'Fix the issues above before saving.' : 'Password looks good.'}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
