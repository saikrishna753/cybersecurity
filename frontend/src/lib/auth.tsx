import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '@/lib/api';
import type { AuthUser, Role } from '@/types/contract';

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (min: Role) => boolean;
}

const rank: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };
const AuthContext = createContext<AuthContextValue | null>(null);

const STORAGE_KEY = 'aiids.auth';

function readStored(): AuthUser | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const u = JSON.parse(raw) as AuthUser;
    if (!u?.token) return null;
    // expires_in is seconds-from-login; persist written-at to detect expiry
    return u;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => readStored());
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // verify token still valid
    const u = readStored();
    if (!u) {
      setLoading(false);
      return;
    }
    api
      .get('/auth/me')
      .then((me: any) => {
        setUser({ ...u, email: me.email, username: me.username, role: me.role });
      })
      .catch(() => {
        localStorage.removeItem(STORAGE_KEY);
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.post<AuthUser & { access_token: string }>('/auth/login', {
      email,
      password,
    });
    const u: AuthUser = {
      email: res.email,
      username: res.username,
      role: res.role,
      token: res.access_token,
      expires_in: res.expires_in,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
    setUser(u);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setUser(null);
  }, []);

  const hasRole = useCallback(
    (min: Role) => (user ? rank[user.role] >= rank[min] : false),
    [user],
  );

  const value = useMemo(
    () => ({ user, loading, login, logout, hasRole }),
    [user, loading, login, logout, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
