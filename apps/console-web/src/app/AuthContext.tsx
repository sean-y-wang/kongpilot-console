import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, post, setCsrfToken, setApiActorId, getApiActorId, ApiError } from '../api/client';
import { recoveryStorageKey } from '../api/workspace-scope';
import type { Session, User } from '../api/types';
import { useQueryClient } from '@tanstack/react-query';
import { closeMutationConfirmDialogs } from '../components/MutationConfirm';
import { loadLoginSession } from '../api/login-session';

interface AuthValue {
  user: User | null;
  loading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  loginLdap: (providerId: string, username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  reloadCapabilities: () => Promise<void>;
  endSession: () => void;
}
const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const actor = useRef<string>();
  const permissionEpoch = useRef<string>();
  const reloading = useRef<Promise<void>>();
  function applySession(session: Session) {
    if (actor.current && actor.current !== session.user.id) { closeMutationConfirmDialogs(); sessionStorage.removeItem(recoveryStorageKey); queryClient.clear(); }
    else if (permissionEpoch.current && permissionEpoch.current !== session.user.permissionsVersion) { closeMutationConfirmDialogs(); queryClient.clear(); }
    permissionEpoch.current = session.user.permissionsVersion;
    actor.current = session.user.id; setApiActorId(session.user.id); setCsrfToken(session.csrfToken); setUser(session.user);
  }
  function endSession() { closeMutationConfirmDialogs(); setUser(null); setCsrfToken(''); setApiActorId(undefined); actor.current = undefined; permissionEpoch.current = undefined; sessionStorage.removeItem(recoveryStorageKey); queryClient.clear(); }
  async function reloadCapabilities() {
    if (!reloading.current) {
      const originalActor = actor.current;
      reloading.current = api<Session>('/auth/me').then(session => {
        if (actor.current !== originalActor || getApiActorId() !== originalActor) return;
        if (session.user.id !== originalActor) {
          endSession();
          throw new ApiError('登录会话的账号已变化，请重新登录。', 401, 'SESSION_CHANGED');
        }
        applySession(session);
      }).finally(() => { reloading.current = undefined; });
    }
    await reloading.current;
  }
  async function refresh() {
    setLoading(true);
    try {
      const session = await api<Session>('/auth/me');
      applySession(session);
      setError(null);
    } catch (e) {
      setUser(null);
      setCsrfToken('');
      if (!(e instanceof ApiError && e.status === 401)) setError(e as Error);
    } finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, []);
  useEffect(() => { setApiActorId(user?.id); }, [user?.id]);
  useEffect(() => {
    const expired = endSession;
    window.addEventListener('kongos:session-expired', expired);
    return () => window.removeEventListener('kongos:session-expired', expired);
  }, [queryClient]);
  useEffect(() => {
    if (!user?.id) return;
    let lastReload = 0;
    const reload = (event?: Event) => {
      const expected = (event as CustomEvent<{ actorId?: string }> | undefined)?.detail?.actorId;
      if (expected && expected !== actor.current || Date.now() - lastReload < 3000) return;
      lastReload = Date.now(); void reloadCapabilities().catch(() => undefined);
    };
    const timer = window.setInterval(reload, 30_000);
    window.addEventListener('kongos:permission-stale', reload);
    window.addEventListener('focus', reload);
    return () => { window.clearInterval(timer); window.removeEventListener('kongos:permission-stale', reload); window.removeEventListener('focus', reload); };
  }, [user?.id]);
  async function login(username: string, password: string) {
    try {
      const session = await loadLoginSession('/auth/login', { username, password });
      applySession(session); setError(null);
    } catch (e) { if (e instanceof ApiError && e.code === 'SESSION_CHANGED') endSession(); throw e; }
  }
  async function loginLdap(providerId: string, username: string, password: string) {
    try {
      const session = await loadLoginSession(`/auth/ldap/${encodeURIComponent(providerId)}/login`, { username, password });
      applySession(session); setError(null);
    } catch (e) { if (e instanceof ApiError && e.code === 'SESSION_CHANGED') endSession(); throw e; }
  }
  async function logout() {
    await post('/auth/logout');
    endSession();
  }
  return <AuthContext.Provider value={{ user, loading, error, refresh, login, loginLdap, logout, reloadCapabilities, endSession }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('AuthProvider is required');
  return value;
}
