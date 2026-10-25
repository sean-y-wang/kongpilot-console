import { createContext, useContext, useEffect, useLayoutEffect, useMemo, useState, type ReactNode } from 'react';
import { Button, ConfigProvider, Tooltip } from 'antd';
import { PilotIcon } from './PilotIcon';
import zhCN from 'antd/locale/zh_CN';
import { pilotTheme } from './pilot-theme';
import { appearanceStorageKey, readAppearancePreference, resolveAppearance, saveAppearancePreference, type AppearanceMode, type AppearancePreference } from './appearance-model';

interface AppearanceContextValue { mode: AppearanceMode; preference: AppearancePreference; select: (preference: AppearancePreference) => void; }
const AppearanceContext = createContext<AppearanceContextValue | null>(null);
function systemDark() { try { return window.matchMedia('(prefers-color-scheme: dark)').matches; } catch { return false; } }

export function PilotThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = useState<AppearancePreference>(() => readAppearancePreference(() => window.localStorage.getItem(appearanceStorageKey)));
  const [darkSystem, setDarkSystem] = useState(systemDark);
  const mode = resolveAppearance(preference, darkSystem);
  useEffect(() => {
    let media: MediaQueryList;
    try { media = window.matchMedia('(prefers-color-scheme: dark)'); } catch { return; }
    const changed = (event: MediaQueryListEvent) => setDarkSystem(event.matches);
    if (media.addEventListener) { media.addEventListener('change', changed); return () => media.removeEventListener('change', changed); }
    media.addListener(changed); return () => media.removeListener(changed);
  }, []);
  useLayoutEffect(() => {
    document.documentElement.dataset.appearance = mode;
    document.documentElement.style.colorScheme = mode;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', mode === 'dark' ? '#121820' : '#f7f8fa');
  }, [mode]);
  const value = useMemo<AppearanceContextValue>(() => ({ mode, preference, select: next => {
    setPreference(next);
    // A browser display preference only; never clear auth/recovery/scope storage.
    saveAppearancePreference(next, saved => window.localStorage.setItem(appearanceStorageKey, saved));
  } }), [mode, preference]);
  return <AppearanceContext.Provider value={value}><ConfigProvider locale={zhCN} theme={pilotTheme(mode)}>{children}</ConfigProvider></AppearanceContext.Provider>;
}

export function usePilotAppearance() {
  const value = useContext(AppearanceContext);
  if (!value) throw new Error('PilotThemeProvider is required');
  return value;
}

export function AppearanceToggle() {
  const { mode, select } = usePilotAppearance();
  const label = mode === 'dark' ? '切换浅色模式' : '切换深色模式';
  return <Tooltip title={label}><Button className="appearance-toggle" type="text" aria-label={label} aria-pressed={mode === 'dark'} icon={<PilotIcon name={mode === 'dark' ? 'sun' : 'moon'} />} onClick={() => select(mode === 'dark' ? 'light' : 'dark')} /></Tooltip>;
}
