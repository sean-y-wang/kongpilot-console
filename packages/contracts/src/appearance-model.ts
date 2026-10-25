export type AppearanceMode = 'light' | 'dark';
export type AppearancePreference = AppearanceMode | 'system';
export const appearanceStorageKey = 'kongpilot.appearance';

export function appearancePreference(value: unknown): AppearancePreference {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}

export function readAppearancePreference(read: () => unknown): AppearancePreference {
  try { return appearancePreference(read()); } catch { return 'system'; }
}

export function resolveAppearance(preference: AppearancePreference, systemDark: boolean): AppearanceMode {
  return preference === 'system' ? systemDark ? 'dark' : 'light' : preference;
}

export function saveAppearancePreference(value: AppearancePreference, write: (value: string) => void): boolean {
  if (!['light', 'dark', 'system'].includes(value)) return false;
  try { write(value); return true; } catch { return false; }
}
