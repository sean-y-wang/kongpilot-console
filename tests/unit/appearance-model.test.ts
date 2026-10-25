import { describe, expect, it, vi } from 'vitest';
import { appearancePreference, readAppearancePreference, resolveAppearance, saveAppearancePreference } from '../../packages/contracts/src/appearance-model';

describe('browser appearance preference without identity or recovery side effects', () => {
  it.each([undefined, null, '', 'LIGHT', 'auto', {}, 'invalid-theme'])('defaults invalid saved value %j to system', value => {
    expect(appearancePreference(value)).toBe('system');
  });
  it.each(['light', 'dark', 'system'] as const)('preserves explicit %s preference', value => expect(appearancePreference(value)).toBe(value));
  it('follows the system only until the user selects an explicit appearance', () => {
    expect(resolveAppearance('system', true)).toBe('dark'); expect(resolveAppearance('system', false)).toBe('light');
    expect(resolveAppearance('light', true)).toBe('light'); expect(resolveAppearance('dark', false)).toBe('dark');
  });
  it('handles blocked storage without making the application fail', () => {
    expect(readAppearancePreference(() => { throw new Error('storage unavailable'); })).toBe('system');
    expect(saveAppearancePreference('dark', () => { throw new Error('storage unavailable'); })).toBe(false);
  });
  it('writes only valid display values, preserving permission and session boundaries', () => {
    const write = vi.fn(); expect(saveAppearancePreference('dark', write)).toBe(true); expect(write).toHaveBeenCalledExactlyOnceWith('dark');
    write.mockClear(); expect(saveAppearancePreference('injected' as any, write)).toBe(false); expect(write).not.toHaveBeenCalled();
  });
});
