import { describe, expect, it } from 'vitest';
import { requiresPlatformPlugin } from '../../apps/console-web/src/api/plugin-policy';

describe('M4 frontend plugin privilege boundaries', () => {
  it.each(['pre-function', 'post-function', 'file-log'])('protects %s even with a valid Service binding', name => {
    expect(requiresPlatformPlugin(name, true, true)).toBe(true);
  });
  it('protects unbound global plugins and unreviewed custom handlers independently', () => {
    expect(requiresPlatformPlugin('cors', true, false)).toBe(true);
    expect(requiresPlatformPlugin('custom-handler', false, true)).toBe(true);
    expect(requiresPlatformPlugin('cors', true, true)).toBe(false);
    expect(requiresPlatformPlugin('http-log', true, true)).toBe(false);
  });
});
