import { describe, expect, it } from 'vitest';
import { abbreviateId } from '../../apps/console-web/src/lib/abbreviate-id';

describe('abbreviateId', () => {
  it('keeps short IDs unchanged', () => {
    expect(abbreviateId('abc')).toBe('abc');
    expect(abbreviateId('123456789012')).toBe('123456789012');
    expect(abbreviateId('1234567890123')).toBe('1234567890123'); // 13 = 8+1+4
  });

  it('uses a fixed middle ellipsis (first 8 + … + last 4)', () => {
    expect(abbreviateId('12345678901234')).toBe('12345678…1234');
    expect(abbreviateId('00c6ad45-aaaa-bbbb-cccc-ddddeeee0001')).toBe('00c6ad45…0001');
  });

  it('accepts custom head/tail widths', () => {
    expect(abbreviateId('abcdefghijklmnop', 4, 2)).toBe('abcd…op');
  });

  it('passes through empty / non-string safely', () => {
    expect(abbreviateId('')).toBe('');
  });
});
