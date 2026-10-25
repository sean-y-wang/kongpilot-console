import { describe, expect, it } from 'vitest';
import { connectionAddressFields } from '../../apps/console-web/src/api/registry-payload';

describe('M4 edits keep protected registry addresses server-side', () => {
  it.each(['admin_url', 'base_url'] as const)('omits hidden %s while editing other metadata', field => {
    for (const value of [undefined, null, '', '  ']) {
      const body = { name: 'Renamed connection', revision: 2, ...connectionAddressFields(field, value, true) };
      expect(body).toEqual({ name: 'Renamed connection', revision: 2 });
      expect(JSON.stringify(body)).not.toContain(field);
    }
  });
  it.each(['admin_url', 'base_url'] as const)('requires %s on creation and submits an explicit replacement when supplied', field => {
    for (const value of [undefined, null, '', '  ']) expect(() => connectionAddressFields(field, value, false)).toThrow('新增连接必须提供地址');
    expect(connectionAddressFields(field, ' https://new-connection.example:8443 ', true)).toEqual({ [field]: 'https://new-connection.example:8443' });
    expect(connectionAddressFields(field, 'http://new-connection.example', false)).toEqual({ [field]: 'http://new-connection.example' });
  });
});
