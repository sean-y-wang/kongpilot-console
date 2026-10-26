import { describe, expect, it } from 'vitest';
import { withoutUnsupportedTags } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';

const kong13KeyAuth = { fields: [{ id: { type: 'string' } }, { created_at: { type: 'integer' } }, { consumer: { type: 'foreign' } }, { key: { type: 'string' } }] };
const kong15KeyAuth = { fields: [...kong13KeyAuth.fields, { tags: { type: 'set' } }] };

describe('Kong 1.3 credential tags', () => {
  it('drops the inherited workspace tag when the native credential schema has no tags field', () => {
    expect(withoutUnsupportedTags({ key: 'k', tags: ['kos-ws-pay'] }, kong13KeyAuth)).toEqual({ key: 'k' });
  });
  it('keeps tags when the schema supports them or the schema is unknown/empty', () => {
    expect(withoutUnsupportedTags({ key: 'k', tags: ['kos-ws-pay'] }, kong15KeyAuth)).toEqual({ key: 'k', tags: ['kos-ws-pay'] });
    expect(withoutUnsupportedTags({ key: 'k', tags: ['a'] }, null)).toEqual({ key: 'k', tags: ['a'] });
    expect(withoutUnsupportedTags({ key: 'k', tags: ['a'] }, { fields: [] })).toEqual({ key: 'k', tags: ['a'] });
  });
});
