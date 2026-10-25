import { describe, expect, it } from 'vitest';
import { ConflictException } from '@nestjs/common';
import { duplicatePreference } from '../../apps/console-api/src/modules/event-core/notification-operations.service';

// Found by live verification: saving a second in-app subscription with an
// existing name returned 500 INTERNAL_ERROR (unique violation leaked).
describe('notification preference duplicate name', () => {
  it('maps the SQL010 per-user name uniqueness violation to a 409 conflict', () => {
    const error = Object.assign(new Error('duplicate key'), { code: '23505', constraint: 'user_notification_subscriptio_user_id_cluster_id_workspace__key' });
    let thrown: unknown;
    try { duplicatePreference(error); } catch (e) { thrown = e; }
    expect(thrown).toBeInstanceOf(ConflictException);
    expect((thrown as ConflictException).getStatus()).toBe(409);
    expect((thrown as ConflictException).getResponse()).toMatchObject({ code: 'NOTIFICATION_PREFERENCE_NAME_EXISTS' });
  });
  it('does not mask other unique violations or errors', () => {
    const other = Object.assign(new Error('dup op'), { code: '23505', constraint: 'iam_operations_actor_id_idempotency_key_key' });
    expect(() => duplicatePreference(other)).toThrow(other);
    const plain = new Error('boom');
    expect(() => duplicatePreference(plain)).toThrow(plain);
  });
});
