import { ForbiddenException } from '@nestjs/common';
import type { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { derivePreparedEntityWrite } from '../entities/entity-prepared-writer.service';
import type { EntityChangePacket } from '../entities/entity-change.types';
import type { EntityScheduledAuthorityInspection } from './entity-scheduled-authority.types';

/** Pure sealed-packet validation only. The real Authority must authenticate
 * its original handle, current SQL roles, lease and window before this runs.
 * A copied inspection or the returned packet never grants a namespace. */
export function scheduledTargetWeightPacket(inspection: Readonly<EntityScheduledAuthorityInspection>, packetKey: string,
  secrets: Pick<SecretService, 'fingerprint'>): Readonly<EntityChangePacket> {
  const deny = () => new ForbiddenException({ code: 'ENTITY_SCHEDULE_TARGET_WEIGHT_PACKET_REQUIRED' });
  if (!inspection || inspection.version !== 1 || inspection.envelope?.version !== 2 || inspection.envelope.executionMode !== 'approval'
    || inspection.plan?.kind !== 'native-change' || inspection.plan.executionMode !== 'approval' || inspection.plan.approvalRequired !== true
    || typeof packetKey !== 'string' || !/^[a-zA-Z\d_.:-]{1,128}$/.test(packetKey) || !Array.isArray(inspection.envelope.prepared?.packets)) throw deny();
  const packets = inspection.envelope.prepared.packets.filter(packet => packet.key === packetKey);
  if (packets.length !== 1) throw deny();
  const packet = packets[0], operation = derivePreparedEntityWrite(packet);
  if (!['target-create', 'target-weight'].includes(operation.kind) || packet.nativeType !== 'targets' || packet.method !== 'POST'
    || packet.canonicalPath !== `/upstreams/${packet.parentId}/targets` || !packet.body || typeof packet.body !== 'object' || Array.isArray(packet.body)
    || Object.keys(packet.body).some(key => !['id', 'target', 'weight', 'tags'].includes(key))
    || !Number.isInteger(packet.body.weight) || Number(packet.body.weight) < 0 || Number(packet.body.weight) > 1000
    || packet.body.tags !== undefined && packet.body.tags !== null && (!Array.isArray(packet.body.tags) || packet.body.tags.some(tag => typeof tag !== 'string' || !tag) || new Set(packet.body.tags).size !== packet.body.tags.length)
    || packet.bodyHmac !== secrets.fingerprint(packet.body) || packet.beforeHmac !== secrets.fingerprint(packet.before ?? null)) throw deny();
  if (operation.kind === 'target-weight' && (!Number.isInteger(operation.before.weight) || Number(operation.before.weight) <= 0 || Number(operation.before.weight) > 1000)) throw deny();
  return immutableJson(packet);
}
