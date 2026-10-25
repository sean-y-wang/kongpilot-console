import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { certifyPartialNoSendTerminalMetadata } from '../../apps/console-api/src/modules/workflows/entity-change-partial-no-send-terminal-proof';
import { partialNoSendTerminalFixture } from './helpers/partial-no-send-terminal-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'c7'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());
const invalid = { response: { code: 'ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID' } };
describe('M11 partial restore known-no-send Root bindings (synthetic sealed material/Reader adapter)', () => {
  it('binds exact Root Source to a fixed authenticated Reader footprint and returns historical metadata proof without writes', async () => {
    const f = partialNoSendTerminalFixture(), before = structuredClone(f.input.envelope);
    const proof = await certifyPartialNoSendTerminalMetadata(f.input);
    expect(proof).toMatchObject({ entryId: f.entryId, failedNodeKey: f.graph.nodes[5].key, failedOperationId: f.footprint.operationId,
      proofHmac: f.footprint.proofHmac, alreadyClosed: false, coveredPresent: 5, nativeSuccesses: 0, knownNotSent: 1, unattempted: 1 });
    expect(proof).not.toHaveProperty('sessionId'); expect(proof).not.toHaveProperty('graph'); expect(proof).not.toHaveProperty('packets'); expect(Object.isFrozen(proof)).toBe(true);
    expect(f.reader.certifyKnownNoSendPartialSource).toHaveBeenCalledWith(expect.objectContaining({ clusterId: f.source.clusterId, workspaceId: f.source.workspaceId,
      entryId: f.entryId, subjectAction: 'write' }), f.source.id, f.txMock);
    expect(f.input.envelope).toEqual(before); expect(f.txMock.exec).not.toHaveBeenCalled(); expect(f.txMock.transaction).not.toHaveBeenCalled();
    f.footprint.alreadyClosed = true; expect(await certifyPartialNoSendTerminalMetadata(f.input)).toEqual({ ...proof, alreadyClosed: true });
  });
  it.each(['sourceId', 'workflowExecutionId', 'materialHmac', 'graphHmac', 'historyCoverageHmac', 'oldSourceId', 'failedPacketKey', 'failedNodeKey'] as const)('rejects an authenticated footprint attached to a different %s', async field => {
    const f = partialNoSendTerminalFixture(); f.footprint[field] = field.endsWith('Hmac') ? '0'.repeat(64) : randomUUID();
    await expect(certifyPartialNoSendTerminalMetadata(f.input)).rejects.toMatchObject(invalid); expect(f.txMock.exec).not.toHaveBeenCalled();
  });
  it('rejects wrong caller workspace/owner or coherent packet body corruption before calling the Reader', async () => {
    for (const edit of [(f: any) => { f.actor.workspaceId = randomUUID(); }, (f: any) => { f.actor.user.id = randomUUID(); },
      (f: any) => { f.envelope.prepared.packets[0].body.secret = 'synthetic-corruption'; f.resignEnvelope(); }]) {
      const f = partialNoSendTerminalFixture(); edit(f); await expect(certifyPartialNoSendTerminalMetadata(f.input)).rejects.toMatchObject(invalid);
      expect(f.reader.certifyKnownNoSendPartialSource).not.toHaveBeenCalled();
    }
  });
  it('fails closed when the real Reader refuses missing/unknown/unaudited evidence, and hides its internal details', async () => {
    const f = partialNoSendTerminalFixture(); f.reader.certifyKnownNoSendPartialSource.mockRejectedValue(new Error('synthetic private fact diagnostic'));
    await expect(certifyPartialNoSendTerminalMetadata(f.input)).rejects.toMatchObject(invalid); expect(f.txMock.exec).not.toHaveBeenCalled();
  });
});
