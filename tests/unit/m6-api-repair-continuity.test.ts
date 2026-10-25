import { describe, expect, it } from 'vitest';
import { repairContainerProjection, apiRepairContinuityChecks, apiRepairContinuityMain } from '../../deploy/scripts/verify-api-repair-continuity.mjs';

function inspected() {
  return { Id: 'same-container', Image: 'same-image', State: { StartedAt: 'first-process' },
    Config: { Env: ['APP_SECRET=synthetic-do-not-publish', 'DATABASE_URL=synthetic-private-url'] },
    Mounts: [{ Type: 'volume', Name: 'kept-data', Destination: '/data' }],
    NetworkSettings: { Networks: { private: { NetworkID: 'same-network', IPAddress: '172.28.41.10' } } } };
}
function snapshot() {
  return { services: [repairContainerProjection('portal-web', inspected()), repairContainerProjection('console-web', inspected())],
    api: repairContainerProjection('console-api', inspected(), false), materialSHA256: 'same-private-material',
    database: { settings: [{ cluster_id: 'same-cluster', credential_generation: 2, catalog_revision: 3 }], epochCount: 12, epochIdentitySHA256: 'same-epochs' } };
}
const passed = (before: any, after: any) => apiRepairContinuityChecks(before, after).every((row: any) => row.passed);

describe('API-only repair continuity proof without runtime calls', () => {
  it('permits only the API process timestamp to change and never projects private environment values', () => {
    const before = snapshot(), changed = inspected(); changed.State.StartedAt = 'restarted-process';
    const after = snapshot(); after.api = repairContainerProjection('console-api', changed, false);
    expect(passed(before, after)).toBe(true);
    const output = JSON.stringify(after);
    expect(output).not.toContain('synthetic-do-not-publish'); expect(output).not.toContain('synthetic-private-url');
    expect(output).not.toContain('APP_SECRET'); expect(output).not.toContain('DATABASE_URL');
  });
  it.each(['id', 'image', 'envSHA256', 'networks', 'volumes'])('rejects API recreation or changed %s', field => {
    const before = snapshot(), after: any = snapshot(); after.api[field] = 'changed'; expect(passed(before, after)).toBe(false);
  });
  it.each(['portal-web', 'console-web'])('rejects an unrelated %s process restart', name => {
    const before = snapshot(), after = snapshot(); after.services.find(row => row.name === name)!.startedAt = 'different'; expect(passed(before, after)).toBe(false);
  });
  it('rejects private material changes, family rotations and epoch changes independently', () => {
    const before = snapshot();
    for (const change of [(after: any) => after.materialSHA256 = 'changed', (after: any) => after.database.settings[0].credential_generation++, (after: any) => after.database.epochCount++, (after: any) => after.database.epochIdentitySHA256 = 'changed']) {
      const after = snapshot(); change(after); expect(passed(before, after)).toBe(false);
    }
  });
  it('rejects extra or missing preserved services', () => {
    const before = snapshot(), extra = snapshot(), missing = snapshot(); extra.services.push(repairContainerProjection('extra', inspected())); missing.services.pop();
    expect(passed(before, extra)).toBe(false); expect(passed(before, missing)).toBe(false);
  });
  it.each([[], ['--before'], ['--after', '../escape'], ['--before', 'safe', 'extra'], ['--rotate', 'safe']])('rejects invalid arguments before any Docker/read operation', args => {
    expect(() => apiRepairContinuityMain(args)).toThrow('API_REPAIR_ARGUMENTS_INVALID');
  });
});
