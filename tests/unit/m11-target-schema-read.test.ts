import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { executionFixture } from './execution-test-fixture';
import { PAY_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actor = { user: { id: 'target-schema-reader', username: 'reader', superAdmin: false }, workspaceId: wid };
function fixture() {
  const { resolver } = workspaceTestResolver(cid), secrets = new SecretService();
  const kong: any = { schema: vi.fn(async () => ({ fields: [{ weight: { type: 'integer', between: [0, 1000] } }] })) };
  const authz: any = { assertCluster: vi.fn() };
  const service = new EntityService(kong, authz, {} as any, {} as any, {} as any, secrets, {} as any, {} as any, resolver, executionFixture());
  return { kong, authz, service };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'b8'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());
describe('nested Target schema read', () => {
  it('requires current targets read scope before requesting the existing Kong schema', async () => {
    const f = fixture(); await f.service.schema(cid, 'targets', actor);
    expect(f.authz.assertCluster).toHaveBeenCalledWith(actor.user, cid, 'targets', 'read', wid);
    expect(f.kong.schema).toHaveBeenCalledWith(cid, 'targets');
  });
  it('rejects forbidden schema scope before any Kong call', async () => {
    const f = fixture(); f.authz.assertCluster.mockRejectedValue(new ForbiddenException());
    await expect(f.service.schema(cid, 'targets', actor)).rejects.toMatchObject({ status: 403 });
    expect(f.kong.schema).not.toHaveBeenCalled();
  });
  it('does not expand schema access to unsupported entity names', async () => {
    const f = fixture(); await expect(f.service.schema(cid, 'vaults', actor)).rejects.toMatchObject({ response: { code: 'UNKNOWN_ENTITY_TYPE' } });
    expect(f.kong.schema).not.toHaveBeenCalled();
  });
});
