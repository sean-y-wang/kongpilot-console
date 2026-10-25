import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { lockedConflict } from '../../apps/console-api/src/infrastructure/redis.service';

describe('M11 RESOURCE_LOCKED message reflects lock scope', () => {
  it.each(['mutation:kong-a', 'index:3f2a', 'kong:scope-1:write'])('cluster-level lock %s says cluster', key => {
    const body: any = lockedConflict(key).getResponse();
    expect(body).toMatchObject({ code: 'RESOURCE_LOCKED', lockScope: 'cluster' });
    expect(body.message).toContain('集群级写锁');
    expect(body.message).not.toContain('同一对象');
  });
  it.each(['workflow:1', 'configuration:2', 'iam-change:u:k'])('object lock %s keeps object wording', key => {
    expect(lockedConflict(key).getResponse()).toMatchObject({ code: 'RESOURCE_LOCKED', lockScope: 'object', message: '同一对象正在变更，请稍后重试' });
  });
});
