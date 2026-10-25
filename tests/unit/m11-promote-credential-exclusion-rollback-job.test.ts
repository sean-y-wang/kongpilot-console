import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertPromoteCredentialDefaultExclusion } from '../../apps/console-api/src/modules/governance/promote-compiler';
import { assertRollbackIsNewConfigurationJob } from '../../apps/console-api/src/modules/configuration/rollback-new-job-contract';

describe('KP-005 promote credential default exclusion', () => {
  it('allows ordinary selection when includeCredentials is omitted/false', () => {
    expect(() => assertPromoteCredentialDefaultExclusion(
      { state: 'ready', selectedObjectKeys: ['services:a', 'routes:b'], document: { services: [{}] } },
      { includeCredentials: false },
    )).not.toThrow();
    expect(() => assertPromoteCredentialDefaultExclusion(
      { state: 'ready', selectedObjectKeys: ['services:a'], document: { services: [{}] } },
      {},
    )).not.toThrow();
  });

  it('rejects credential keys or document nests unless includeCredentials is true', () => {
    expect(() => assertPromoteCredentialDefaultExclusion(
      { state: 'ready', selectedObjectKeys: ['credentials:key-auth:x'], document: null },
      { includeCredentials: false },
    )).toThrow(/GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION/);
    expect(() => assertPromoteCredentialDefaultExclusion(
      { state: 'ready', selectedObjectKeys: ['services:a'], document: { credentials: [{ id: 'x' }] } },
      { includeCredentials: false },
    )).toThrow(/GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION/);
    expect(() => assertPromoteCredentialDefaultExclusion(
      { state: 'ready', selectedObjectKeys: ['credentials:key-auth:x'], document: { credentials: [{ id: 'x' }] } },
      { includeCredentials: true },
    )).not.toThrow();
  });
});

describe('KP-005 rollback opens a new configuration job', () => {
  const sourceJobId = randomUUID(), rollbackJobId = randomUUID();
  const sourceExecutionId = randomUUID(), rollbackExecutionId = randomUUID();

  it('accepts distinct rollback job (and execution) ids', () => {
    expect(() => assertRollbackIsNewConfigurationJob({
      mode: 'rollback', sourceJobId, rollbackJobId, sourceExecutionId, rollbackExecutionId,
    })).not.toThrow();
  });

  it('rejects reused source job or execution and non-rollback mode', () => {
    expect(() => assertRollbackIsNewConfigurationJob({
      mode: 'rollback', sourceJobId, rollbackJobId: sourceJobId,
    })).toThrow(/回滚须开立新配置工单|CONFIGURATION_ROLLBACK_REQUIRES_NEW_JOB/);
    expect(() => assertRollbackIsNewConfigurationJob({
      mode: 'rollback', sourceJobId, rollbackJobId, sourceExecutionId, rollbackExecutionId: sourceExecutionId,
    })).toThrow(/回滚须开立新执行|CONFIGURATION_ROLLBACK_REQUIRES_NEW_EXECUTION/);
    expect(() => assertRollbackIsNewConfigurationJob({
      mode: 'apply', sourceJobId, rollbackJobId,
    })).toThrow(/回滚工单合同仅适用于|CONFIGURATION_ROLLBACK_MODE_REQUIRED/);
  });
});
