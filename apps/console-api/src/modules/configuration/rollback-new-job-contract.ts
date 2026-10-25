import { ConflictException, ForbiddenException } from '@nestjs/common';
import { UUID } from '../config-transfer/schema-normalization';

/**
 * KP-005: rollbackPreview / apply of a rollback plan must open a new
 * configuration job (and execution when present). Reusing the source apply
 * job id is never a rollback completion certificate.
 */
export function assertRollbackIsNewConfigurationJob(input: Readonly<{
  mode: string;
  sourceJobId: string;
  rollbackJobId: string;
  sourceExecutionId?: string | null;
  rollbackExecutionId?: string | null;
}>): void {
  if (input.mode !== 'rollback') {
    throw new ForbiddenException({
      code: 'CONFIGURATION_ROLLBACK_MODE_REQUIRED',
      message: '回滚工单合同仅适用于 mode=rollback',
    });
  }
  if (!UUID.test(input.sourceJobId) || !UUID.test(input.rollbackJobId)) {
    throw new ForbiddenException({
      code: 'CONFIGURATION_ROLLBACK_JOB_INVALID',
      message: '回滚工单标识无效',
    });
  }
  if (input.sourceJobId === input.rollbackJobId) {
    throw new ConflictException({
      code: 'CONFIGURATION_ROLLBACK_REQUIRES_NEW_JOB',
      message: '回滚须开立新配置工单，禁止复用源发布工单',
    });
  }
  if (input.sourceExecutionId != null && input.rollbackExecutionId != null) {
    if (typeof input.sourceExecutionId !== 'string' || !UUID.test(input.sourceExecutionId)
      || typeof input.rollbackExecutionId !== 'string' || !UUID.test(input.rollbackExecutionId)) {
      throw new ForbiddenException({
        code: 'CONFIGURATION_ROLLBACK_EXECUTION_INVALID',
        message: '回滚执行标识无效',
      });
    }
    if (input.sourceExecutionId === input.rollbackExecutionId) {
      throw new ConflictException({
        code: 'CONFIGURATION_ROLLBACK_REQUIRES_NEW_EXECUTION',
        message: '回滚须开立新执行，禁止复用源发布执行',
      });
    }
  }
}
