import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { abandonmentEndpointFixture } from '../security/m6-abandonment-endpoint-fixture';

/** Actual abandonment catch and structured logger with the existing explicit
 * offline SQL/Authz/Gateway fixtures. No network, SQL migration or native write. */
beforeEach(()=>{
  vi.stubEnv('APP_SECRET','offline-abandonment-signing-secret-at-least32');
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY','de'.repeat(32));
});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});

const marker='OFFLINE_PRIVATE_ERROR_MATERIAL';
function fixture(){
  const f=abandonmentEndpointFixture();
  const log=vi.spyOn((f.service as any).logger,'error').mockImplementation(()=>undefined);
  return{...f,log};
}
describe('M6 rejected issue persistence diagnostics',()=>{
  it.each(['42501','23514','23505','40001','40P01','08006'])('logs only fixed scope and recognized SQLSTATE %s while preserving the original-key unknown response',async(code)=>{
    const f=fixture();
    const error=Object.assign(new Error(marker),{code,detail:marker,hint:marker,query:marker,body:{key:f.originalKey,cipher:marker},stack:marker});
    f.audit.append.mockRejectedValueOnce(error);
    await expect(f.invoke()).rejects.toMatchObject({status:503,response:{code:'PORTAL_ISSUE_ABANDONMENT_UNKNOWN',state:'uncertain',workflowId:f.workflow.id,executionId:f.execution.id}});
    expect(f.log).toHaveBeenCalledExactlyOnceWith({event:'portal.issue.abandon-rejected.persistence-unknown',clusterId:f.cluster.id,workspaceId:f.workspace.id,workflowId:f.workflow.id,executionId:f.execution.id,grantId:f.grant.id,category:'sql_failure',sqlState:code});
    const logged=JSON.stringify(f.log.mock.calls);
    expect(logged).not.toContain(marker);expect(logged).not.toContain(f.originalKey);
    f.unchanged();expect(f.workflow.state).toBe('failed');expect(f.execution.state).toBe('failed');
  });
  it.each([undefined,'ABCDE','42501\n'+marker,marker,42501,{state:'42501',private:marker}])('uses a fixed unknown category for an unrecognized code %j',async(code)=>{
    const f=fixture();f.audit.append.mockRejectedValueOnce(Object.assign(new Error(marker),{code,detail:marker}));
    await expect(f.invoke()).rejects.toMatchObject({response:{code:'PORTAL_ISSUE_ABANDONMENT_UNKNOWN'}});
    const record=f.log.mock.calls[0][0];expect(record).toMatchObject({category:'unknown_failure'});expect(record).not.toHaveProperty('sqlState');
    expect(JSON.stringify(f.log.mock.calls)).not.toContain(marker);f.unchanged();
  });
  it('does not convert or log a known HTTP denial as an unknown SQL failure',async()=>{
    const f=fixture();f.audit.append.mockRejectedValueOnce(new HttpException({code:'OFFLINE_KNOWN_DENIAL'},403));
    await expect(f.invoke()).rejects.toMatchObject({status:403,response:{code:'OFFLINE_KNOWN_DENIAL'}});
    expect(f.log).not.toHaveBeenCalled();f.unchanged();
  });
  it('omits malformed scope values and ignores any extra material from the private logger input',()=>{
    const f=fixture();
    (f.service as any).logAbandonmentPersistenceFailure({code:'42501',message:marker},{clusterId:marker,workspaceId:f.workspace.id,workflowId:f.workflow.id,executionId:[f.execution.id],grantId:marker,extra:marker});
    expect(f.log).toHaveBeenCalledExactlyOnceWith({event:'portal.issue.abandon-rejected.persistence-unknown',workspaceId:f.workspace.id,workflowId:f.workflow.id,category:'sql_failure',sqlState:'42501'});
    expect(JSON.stringify(f.log.mock.calls)).not.toContain(marker);
  });
});
