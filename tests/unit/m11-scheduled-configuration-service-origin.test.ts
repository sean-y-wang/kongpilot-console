import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationService,CONFIGURATION_SCHEDULED_NESTED_ORIGIN_INSERT_SQL} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
const id=(n:number)=>`5f000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','da'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
/** Actual Service bootstrap/Repository callback implementation; Access,
 * namespace and SQL engine are explicit doubles. Assertions prove ordering
 * and fail-closed dependency boundaries, not a real PostgreSQL transaction. */
function fixture(){
 const proof:any={jobId:id(1),actor:{id:id(2)},clusterId:id(3),workspaceId:id(4),wrapperOriginId:id(5),claimId:id(6),wrapperExecutionId:id(7),planId:id(8),planRevision:2,planHash:'8'.repeat(64),permissionVersion:'actual-v1'};
 const state={scheduled:true,namespace:true,rows:1},access:any={isWorkflowScheduledConfigurationJob:vi.fn(()=>state.scheduled),workflowScheduledConfigurationJobProof:vi.fn(async()=>proof),installWorkflowScheduledConfigurationOrigin:vi.fn()};
 const context:any={hasWorkflowScheduledNamespace:()=>state.namespace},approved:any={installWorkflowScheduledConfigurationDelegate:vi.fn()},tx:any={exec:vi.fn(async()=>state.rows)},repo:any={installScheduledExecutionOriginPolicy:vi.fn(),installEvidenceWriter:vi.fn()};
 const service=new ConfigurationService({}as any,{}as any,new SecretService(),context,{}as any,{}as any,{}as any,access,repo,{}as any,{}as any,{}as any,{}as any,approved,{}as any,{}as any,{}as any);
 const origin:any={runOriginalJob:vi.fn(),verifyConfigurationExecution:vi.fn()},handle=Object.freeze({});
 return{service,proof,state,access,context,approved,tx,repo,origin,handle,created:()=>((service as any).scheduledConfigurationOriginCreated(tx,handle,id(9))as Promise<void>)};
}
describe('configuration Service scheduled nested-origin writer',()=>{
 it('once installs fixed original provider in Access and Approved without accepting a per-call callback',()=>{const f=fixture();f.service.installWorkflowScheduledConfigurationOrigin(f.origin);expect(f.access.installWorkflowScheduledConfigurationOrigin).toHaveBeenCalledWith(f.origin);expect(f.approved.installWorkflowScheduledConfigurationDelegate).toHaveBeenCalledTimes(1);expect(()=>f.service.installWorkflowScheduledConfigurationOrigin(f.origin)).toThrow();});
 it('ordinary genuine HTTP jobs add no SQL026 origin',async()=>{const f=fixture();f.state.scheduled=false;f.state.namespace=false;await f.created();expect(f.tx.exec).not.toHaveBeenCalled();expect(f.access.workflowScheduledConfigurationJobProof).not.toHaveBeenCalled();});
 it('never downgrades a scheduled namespace into an ordinary Access handle',async()=>{const f=fixture();f.state.scheduled=false;await expect(f.created()).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGINAL_JOB_REQUIRED'}});expect(f.tx.exec).not.toHaveBeenCalled();});
 it('requires original provider before writing actual nested origin',async()=>{const f=fixture();await expect(f.created()).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_UNAVAILABLE'}});expect(f.tx.exec).not.toHaveBeenCalled();});
 it('verifies the private job inside the original Repository transaction and inserts only exact allocated nested execution',async()=>{const f=fixture();f.service.installWorkflowScheduledConfigurationOrigin(f.origin);await f.created();expect(f.access.workflowScheduledConfigurationJobProof).toHaveBeenCalledWith(f.handle,f.tx);
  const [sql,p]=f.tx.exec.mock.calls[0];expect(sql).toBe(CONFIGURATION_SCHEDULED_NESTED_ORIGIN_INSERT_SQL);expect(p.slice(1)).toEqual([f.proof.wrapperOriginId,f.proof.claimId,f.proof.wrapperExecutionId,id(9),f.proof.jobId,f.proof.actor.id,f.proof.clusterId,f.proof.workspaceId,f.proof.planId,f.proof.planRevision,f.proof.planHash,f.proof.permissionVersion]);
 });
 it.each([0,2])('fails atomically for %s matched nested origins rather than inventing a receipt',async rows=>{const f=fixture();f.service.installWorkflowScheduledConfigurationOrigin(f.origin);f.state.rows=rows;await expect(f.created()).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_NESTED_ORIGIN_CONFLICT'}});});
 it('rejects a revoked original job before any nested-origin INSERT',async()=>{const f=fixture();f.service.installWorkflowScheduledConfigurationOrigin(f.origin);f.access.workflowScheduledConfigurationJobProof.mockRejectedValueOnce(Error('REVOKED_ORIGINAL_CLAIM'));await expect(f.created()).rejects.toThrow('REVOKED_ORIGINAL_CLAIM');expect(f.tx.exec).not.toHaveBeenCalled();});
});
