import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {annotationWorkflowFixture} from '../fixtures/m11-annotation-workflow.fixture';

/** Independent integration review of pg's default timestamptz Date objects.
 * The real Main/Business/original services and Core ALS are used with the
 * existing explicit SQL/Approved transport fixture. This is SOURCE-only:
 * it does not execute PostgreSQL or assert migration/runtime acceptance. */
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6f'.repeat(32));vi.stubEnv('RECYCLE_RETENTION_DAYS','30');});
afterEach(()=>vi.unstubAllEnvs());
function pgDateRows(f:ReturnType<typeof annotationWorkflowFixture>):void {
 const original=f.tx.one.getMockImplementation()!;
 f.tx.one.mockImplementation(async(sql:string,params?:any[])=>{
  const row:any=await original(sql,params);
  if(!row||row.cluster_id!==f.cid||row.entity_type!=='services'||row.kong_id!==f.entityId)return row;
  for(const key of ['created_at','updated_at','deleted_at','retention_until'])if(typeof row[key]==='string')row[key]=new Date(row[key]);
  return row;
 });
}
describe('Annotation review: pg Date rows do not break sealed before/after or original completion',()=>{
 it('accepts the first set and later partial set with actual Date-shaped returned row fields',async()=>{
  const f=annotationWorkflowFixture();pgDateRows(f);const prepared:any=await f.prepare(),submitted:any=await f.submit(prepared);await f.execute(f.state().plans.get(submitted.workflowId));
  expect(f.state().annotation).toMatchObject({status:'active',revision:1,description:'Approved annotation'});
  f.author.idempotencyKey='pg-date-partial-set-prepare';const next:any=await f.prepare({entityType:'services',entityId:f.entityId,operation:'set',input:{revision:1,description:'Updated without replacing metadata'}});
  const capture=f.intent(next.intentId).capture;expect(typeof capture.before.created_at).toBe('string');expect(typeof capture.before.updated_at).toBe('string');
  const submittedNext:any=await f.http(()=>f.workflow.submit(f.cid,f.wid,next.intentId,{confirmed:true,materialHmac:next.materialHmac},{...f.author,idempotencyKey:'pg-date-partial-set-submit'}));await f.execute(f.state().plans.get(submittedNext.workflowId));
  expect(f.state().annotation).toMatchObject({status:'active',revision:2,description:'Updated without replacing metadata',metadata:{business:'payments'}});expect(f.state().facts.size).toBe(2);
 });
 it('accepts Date-shaped deletion/retention timestamps across remove and separately approved restore',async()=>{
  const f=annotationWorkflowFixture();pgDateRows(f);const prepared:any=await f.prepare(),submitted:any=await f.submit(prepared);await f.execute(f.state().plans.get(submitted.workflowId));
  f.author.idempotencyKey='pg-date-remove-prepare';const remove:any=await f.prepare({entityType:'services',entityId:f.entityId,operation:'remove',input:{revision:1,confirmed:true,confirm_name:'payments'}}),removeSubmitted:any=await f.http(()=>f.workflow.submit(f.cid,f.wid,remove.intentId,{confirmed:true,materialHmac:remove.materialHmac},{...f.author,idempotencyKey:'pg-date-remove-submit'}));await f.execute(f.state().plans.get(removeSubmitted.workflowId));
  expect(f.state().annotation).toMatchObject({status:'deleted',revision:2});
  f.author.idempotencyKey='pg-date-restore-prepare';const restore:any=await f.prepare({entityType:'services',entityId:f.entityId,operation:'restore',input:{revision:2,confirmed:true,confirm_name:'payments'}}),capture=f.intent(restore.intentId).capture;
  expect(typeof capture.before.deleted_at).toBe('string');expect(typeof capture.before.retention_until).toBe('string');
  const restoreSubmitted:any=await f.http(()=>f.workflow.submit(f.cid,f.wid,restore.intentId,{confirmed:true,materialHmac:restore.materialHmac},{...f.author,idempotencyKey:'pg-date-restore-submit'}));await f.execute(f.state().plans.get(restoreSubmitted.workflowId));
  expect(f.state().annotation).toMatchObject({status:'active',revision:3,deleted_at:null,retention_until:null,description:'Approved annotation'});expect(f.state().facts.size).toBe(3);expect(f.nativeCalls.every(call=>call.method==='GET')).toBe(true);
 });
});
