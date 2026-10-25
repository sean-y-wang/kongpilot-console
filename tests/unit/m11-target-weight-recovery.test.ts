import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {targetWeightRecoveryOperation} from '../../apps/console-api/src/modules/workflows/target-weight-recovery';

/** Pure intent selection over explicit historical/current domain facts.
 * This does not certify a Native201, grant, original packet or approval. */
function fixture(weight=80){
  const secrets=new SecretService(),upstream=randomUUID(),oldId=randomUUID(),newId=randomUUID(),
    before={id:oldId,target:'echo.internal:8080',weight:100,tags:['owner:unit'],upstream:{id:upstream},created_at:1},
    original:any={key:`targets:${upstream}:${oldId}`,nativeType:'targets',nativeId:oldId,parentId:upstream,affected:true,present:true,
      dependencies:[],before,restorePayload:structuredClone(before),schemaMaterial:{fields:[]},trustedProvenance:{kind:'native-observed'},recovery:'complete'},
    packet={nativeId:newId,originalNativeId:oldId,parentId:upstream,mutationAction:'update',nativeStatus:201},
    body={id:newId,target:before.target,weight,tags:['owner:unit']},result={...body,upstream:{id:upstream},created_at:2},
    current:any=weight===0?null:structuredClone(result);
  return{secrets,original,packet,body,result,current,oldId,newId,upstream,
    prepare:()=>targetWeightRecoveryOperation(original,packet,result,body,current,secrets)};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('Target rollback uses a new approved append intent',()=>{
  it('restores old weight using the current new UUID as logical before; never reuses historical UUID in the body',()=>{
    const f=fixture(),operation:any=f.prepare();expect(operation).toEqual({kind:'target',action:'weight',upstreamId:f.upstream,targetId:f.newId,body:{target:f.body.target,weight:100,tags:['owner:unit']}});
    expect(operation.targetId).not.toBe(f.oldId);expect(operation.body.id).toBeUndefined();expect(Object.isFrozen(operation)).toBe(true);expect(f.current.weight).toBe(80);
  });
  it('turns a genuine current zero-weight absence into fresh create while retaining old baseline as history',()=>{
    const f=fixture(0),operation:any=f.prepare();expect(operation).toMatchObject({kind:'target',action:'create',upstreamId:f.upstream,body:{weight:100,target:f.body.target}});
    expect(operation.targetId).toBeUndefined();expect(operation.body.id).toBeUndefined();expect(f.original.nativeId).toBe(f.oldId);expect(f.result.weight).toBe(0);
  });
  it.each([0,200,204,400,503])('does not infer an original 201 from status %s',status=>{const f=fixture();f.packet.nativeStatus=status;expect(f.prepare).toThrow();});
  it.each(['missing-original','wrong-parent','not-update','same-id','changed-target','bad-weight','wrong-result-id','wrong-result-weight','wrong-result-parent','wrong-result-tags','not-affected','not-present','missing-restore','changed-restore-address','zero-original-weight','changed-restore-weight','changed-restore-tags'])('refuses incomplete or changed original facts: %s',defect=>{
    const f=fixture();
    if(defect==='missing-original')f.packet.originalNativeId=randomUUID();if(defect==='wrong-parent')f.packet.parentId=randomUUID();
    if(defect==='not-update')f.packet.mutationAction='mark_healthy';if(defect==='same-id')f.packet.nativeId=f.oldId;
    if(defect==='changed-target')f.body.target='other.internal:8080';if(defect==='bad-weight')f.body.weight=1001;
    if(defect==='wrong-result-id')f.result.id=randomUUID();if(defect==='wrong-result-weight')f.result.weight=81;
    if(defect==='wrong-result-parent')f.result.upstream.id=randomUUID();if(defect==='wrong-result-tags')f.result.tags=['other'];
    if(defect==='not-affected')f.original.affected=false;if(defect==='not-present')f.original.present=false;
    if(defect==='missing-restore')delete f.original.restorePayload;if(defect==='changed-restore-address')f.original.restorePayload.target='other.internal:8080';
    if(defect==='zero-original-weight')f.original.restorePayload.weight=0;if(defect==='changed-restore-weight')f.original.restorePayload.weight=90;
    if(defect==='changed-restore-tags')f.original.restorePayload.tags=['new-scope'];expect(f.prepare).toThrow();
  });
  it.each(['different-id','different-weight','different-tags','missing-current'])('does not overwrite later current state: %s',defect=>{
    const f=fixture();if(defect==='different-id')f.current.id=randomUUID();if(defect==='different-weight')f.current.weight=60;
    if(defect==='different-tags')f.current.tags=['changed'];if(defect==='missing-current')f.current=null;
    expect(()=>targetWeightRecoveryOperation(f.original,f.packet,f.result,f.body,f.current,f.secrets)).toThrow();
  });
  it('refuses an effective target after the original zero-weight success rather than overriding another change',()=>{
    const f=fixture(0);expect(()=>targetWeightRecoveryOperation(f.original,f.packet,f.result,f.body,{...f.result,weight:70},f.secrets)).toThrow();
  });
});
