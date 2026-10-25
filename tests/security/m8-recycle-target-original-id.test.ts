import{describe,it,expect,vi}from'vitest';
import{ForbiddenException,NotFoundException}from'@nestjs/common';
import{RecycleService}from'../../apps/console-api/src/modules/recycle-bin/recycle.service';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`,cid=id(1),wid=id(2),upstream=id(3),target=id(4),newTarget=id(5),entryId=id(6),actor={id:id(7),username:'synthetic',superAdmin:false};
function fixture({shared=false,readError=undefined,wrong=undefined}:{shared?:boolean;readError?:Error;wrong?:string}={}){
 const parent={key:`upstreams:${upstream}`,type:'upstreams',id:upstream,path:`/upstreams/${upstream}`,data:{id:upstream,name:'synthetic-upstream',tags:['workspace:synthetic']},affected:!shared,dependencies:[],restorable:true};
 const child={key:`targets:${target}`,type:'targets',id:target,path:`/upstreams/${upstream}/targets/${target}`,data:{id:target,target:'127.0.0.1:8081',weight:100,upstream:{id:upstream}},affected:true,dependencies:[parent.key],restorable:true};
 const graph:any={complete:true,rootKey:shared?child.key:parent.key,nodes:[parent,child],capturedAt:new Date().toISOString()};
 const entry={id:entryId,cluster_id:cid,workspace_id:wid,root_type:shared?'targets':'upstreams',original_id:shared?target:upstream,root_name:'synthetic',payload_secret:'synthetic-seal',state:'deleted',actor_id:actor.id};
 let actualParent:any=shared?parent.data:undefined,actualTarget:any;
 const db:any={one:vi.fn(async(sql:string)=>sql.includes('FROM configuration_recycle_components')?null:sql.includes('restore_state')?{delete_state:'deleted',restore_state:'pending'}:entry),query:vi.fn(async()=>[]),exec:vi.fn(async()=>1),transaction:vi.fn(async(fn:any)=>fn(db))};
 const kong:any={list:vi.fn(async()=>({items:[],nextCursor:null,size:100})),request:vi.fn(async(_cid:string,method:string,path:string,body:any)=>{
   if(method==='POST'&&path==='/upstreams'){actualParent={...body};return actualParent;}
   if(method==='POST'&&path===`/upstreams/${upstream}/targets`){actualTarget={...body,id:body.id??newTarget,upstream:{id:upstream}};if(wrong==='id')actualTarget.id=newTarget;if(wrong==='parent')actualTarget.upstream.id=id(99);if(wrong==='address')actualTarget.target='foreign:8081';if(wrong==='weight')actualTarget.weight=50;return actualTarget;}
   if(path===parent.path){if(actualParent)return actualParent;throw new NotFoundException();}
   if(path===child.path&&readError)throw readError;
   if(actualTarget&&path===`/upstreams/${upstream}/targets/${actualTarget.id}`)return actualTarget;
   if(shared&&path===child.path)return{...child.data,weight:0};
   throw new NotFoundException();
 })};
 const authz:any={assertCluster:vi.fn(async()=>undefined),assertEntity:vi.fn(async()=>undefined),assertArchivedEntity:vi.fn(async()=>undefined)};
 const mutations:any={execute:vi.fn(async(_context:any,fn:any)=>fn())},workspaces:any={listScope:vi.fn(async()=>({workspaceId:wid})),resolve:vi.fn(async()=>({status:'active'})),assertMembership:vi.fn()};
 const secrets:any={decrypt:vi.fn(()=>graph),redact:(v:any)=>v,fingerprint:(v:any)=>JSON.stringify(v)};
 const service=new RecycleService(db,secrets,kong,mutations,{}as any,authz,{append:vi.fn(async()=>undefined)}as any,{}as any,{upsert:vi.fn(async()=>undefined)}as any,workspaces,{runInternalRead:async(_cid:string,_purpose:string,fn:any)=>fn()}as any);
 return{service,kong,db,parent,child,restore:()=>service.restore(cid,entryId,actor,{confirmed:true,confirm_name:'synthetic'},{workspaceId:wid})};
}
describe('M8 actual Recycle Target restore ID boundary',()=>{
 it('retains original UUID only with affected Upstream and original Target GET404, then verifies parent/address/weight',async()=>{
   const f=fixture(),r=await f.restore();expect(r.state).toBe('restored');const call=f.kong.request.mock.calls.find((v:any[])=>v[1]==='POST'&&v[2].endsWith('/targets'));expect(call[3]).toMatchObject({id:target,target:'127.0.0.1:8081',weight:100});expect(call[3]).not.toHaveProperty('upstream');expect(r.restored.find((v:any)=>v.type==='targets').restoredId).toBe(target);
 });
 it('single Target/shared parent keeps immutable old history and appends a new physical ID',async()=>{
   const f=fixture({shared:true}),r=await f.restore();const call=f.kong.request.mock.calls.find((v:any[])=>v[1]==='POST'&&v[2].endsWith('/targets'));expect(call[3]).not.toHaveProperty('id');expect(r.restored.find((v:any)=>v.type==='targets').restoredId).toBe(newTarget);
 });
 it('forbidden original-Target GET is never interpreted as 404 absence',async()=>{
   const f=fixture({readError:new ForbiddenException()});await expect(f.restore()).rejects.toMatchObject({response:{code:'RECYCLE_RESTORE_INCOMPLETE'}});expect(f.kong.request.mock.calls.some((v:any[])=>v[1]==='POST'&&v[2].endsWith('/targets'))).toBe(false);
 });
 it.each(['id','parent','address','weight'])('rejects wrong post-write %s readback rather than declaring original UUID recovery',async(wrong)=>{
   const f=fixture({wrong});await expect(f.restore()).rejects.toMatchObject({response:{code:'RECYCLE_RESTORE_INCOMPLETE',cause:'RESTORE_TARGET_READBACK_MISMATCH'}});
 });
});
