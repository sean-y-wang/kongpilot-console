import{describe,it,expect,vi}from'vitest';
import{RecycleService}from'../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type{RecycleGraph}from'../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const consumer=id(1),key=id(2),cid=id(3),wid=id(4);
function graph(type='consumers',parent=consumer,nodeId=consumer,affected=true):RecycleGraph{const node:any={key:'root',type,id:nodeId,data:{id:nodeId,...(type==='consumers'?{username:'old'}:{consumer:{id:parent}})},restoreData:{id:nodeId,...(type==='consumers'?{username:'old'}:{consumer:{id:parent}})},path:type==='consumers'?`/consumers/${nodeId}`:`/consumers/${parent}/${type}/${nodeId}`,affected,dependencies:[],restorable:true};return{rootKey:'root',nodes:[node],complete:true,capturedAt:new Date().toISOString()};}
function fixture(g:RecycleGraph,owned=true){
  const query=vi.fn(async(sql:string,p:any[])=>{expect(sql).toContain('m6_portal_scope_alias');expect(sql).not.toMatch(/g\.state\s*=/);return owned&&(p[1].includes(consumer)||p[2].includes(key))?[{id:id(9)}]:[];});
  const db:any={query,one:vi.fn(async()=>({id:id(5),cluster_id:cid,workspace_id:null,payload_secret:'sealed',state:'deleted'})),exec:vi.fn(),transaction:vi.fn()},secrets:any={decrypt:vi.fn(()=>g)};
  const kong:any={request:vi.fn()},mutations:any={execute:vi.fn()},authz:any={assertCluster:vi.fn(async()=>undefined),assertEntity:vi.fn()},workspaces:any={listScope:vi.fn(async()=>({workspaceId:wid})),resolve:vi.fn(async()=>({status:'active'}))};
  const service=new RecycleService(db,secrets,kong,mutations,{}as any,authz,{}as any,{}as any,{}as any,workspaces,{}as any);
  const bind=vi.spyOn(service as any,'bindEntry').mockResolvedValue(undefined);return{service,db,kong,mutations,query,bind};
}
describe('M8 DB-only recycle Portal history boundary',()=>{
  it.each(['consumers','key-auth','acls','jwt','oauth2','basic-auth','hmac-auth'])('blocks historical consumer or new %s beneath it before metadata binding/Mutation/native',async(type)=>{const f=fixture(graph(type,consumer,type==='consumers'?consumer:id(55)));
    await expect(f.service.restore(cid,id(5),{id:id(6),username:'admin',superAdmin:true},{confirmed:true,confirm_name:'old'},{workspaceId:wid})).rejects.toMatchObject({response:{code:'PORTAL_MANAGED_OBJECT'}});
    expect(f.bind).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('blocks original credential UUID after moving it to unrelated consumer',async()=>{const f=fixture(graph('key-auth',id(55),key));await expect(f.service.assertPortalRestoreAllowed(cid,graph('key-auth',id(55),key))).rejects.toThrow();expect(f.query.mock.calls[0][1][2]).toContain(key);});
  it('checks original id and restoreData identity, including deleted/remapped aliases',async()=>{const g=graph('key-auth',id(55),id(56));g.nodes[0].restoreData.id=key;const f=fixture(g);await expect(f.service.assertPortalRestoreAllowed(id(99),g)).rejects.toThrow();expect(f.query.mock.calls[0][1][0]).toBe(id(99));expect(f.query.mock.calls[0][1][2]).toContain(key);});
  it('blocks reserved ACL restoration before any DB write or native call',async()=>{const g=graph('acls',id(55),id(56));g.nodes[0].data.group=`kos-portal-api-${id(66)}`;const f=fixture(g,false);await expect(f.service.assertPortalRestoreAllowed(cid,g)).rejects.toThrow();expect(f.query).not.toHaveBeenCalled();});
  it('unaffected shared consumer references do not restore any authentication',async()=>{const g=graph('consumers',consumer,consumer,false);const f=fixture(g);await expect(f.service.assertPortalRestoreAllowed(cid,g)).resolves.toBeUndefined();expect(f.query).not.toHaveBeenCalled();});
  it('permits ordinary independently owned credentials after historical DB check',async()=>{const g=graph('key-auth',id(55),id(56)),f=fixture(g);await expect(f.service.assertPortalRestoreAllowed(cid,g)).resolves.toBeUndefined();expect(f.query).toHaveBeenCalledTimes(1);expect(f.kong.request).not.toHaveBeenCalled();});
  it('rejects DB-unavailable ownership checks instead of proceeding',async()=>{const g=graph(),f=fixture(g);f.query.mockRejectedValue(new Error('synthetic db unavailable'));await expect(f.service.assertPortalRestoreAllowed(cid,g)).rejects.toThrow();expect(f.mutations.execute).not.toHaveBeenCalled();});
});
