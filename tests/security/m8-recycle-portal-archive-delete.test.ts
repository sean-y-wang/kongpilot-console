import{describe,it,expect,vi}from'vitest';
import{RecycleService}from'../../apps/console-api/src/modules/recycle-bin/recycle.service';
import type{RecycleGraph}from'../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const serviceId=id(10),keyPlugin=id(11),aclPlugin=id(12),cid=id(3),wid=id(4);
function serviceGraph(extra:Array<{type:string;id:string;path:string;data:any}>=[]):RecycleGraph{
  const root:any={key:'root',type:'services',id:serviceId,data:{id:serviceId,name:'portal-svc'},restoreData:{id:serviceId,name:'portal-svc'},path:`/services/${serviceId}`,affected:true,dependencies:[],restorable:true};
  const nodes=[root,...extra.map((item,i)=>({key:`n${i}`,type:item.type,id:item.id,data:item.data,restoreData:item.data,path:item.path,affected:true,dependencies:['root'],restorable:true}))];
  return{rootKey:'root',nodes,complete:true,capturedAt:new Date().toISOString()};
}
function fixture(owned:boolean|((sql:string,p:any[])=>any[])){
  const query=vi.fn(async(sql:string,p:any[])=>{
    expect(sql).toContain('portal_publications');
    expect(sql).toContain('m6_portal_scope_alias');
    if(typeof owned==='function')return owned(sql,p);
    return owned?[{id:id(9)}]:[];
  });
  const db:any={query,one:vi.fn(),exec:vi.fn(),transaction:vi.fn()};
  const service=new RecycleService(db,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any);
  return{service,query,db};
}
describe('M8 recycle Portal published archive-delete fail-fast',()=>{
  it('blocks published service id before durable archive',async()=>{
    const f=fixture(true),g=serviceGraph();
    await expect(f.service.assertPortalArchiveDeleteAllowed(cid,g)).rejects.toMatchObject({response:{code:'PORTAL_PUBLISHED_OBJECT'}});
    expect(f.query.mock.calls[0][1][0]).toBe(cid);
    expect(f.query.mock.calls[0][1][1]).toContain(serviceId);
  });
  it('blocks publication key-auth / acl plugin ids in the same graph',async()=>{
    const f=fixture((sql,p)=>p[1].includes(keyPlugin)||p[1].includes(aclPlugin)?[{id:id(9)}]:[]);
    const g=serviceGraph([
      {type:'plugins',id:keyPlugin,path:`/plugins/${keyPlugin}`,data:{id:keyPlugin,name:'key-auth',service:{id:serviceId}}},
      {type:'plugins',id:aclPlugin,path:`/plugins/${aclPlugin}`,data:{id:aclPlugin,name:'acl',service:{id:serviceId}}},
    ]);
    await expect(f.service.assertPortalArchiveDeleteAllowed(cid,g)).rejects.toMatchObject({response:{code:'PORTAL_PUBLISHED_OBJECT'}});
  });
  it('permits ordinary unpublished service graphs after DB ownership miss',async()=>{
    const f=fixture(false),g=serviceGraph([{type:'routes',id:id(20),path:`/routes/${id(20)}`,data:{id:id(20),service:{id:serviceId}}}]);
    await expect(f.service.assertPortalArchiveDeleteAllowed(cid,g)).resolves.toBeUndefined();
    expect(f.query).toHaveBeenCalledTimes(1);
  });
  it('skips DB when no affected node ids are present',async()=>{
    const g=serviceGraph();g.nodes.forEach(n=>{(n as any).affected=false;});
    const f=fixture(true);
    await expect(f.service.assertPortalArchiveDeleteAllowed(cid,g)).resolves.toBeUndefined();
    expect(f.query).not.toHaveBeenCalled();
  });
  it('rejects DB-unavailable ownership checks instead of archiving',async()=>{
    const f=fixture(false);f.query.mockRejectedValue(new Error('synthetic db unavailable'));
    await expect(f.service.assertPortalArchiveDeleteAllowed(cid,serviceGraph())).rejects.toThrow('synthetic db unavailable');
  });
});
