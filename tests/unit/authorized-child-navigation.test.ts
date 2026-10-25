import 'reflect-metadata';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException,NotFoundException } from '@nestjs/common';
import { AuthorizationController } from '../../apps/console-api/src/modules/authorization/authorization.controller';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { workspaceFixture,payWorkspaceId,opsWorkspaceId } from './workspace-test-fixture';
import { executionFixture } from './execution-test-fixture';

// Controller/database navigation fixtures; actual grant engine and native
// membership/response boundaries have separate real-implementation tests.
const cid=randomUUID(),uid=randomUUID(),parent=randomUUID(),id=randomUUID(),actor={user:{id:uid,username:'child-only',superAdmin:false}};
function fixture(){
 const secrets=new SecretService(),row={child_type:'key-auth',child_id:id,parent_type:'consumers',parent_id:parent};
 const db:any={query:vi.fn().mockResolvedValue([row])};
 const authz:any={assertCluster:vi.fn(),snapshot:vi.fn().mockResolvedValue({version:'epoch-1'}),permissionVersion:vi.fn().mockResolvedValue('epoch-1'),assertEntity:vi.fn(),
  entityCapabilities:vi.fn().mockResolvedValue({read:true,write:false,delete:false,approve:false,reveal:false})};
 const kong:any={request:vi.fn().mockResolvedValue({id,key:'synthetic-navigation-secret',consumer:{id:parent},tags:['kos-ws-pay']})};
 const controller=new AuthorizationController(authz,kong,executionFixture(),workspaceFixture(cid).resolver,db,secrets);
 return {controller,authz,kong,db,secrets,row};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','dc'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());
describe('bounded child-only navigation and capability projection',()=>{
 it('rereads the exact child, masks secrets and never requests parent configuration',async()=>{const f=fixture(),page=await f.controller.children(cid,{workspaceId:payWorkspaceId,type:'key-auth'},actor);expect(page.items).toHaveLength(1);expect(page.items[0]).toMatchObject({type:'key-auth',id,parent_id:parent,entity:{key:expect.stringMatching(/^\[REDACTED/)}});expect(f.kong.request).toHaveBeenCalledOnce();expect(f.kong.request).toHaveBeenCalledWith(cid,'GET',`/consumers/${parent}/key-auth/${id}`);expect(JSON.stringify(page)).not.toContain('synthetic-navigation-secret');expect(page.total).toBeNull();});
 it('does not let a stale owner cache or endpoint alias move a child to another parent or ID',async()=>{for(const altered of [{id:randomUUID(),consumer:{id:parent}},{id,consumer:{id:randomUUID()}}]){const f=fixture();f.kong.request.mockResolvedValue(altered);const page=await f.controller.children(cid,{workspaceId:payWorkspaceId,type:'key-auth'},actor);expect(page.items).toEqual([]);expect(f.authz.assertEntity).not.toHaveBeenCalled();}});
 it('filters forbidden/deleted actual objects without returning cached IDs or parent names',async()=>{for(const error of [new ForbiddenException(),new NotFoundException()]){const f=fixture();f.kong.request.mockRejectedValue(error);const page=await f.controller.children(cid,{workspaceId:payWorkspaceId},actor);expect(page.items).toEqual([]);expect(page.discovery).toBe('observed-parent-index');}});
 it('binds a resumable cursor to actor, workspace, size and permission epoch',async()=>{const f=fixture();f.db.query.mockResolvedValue([f.row,{...f.row,child_id:randomUUID()}]);const first=await f.controller.children(cid,{workspaceId:payWorkspaceId,type:'key-auth',size:1},actor);expect(first.nextCursor).toBeTruthy();for(const [query,who] of [[{workspaceId:opsWorkspaceId,type:'key-auth',size:1},actor],[{workspaceId:payWorkspaceId,type:'key-auth',size:2},actor],[{workspaceId:payWorkspaceId,type:'key-auth',size:1},{user:{...actor.user,id:randomUUID()}}]] as any){await expect(f.controller.children(cid,{...query,cursor:first.nextCursor},who)).rejects.toMatchObject({status:400});}f.authz.snapshot.mockResolvedValue({version:'epoch-2'});await expect(f.controller.children(cid,{workspaceId:payWorkspaceId,type:'key-auth',size:1,cursor:first.nextCursor},actor)).rejects.toMatchObject({status:400});expect(f.db.query).toHaveBeenCalledOnce();});
 it('rejects unbounded sizes, unknown query/body fields and unsupported types before inventory',async()=>{const f=fixture();for(const query of [{size:0},{size:51},{size:'nan'},{type:'services'},{all:true}])await expect(f.controller.children(cid,query,actor)).rejects.toMatchObject({status:400});expect(f.db.query).not.toHaveBeenCalled();});
 it('rejects an epoch change during navigation instead of attaching stale flags to a new version',async()=>{const f=fixture();f.authz.permissionVersion.mockResolvedValue('epoch-2');await expect(f.controller.children(cid,{workspaceId:payWorkspaceId,type:'key-auth'},actor)).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED'}});});
 it('does not project another parent or endpoint-alias identity as an authorized own ID',async()=>{const f=fixture();f.kong.request.mockResolvedValue({id,consumer:{id:randomUUID()}});const projected=await f.controller.entityCapabilities(cid,payWorkspaceId,{entities:[{type:'key-auth',id,parent_id:parent}]},actor);expect(projected.items[0]).toMatchObject({read:false,write:false,reveal:false});expect(f.authz.entityCapabilities).not.toHaveBeenCalled();});
});
