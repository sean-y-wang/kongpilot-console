import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {portalWholeNativeSourceFixture} from './helpers/m11-portal-whole-native-source-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
it('executes the original NativePolicy parent-index observation through its explicit Source SQL adapter',async()=>{
 const f=await portalWholeNativeSourceFixture(),row={id:f.plan.generated!.aclId,consumer:{id:f.plan.generated!.consumerId}};
 await(f.nativePolicy as any).observeChildren(f.cid,'acls',[row]);await(f.nativePolicy as any).observeChildren(f.cid,'acls',[row]);
 expect(f.entityParentIndex).toEqual([{cluster_id:f.cid,child_type:'acls',child_id:row.id,parent_type:'consumers',parent_id:row.consumer.id}]);
});
