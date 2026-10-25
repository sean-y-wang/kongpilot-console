import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {annotationWorkflowFixture as fixture} from '../fixtures/m11-annotation-workflow.fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6f'.repeat(32));vi.stubEnv('RECYCLE_RETENTION_DAYS','30');});
afterEach(()=>vi.unstubAllEnvs());
const scheduled=(p:any)=>({...p,scheduling:{version:1,scheduleId:'00000000-0000-4000-8000-000000000001'}});

describe('M11 annotation scheduled identity guards (HTTP paths unchanged)',()=>{
 it('HTTP session path still executes as before',async()=>{const f=fixture(),r:any=await f.prepare(),s:any=await f.submit(r),p:any=f.state().plans.get(s.workflowId);
  await f.execute(p);expect(f.state().annotation.description).toBe('Approved annotation');});
 it('a sealed scheduling block is refused inside an HTTP session',async()=>{const f=fixture(),r:any=await f.prepare(),s:any=await f.submit(r),p:any=f.state().plans.get(s.workflowId);
  await expect(f.http(()=>f.workflow.assertWorkflowAdmission(scheduled(p),f.author,'write'))).rejects.toMatchObject({response:{code:'ANNOTATION_BINDING_INVALID'}});});
 it('a sealed scheduling block is refused with no frame and no scheduled namespace',async()=>{const f=fixture(),r:any=await f.prepare(),s:any=await f.submit(r),p:any=f.state().plans.get(s.workflowId);
  await expect(f.workflow.verifyIntent(scheduled(p))).rejects.toMatchObject({response:{code:'ANNOTATION_BINDING_INVALID'}});});
 it('a sessionless frame outside a scheduled namespace is still refused',async()=>{const f=fixture(),r:any=await f.prepare(),s:any=await f.submit(r),p:any=f.state().plans.get(s.workflowId);
  await expect(f.workflow.assertWorkflowAdmission(p,f.author,'write')).rejects.toBeTruthy();expect(f.state().annotation).toBeNull();});
});
