import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {ConfigurationRepositoryService,SNAPSHOT_TERMINAL_CAPTURE_QUERY} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';

const id=(n:number)=>`76000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** Real repository orchestration, with explicit synthetic transactions.
 * Exact terminal-capture SQL and runtime permissions are checked on separate PG. */
function fixture(state='capturing'){
 const scope:any={clusterId:id(1),workspaceId:id(2),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]},handle=Object.freeze({});
 let row:any={id:id(3),cluster_id:scope.clusterId,workspace_id:scope.workspaceId,transport_scope:scope.transportScope,scope_kind:scope.kind,root_ids:[],created_by:id(4),
  name:'Synthetic snapshot',description:'',state,revision:1,current_version:state==='ready'?1:null,created_at:new Date(),updated_at:new Date()};
 const data={terminal:true,material:false,cas:true},trace:string[]=[];
 const tx:any={one:vi.fn(async(sql:string,params:any[])=>{
  if(sql===SNAPSHOT_TERMINAL_CAPTURE_QUERY){expect(params).toEqual([scope.clusterId,scope.workspaceId,row.id]);trace.push('terminal-proof');return data.terminal?{id:id(5),state:'failed'}:null;}
  if(sql.includes('SELECT id FROM config_snapshots')){trace.push('root-lock');return{id:row.id};}
  if(sql.includes('SELECT s.*,v.version_id'))return structuredClone(row);
  if(sql.startsWith('SELECT 1 FROM config_snapshot_versions'))return data.material?{available:true}:null;
  throw Error('UNEXPECTED_SYNTHETIC_QUERY');
 }),exec:vi.fn(async(sql:string,params:any[])=>{
  expect(sql).toContain('UPDATE config_snapshots SET state=$4');expect(params.slice(0,3)).toEqual([scope.clusterId,scope.workspaceId,row.id]);
  if(!data.cas||params[6]!==row.revision||params[7]!==row.state)return 0;
  trace.push('archive-cas');row={...row,state:params[3],deleted_at:params[4],retention_until:params[5],revision:row.revision+1};return 1;
 })};
 const db:any={transaction:vi.fn(async(fn:any)=>{const before=structuredClone(row);trace.push('begin');try{const result=await fn(tx);trace.push('commit');return result;}catch(e){row=before;trace.push('rollback');throw e;}})};
 const access:any={assertStorage:vi.fn(async(_:any,input:any,transaction:any)=>{expect(transaction).toBe(tx);expect(input.scope).toEqual(scope);trace.push('authority');return{scope,actorId:id(4),expiresAt:Date.now()+60000};})};
 const writer=vi.fn(async(transaction:any,event:any)=>{expect(transaction).toBe(tx);expect(event.before.state).toBe(state);expect(event.after.state).toBe('deleted');trace.push('audit');});
 const repo=new ConfigurationRepositoryService(db,new SecretService(),{}as any,access);repo.installEvidenceWriter({jobCreated:vi.fn(),snapshotSealed:vi.fn(),metadataChanged:writer});
 return{repo,scope,handle,tx,db,data,trace,access,writer,get row(){return row;},set row(value:any){row=value;}};
}
describe('M8 failed capture soft archive and live-capture protection',()=>{
 it.each(['ready','failed','incomplete','expired'])('soft archives terminal snapshot state %s using its exact current state',async state=>{
  const f=fixture(state),before=structuredClone(f.row),s=await f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1});
  expect(s).toMatchObject({state:'deleted',revision:2,currentVersion:before.current_version});expect(f.trace).not.toContain('terminal-proof');expect(f.row.deleted_at).toBeTruthy();
  expect(f.writer).toHaveBeenCalledOnce();expect(f.trace.slice(-2)).toEqual(['authority','commit']);
 });
 it('archives the exact terminal unsealed capture without inventing a recovery version or changing its original job',async()=>{
  const f=fixture(),s=await f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1});
  expect(s).toMatchObject({state:'deleted',revision:2,currentVersion:null,completeness:null});expect(f.trace).toContain('terminal-proof');
  expect(f.tx.exec.mock.calls.every(c=>c[0].includes('UPDATE config_snapshots'))).toBe(true);
  await expect(f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:2,restore:true})).rejects.toMatchObject({response:{code:'CONFIGURATION_MATERIAL_UNAVAILABLE'}});
  expect(f.row.state).toBe('deleted');expect(f.row.current_version).toBeNull();
 });
 it('denies a capturing root when the exact terminal-source query has no proof, before archive CAS',async()=>{
  const f=fixture();f.data.terminal=false;const before=structuredClone(f.row);
  await expect(f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1})).rejects.toMatchObject({response:{code:'CONFIGURATION_CAPTURE_NOT_TERMINAL'}});
  expect(f.tx.exec).not.toHaveBeenCalled();expect(f.writer).not.toHaveBeenCalled();expect(f.row).toEqual(before);
 });
 it('rejects physical scope drift before consulting a terminal capture or writing',async()=>{
  const f=fixture();f.row={...f.row,transport_scope:'b'.repeat(64)};
  await expect(f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1})).rejects.toMatchObject({response:{code:'SOURCE_SCOPE_CHANGED'}});
  expect(f.trace).not.toContain('terminal-proof');expect(f.tx.exec).not.toHaveBeenCalled();
 });
 it('does not accept an old snapshot revision or zero-row CAS',async()=>{
  const f=fixture();f.data.cas=false;
  await expect(f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1})).rejects.toMatchObject({response:{code:'SNAPSHOT_REVISION_CONFLICT'}});
  expect(f.row.state).toBe('capturing');expect(f.writer).not.toHaveBeenCalled();
 });
 it.each(['authority','audit'])('rolls archive back if final %s fails',async outcome=>{
  const f=fixture(),before=structuredClone(f.row);
  if(outcome==='audit')f.writer.mockRejectedValueOnce(new Error('SYNTHETIC_EVIDENCE_REJECTED'));
  else f.access.assertStorage.mockResolvedValueOnce({scope:f.scope,actorId:id(4),expiresAt:Date.now()+60000}).mockRejectedValueOnce(new ForbiddenException({code:'CURRENT_AUTHORITY_REVOKED'}));
  await expect(f.repo.archiveSnapshot(f.handle,{scope:f.scope,snapshotId:f.row.id,revision:1})).rejects.toThrow();
  expect(f.trace).toContain('archive-cas');expect(f.trace.at(-1)).toBe('rollback');expect(f.row).toEqual(before);
 });
});
