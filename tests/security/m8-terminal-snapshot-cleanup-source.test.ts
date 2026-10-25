import { describe,it,expect } from 'vitest';
import{M8_TERMINAL_CAPTURE_ARCHIVE as c,assertM8KnownTerminalCaptureRow,assertM8KnownTerminalCaptureCleanup}from'./lib/m8-terminal-snapshot-cleanup.mjs';
function fixture(){return{row:{id:c.snapshotId,clusterId:c.cid,workspaceId:c.wid,state:'capturing',currentVersion:null,revision:1,capabilities:{delete:true},completeness:null,objectCount:0,pageCount:0,recordCount:0,byteCount:0,scopeKind:'workspace',rootIds:[]},
 selection:{area:{cid:c.cid,wid:c.wid},kind:'workspace',roots:[]},actor:{user:{id:c.actorId}},item:{state:'capturing',revision:1,currentVersion:null,sameOwner:true,versions:[],
 jobs:[{id:c.jobId,kind:'capture',state:'failed',error_code:'CONFIGURATION_SCHEMA_FIELD_MISMATCH',same_owner:true,same_transport:true,progress_matches:true,scope_kind:'workspace',root_ids:[]}],
 materials:[{job_id:c.jobId,state:'available',has_wrapped_secret:true,artifact_kind:'snapshot'}]}};}
describe('M8 unique failed unsealed capture soft cleanup predicate',()=>{
 it('allows only the fixed complete safe structure and never permits restore or purge',()=>{const f=fixture();expect(assertM8KnownTerminalCaptureRow(f.row,f.selection,f.actor,f.item)).toMatchObject({snapshotId:c.snapshotId,jobId:c.jobId,terminalJobState:'failed',unsealed:true,restoreAllowed:false,purgeUsed:false});});
 for(const name of['deletecap','currentversion','revision','sealed','objects','snapshot','cluster','workspace','owner','scope','job','running','uncertain','transport','progress','versionrow','material'])it(`refuses ${name} without broadening capture cleanup`,()=>{
  const f:any=fixture();if(name==='deletecap')f.row.capabilities.delete=false;if(name==='currentversion')f.row.currentVersion=1;if(name==='revision')f.row.revision=2;if(name==='sealed')f.row.completeness='complete';if(name==='objects')f.row.objectCount=1;
  if(name==='snapshot')f.row.id=c.jobId;if(name==='cluster')f.row.clusterId=c.wid;if(name==='workspace')f.row.workspaceId=c.cid;if(name==='owner')f.actor.user.id=c.jobId;if(name==='scope')f.selection.kind='cluster';
  if(name==='job')f.item.jobs[0].id=c.snapshotId;if(name==='running')f.item.jobs[0].state='running';if(name==='uncertain')f.item.jobs[0].state='uncertain';if(name==='transport')f.item.jobs[0].same_transport=false;if(name==='progress')f.item.jobs[0].progress_matches=false;
  if(name==='versionrow')f.item.versions.push({version:1});if(name==='material')f.item.materials[0].state='destroyed';expect(()=>assertM8KnownTerminalCaptureRow(f.row,f.selection,f.actor,f.item)).toThrow('M8_ONLY_EXACT_FAILED_UNSEALED_CAPTURE_MAY_SOFT_ARCHIVE');
 });
 it('validating safe structure cannot replace the actual immutable proof or original wire prefix',()=>{const f=fixture();expect(()=>assertM8KnownTerminalCaptureCleanup(f.row,f.selection,f.actor,{requests:[]},Buffer.from('{}'))).toThrow('M8_EXACT_TERMINAL_CAPTURE_PROVENANCE_REQUIRED');});
});
