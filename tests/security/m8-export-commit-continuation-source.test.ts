// @ts-nocheck: exercise the actual ESM continuation predicates with RAM-only
// packets. No environment, private reference, HTTP, process or DB access.
import { describe, it, expect } from 'vitest';
import { assertOriginalM8ExportPacket, assertM8RecoveredExportReceipt, assertM8HistoricalCommittedExportReceipt, assertM8CommittedExportCheckpoint, isM8ProvenCommittedExportPacket, M8_EXPORT_COMMIT_CHECKPOINT as c } from './lib/m8-export-commit-continuation.mjs';
const area={cid:c.cid,wid:c.wid},actor={user:{id:c.actorId},sid:c.sessionId};
const packet=()=>({index:60,key:c.key,requestId:c.requestId,method:'POST',path:`/api/v1/clusters/${c.cid}/snapshots/${c.snapshotId}/export`,query:`?workspaceId=${c.wid}`,
  clusterId:c.cid,workspaceId:c.wid,actorId:c.actorId,sessionId:c.sessionId,state:'response_observed',status:500,errorCode:'INTERNAL_ERROR',responseData:null,
  body:{mode:'deployment',confirmed:true,confirm_name:c.confirmationName},bodySha256:c.bodySha256,headers:{Cookie:'kongos_access=synthetic-ram-only','X-CSRF-Token':'synthetic-ram-only','X-Idempotency-Key':c.key}});
const receipt=()=>({domain:'configuration',durable:true,idempotencyKey:c.key,id:c.jobId,jobId:c.jobId,kind:'export',state:'succeeded',actorId:c.actorId,
  clusterId:c.cid,workspaceId:c.wid,originalScope:{clusterId:c.cid,workspaceId:c.wid},exportId:c.exportId,sourceSnapshotId:c.snapshotId,mode:'deployment',exportRevision:1,capabilities:{download:true}});
describe('one immutable committed M8 export acknowledgement recovery',()=>{
  it('accepts its fixed failed original packet and positive current receipt',()=>{
    expect(assertOriginalM8ExportPacket(packet()).status).toBe(500);
    expect(assertM8RecoveredExportReceipt(receipt(),actor,area).exportId).toBe(c.exportId);
  });
  it.each(['actorId','sessionId','clusterId','workspaceId','key','requestId','path','query'])('cannot borrow changed original %s',field=>{
    const p=packet();p[field]='not-the-original';expect(()=>assertOriginalM8ExportPacket(p)).toThrow();
  });
  it('refuses altered body, extra parameter, missing headers or status-only guesses',()=>{
    for(const change of [p=>p.body.mode='review',p=>p.body.extra='payload',p=>p.body.confirmed=false,p=>delete p.headers,
      p=>delete p.headers.Cookie,p=>p.headers['X-Idempotency-Key']='other',p=>p.state='response_unknown',p=>delete p.status,p=>p.errorCode='OTHER',p=>p.responseData={state:'succeeded'}]){
      const p=packet();change(p);expect(()=>assertOriginalM8ExportPacket(p)).toThrow();
    }
  });
  it.each(['actorId','idempotencyKey','id','jobId','clusterId','workspaceId','exportId','sourceSnapshotId'])('refuses a foreign protected receipt %s',field=>{
    expect(()=>assertM8RecoveredExportReceipt({...receipt(),[field]:'not-original'},actor,area)).toThrow();
  });
  it('requires current successful, exact deployment receipt and real revision capability',()=>{
    for(const changed of [{state:'failed'},{domain:'workflow'},{durable:false},{kind:'capture'},{mode:'review'},{exportRevision:null},{exportRevision:0},{exportRevision:'1'},
      {capabilities:{download:false}},{originalScope:{clusterId:c.cid,workspaceId:'foreign'}}])expect(()=>assertM8RecoveredExportReceipt({...receipt(),...changed},actor,area)).toThrow();
    expect(()=>assertM8RecoveredExportReceipt(receipt(),{...actor,sid:'different-session'},area)).toThrow();
  });
  it('arbitrary HTTP500/proof cannot enter the exact 61-prefix continuation',()=>{
    expect(()=>assertM8CommittedExportCheckpoint({phase:'stopped-failure',requests:[packet()]},Buffer.from('{}'),Buffer.from('{}'))).toThrow();
  });
  it('expired historical commit is still proved independently of download/new SID authority',()=>{
    const historical={...receipt(),capabilities:{download:false}},newSID={...actor,sid:'new-real-session'};
    expect(assertM8HistoricalCommittedExportReceipt(historical,newSID,area).state).toBe('succeeded');
    expect(()=>assertM8RecoveredExportReceipt(historical,newSID,area)).toThrow();
    expect(()=>assertM8HistoricalCommittedExportReceipt({...historical,state:'failed'},newSID,area)).toThrow();
  });
  it('audit cannot promote an arbitrary client claim or altered packet to a committed failure',()=>{
    const r={requests:[packet()],exportCommitContinuation:{recoveredReceipt:{state:'succeeded'}},configurationOperations:[]};
    expect(()=>isM8ProvenCommittedExportPacket(r,packet(),60)).toThrow();
    expect(isM8ProvenCommittedExportPacket({},packet(),0)).toBe(false);
    expect(isM8ProvenCommittedExportPacket({requests:[packet()]},packet(),60)).toBe(false);
  });
});
