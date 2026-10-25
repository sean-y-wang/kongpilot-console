import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {bindEntityRecyclePayloadReferences} from '../../apps/console-api/src/modules/workflows/entity-change-recycle-payload-reference';
function fixture(){
 const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),entryId=randomUUID(),otherEntry=randomUUID(),nativeId=randomUUID(),graph={complete:true,rootKey:`services:${nativeId}`,nodes:[{key:`services:${nativeId}`,id:nativeId,type:'services',data:{id:nativeId,host:'private-upstream.example'},restoreData:{id:nativeId,host:'private-upstream.example'},affected:true,dependencies:[]}]};
 const row:any={id:entryId,cluster_id:cid,workspace_id:wid,revision:8,state:'deleted',expires_at:'2099-01-01T00:00:00.000Z',payload_secret:secrets.encrypt(graph,`recycle:${entryId}`)},
  other:any={...row,id:otherEntry,payload_secret:secrets.encrypt(graph,`recycle:${otherEntry}`)};
 const gHma=secrets.fingerprint(graph),envelope:any={version:1,intentId:randomUUID(),revision:1,clusterId:cid,workspaceId:wid,packetManifestHmac:'a'.repeat(64),prepared:{changeDigest:'b'.repeat(64),metadataObligations:[{
  kind:'recycle-restore',entryId,graph,graphHmac:gHma,sealedEntry:{entryId,clusterId:cid,workspaceId:wid,payloadHmac:gHma,state:'deleted',expiresAt:row.expires_at}}]}};
 const db:any={one:vi.fn(async(_sql:string,p:any[])=>p[0]===cid&&p[1]===wid?(p[2]===entryId?structuredClone(row):p[2]===otherEntry?structuredClone(other):null):null),exec:vi.fn(async()=>1)};
 return{secrets,row,other,envelope,db,bind:(material=secrets.fingerprint(envelope))=>bindEntityRecyclePayloadReferences(envelope,material,db,secrets)};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('Exact immutable recovery payload reference before normalized restoration packet publication',()=>{
 it('binds the actual entry and version from its original graph rather than a reused native ID or another archival cycle',async()=>{
  const f=fixture();await f.bind();expect(f.db.one.mock.calls[0][0]).toContain('FOR SHARE');
  const [,p]=f.db.exec.mock.calls[0];expect(p[7]).toBe(f.row.id);expect(p[7]).not.toBe(f.other.id);expect(p[8]).toBe(8);expect(p[9]).toBe(f.secrets.fingerprint(f.row.payload_secret));
  expect(p[10]).toBe(f.envelope.prepared.metadataObligations[0].graphHmac);expect(JSON.stringify(p)).not.toContain(f.row.payload_secret);expect(JSON.stringify(p)).not.toContain('private-upstream.example');
 });
 for(const flaw of ['purged','null-payload','foreign-workspace','wrong-cycle','changed-graph','expired-binding','wrong-material','duplicate-reference'])it(`rejects ${flaw} before a reference INSERT`,async()=>{
  const f=fixture();let hma:string|undefined;
  if(flaw==='purged')f.row.state='purged';if(flaw==='null-payload')f.row.payload_secret=null;
  if(flaw==='foreign-workspace')f.envelope.prepared.metadataObligations[0].sealedEntry.workspaceId=randomUUID();
  if(flaw==='wrong-cycle')f.envelope.prepared.metadataObligations[0].entryId=f.other.id;
  if(flaw==='changed-graph')f.row.payload_secret=f.secrets.encrypt({different:true},`recycle:${f.row.id}`);
  if(flaw==='expired-binding')f.row.expires_at='2099-02-01T00:00:00.000Z';
  if(flaw==='wrong-material')hma='e'.repeat(64);
  if(flaw==='duplicate-reference')f.envelope.prepared.metadataObligations.push(structuredClone(f.envelope.prepared.metadataObligations[0]));
  await expect(f.bind(hma)).rejects.toThrow();
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('keeps a later archive cycle for the same native UUID as an independent exact source',async()=>{
  const f=fixture(),obligation=f.envelope.prepared.metadataObligations[0];
  obligation.entryId=f.other.id;obligation.sealedEntry.entryId=f.other.id;
  await f.bind();const [,p]=f.db.exec.mock.calls[0];expect(p[7]).toBe(f.other.id);expect(p[7]).not.toBe(f.row.id);
  expect(p[9]).toBe(f.secrets.fingerprint(f.other.payload_secret));expect(p[9]).not.toBe(f.secrets.fingerprint(f.row.payload_secret));
 });
 it('does not add a new payload reference to ordinary create/update/delete plans',async()=>{const f=fixture();f.envelope.prepared.metadataObligations=[];await f.bind();expect(f.db.one).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();});
});
