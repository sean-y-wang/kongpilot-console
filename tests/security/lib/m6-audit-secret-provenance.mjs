import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const secretNames=new Set(['password','currentpassword','newpassword','resetpassword','initialpassword','apikey','clientsecret','csrf','csrftoken','accesstoken','refreshtoken','secret','token']);
const normalized=name=>name.replaceAll('_','').toLowerCase();
export const canonicalAuditMarker=value=>typeof value==='string'&&/^\[REDACTED:[a-f0-9]{16}\]$/.test(value);

/** Aggregate candidates are never deleted. Body/reveal/private-key and session
 * provenance takes precedence over a value resembling a redaction marker. */
export function auditSecretProvenance(reference,environmentSecrets=[]){
 const actual=new Set(environmentSecrets.filter(v=>typeof v==='string'&&v.length)),rawKeys=new Set();let visited=0;
 // JSON checkpoints contain independent clones. Identity-only dedup cannot
 // bound them. A Merkle prepass hashes each physical object once; provenance
 // visits each structural value once per interpretation context. Both object
 // hashing and semantic visits retain the 200000 limit, with a byte/depth cap.
 const digests=new WeakMap(),hashing=new WeakSet();let hashedObjects=0,hashedBytes=0;
 const digest=(value,depth=0)=>{
  if(depth>512)throw new Error('Audit provenance structural depth exceeded');
  if(!value||typeof value!=='object'){
   const token=typeof value+':'+String(JSON.stringify(value));hashedBytes+=Buffer.byteLength(token,'utf8');
   if(hashedBytes>64*1024*1024)throw new Error('Audit provenance structural byte budget exceeded');
   return createHash('sha256').update(token).digest('hex');
  }
  if(digests.has(value))return digests.get(value);
  if(hashing.has(value))throw new Error('Audit provenance cycle rejected');
  if(++hashedObjects>200000)throw new Error('Audit provenance structural object budget exceeded');
  hashing.add(value);const pieces=[Array.isArray(value)?'array':'object'];
  // Sort keys so equivalent complete JSON clones deduplicate regardless of
  // property insertion order. Arrays keep their actual element order.
  const entries=Array.isArray(value)?value.map((v,i)=>[String(i),v]):Object.entries(value).sort(([a],[b])=>a<b?-1:a>b?1:0);
  for(const[name,child]of entries){const key=JSON.stringify(name);hashedBytes+=Buffer.byteLength(key,'utf8')+64;if(hashedBytes>64*1024*1024)throw new Error('Audit provenance structural byte budget exceeded');pieces.push(key,digest(child,depth+1));}
  const result=createHash('sha256').update(JSON.stringify(pieces)).digest('hex');hashing.delete(value);digests.set(value,result);return result;
 };
 digest(reference);const seenContexts=new Set();
 const writes=attempt=>!!attempt&&['POST','PATCH','PUT','DELETE'].includes(attempt.method);
 const reveals=attempt=>!!attempt&&attempt.httpStatus>=200&&attempt.httpStatus<300&&(attempt.path.endsWith('/reveal')||new URLSearchParams(attempt.query??'').get('reveal')==='true');
 const aggregateRoots=new WeakSet(),roots=[reference];let journalVisited=0;
 while(roots.length){
  if(++journalVisited>16)throw new Error('Audit journal history budget exceeded');const root=roots.shift();
  aggregateRoots.add(root);
  for(const prior of root.priorFixtureRuns??[]){if(!prior.checkpoint||prior.testTag!==prior.checkpoint.testTag||prior.checkpointSha256!==createHash('sha256').update(JSON.stringify(prior.checkpoint)).digest('hex'))throw new Error('Audit historical journal SHA changed');roots.push(prior.checkpoint);}
 }
 const add=v=>{if(typeof v==='string'&&v.length)actual.add(v);};
 const key=v=>{add(v);if(typeof v==='string'&&v.length)rawKeys.add(v);};
 const visit=(object,path=[],attempt=null)=>{
  // Every flag affects existing body/reveal/key/aggregate interpretation.
  // Equal content under different contexts must still be traversed.
  const context=[path.includes('body'),path.includes('responseData'),path.includes('writeAttempts')||path.includes('manualWriteAttempts'),aggregateRoots.has(object),writes(attempt),reveals(attempt)];
  const identity=digests.get(object)??digest(object);
  const semanticKey=identity+':'+context.map(Boolean).map(Number).join('');
  if(seenContexts.has(semanticKey))return;seenContexts.add(semanticKey);
  if(++visited>200000)throw new Error('Audit provenance traversal budget exceeded');
  if(typeof object==='string'&&path.includes('body')&&attempt&&['POST','PATCH','PUT','DELETE'].includes(attempt.method))add(object);
  if(!object||typeof object!=='object')return;
  if(Array.isArray(object)){for(const row of object)visit(row,path,attempt);return;}
  const insideTrustedBody=path.includes('body')&&attempt&&['POST','PATCH','PUT','DELETE'].includes(attempt.method);
  const currentAttempt=insideTrustedBody?attempt:typeof object.method==='string'&&typeof object.path==='string'&&typeof object.state==='string'?object:attempt;
  for(const[name,value]of Object.entries(object)){
   if(name==='secrets'&&Array.isArray(value)&&aggregateRoots.has(object))continue; // Only actual root and SHA-verified history aggregates are not provenance.
   if(name==='secrets'&&Array.isArray(value))value.forEach(add);
   if(['privateKeys','capturedKeys'].includes(name)&&Array.isArray(value))value.forEach(key);
   const compact=normalized(name),next=[...path,name];
   if(secretNames.has(compact)){add(value);if(compact==='apikey')key(value);}
   if(/cookie$/i.test(name)&&typeof value==='string')for(const pair of value.split(';')){const at=pair.indexOf('=');if(at>0&&/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(pair.slice(0,at).trim()))add(pair.slice(at+1));}
   if(name==='key'&&typeof value==='string'){
    const body=path.includes('body')&&currentAttempt&&['POST','PATCH','PUT','DELETE'].includes(currentAttempt.method);
    const revealed=path.includes('responseData')&&currentAttempt&&currentAttempt.httpStatus>=200&&currentAttempt.httpStatus<300&&(currentAttempt.path.endsWith('/reveal')||new URLSearchParams(currentAttempt.query??'').get('reveal')==='true');
    const journalMetadata=path.includes('writeAttempts')||path.includes('manualWriteAttempts');
    const privateKey=!path.includes('responseData')&&!journalMetadata;
    if(body||revealed||privateKey)key(value);
   }
   if(currentAttempt&&next.includes('body')&&['POST','PATCH','PUT','DELETE'].includes(currentAttempt.method)&&typeof value==='string')add(value);
   if(value&&typeof value==='object')visit(value,next,currentAttempt);
  }
 };
 visit(reference);
 return{actual:[...actual],rawKeys:[...rawKeys]};
}

/** Only exact markers proved by the actual compiled SecretService, with a
 * separately trusted raw-key source, may be removed from an audit comparison. */
export function classifyAuditCandidates(candidates,provenance,verifiedMarkers){
 const actual=new Set(provenance.actual),verified=new Set(verifiedMarkers),retained=[],excluded=[];
 for(const value of new Set(candidates.filter(v=>typeof v==='string'&&v.length))){
  if(canonicalAuditMarker(value)&&verified.has(value)&&!actual.has(value))excluded.push(value);else retained.push(value);
 }
 return{retained,excluded};
}

export function readAuditWithActualMarkerProof(requestIds,candidates,provenance){
 // STDIN/STDOUT remain private in process memory. No credential or audit row is
 // written to evidence. This uses the runtime's compiled, authoritative class.
 const code=`const pg=require('pg'),{SecretService}=require('./dist/infrastructure/secret.service.js');let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',async()=>{const q=JSON.parse(input),p=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL}),s=new SecretService();let c;try{c=await p.connect();await c.query('BEGIN READ ONLY');const rows=(await c.query('SELECT request_id,before,after,json_patch FROM audit_events WHERE request_id=ANY($1::text[])',[q.ids])).rows;await c.query('ROLLBACK');const markers=new Set(q.rawKeys.map(key=>s.redact({key}).key));process.stdout.write(JSON.stringify({rows,verifiedMarkers:q.candidates.filter(value=>markers.has(value))}));}catch{if(c)await c.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{c?.release();await p.end();}});`;
 try{return JSON.parse(execFileSync('docker',['compose','exec','-T','console-api','node','-e',code],{input:JSON.stringify({ids:requestIds,candidates,rawKeys:provenance.rawKeys}),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:32*1024*1024}));}
 catch{throw new Error('Read-only actual audit fingerprint verification failed; private details withheld');}
}

export function verifyM6AuditCoverage(h,read=readAuditWithActualMarkerProof){
 const ids=[...new Set(h.successfulWrites.map(v=>v.requestId).filter(Boolean))];
 h.check(h.successfulWrites.every(v=>typeof v.requestId==='string'&&v.requestId.length),'Audit/M6','every successful product write has a server request ID');
 const environment=Object.values(process.env).filter(v=>typeof v==='string'&&v.length);
 // Optional provider/SMTP/LDAP values may be nested JSON or connection URLs.
 // Preserve any candidate appearing there in raw/JSON/URI form as real material.
 const environmentCandidates=h.secrets.filter(v=>typeof v==='string'&&v.length&&environment.some(e=>[v,JSON.stringify(v).slice(1,-1),encodeURIComponent(v)].some(form=>e.includes(form))));
 const provenance=auditSecretProvenance(h.referenceData,[...environment,...environmentCandidates]);
 const {rows,verifiedMarkers}=read(ids,h.secrets,provenance),found=new Set(rows.map(v=>v.request_id));
 const missing=h.successfulWrites.filter(v=>!found.has(v.requestId));
 h.public.auditCoverage={successfulProductWrites:h.successfulWrites.length,distinctRequestIds:ids.length,auditedRequestIds:found.size,missing:missing.map(({method,path})=>({method,path})),controlledNativeFixtureCreationExcluded:false};
 h.check(!missing.length,'Audit/M6','all successful HTTP product writes correlate with append-only audit events');
 h.check(rows.every(v=>Array.isArray(v.json_patch)),'Audit/M6','all inspected audit events have JSON patch arrays');
 const classified=classifyAuditCandidates(h.secrets,provenance,verifiedMarkers),text=JSON.stringify(rows);
 h.check(!classified.retained.some(value=>text.includes(value)),'Audit/M6','audit before/after/patch contain no provenance-protected or unclassified credential candidate');
 h.public.auditSecretClassification={actualCompiledSecretService:true,excludedProvenFingerprintMarkers:classified.excluded.length,aggregateSecretsPreserved:true,bodyRevealEnvironmentSessionPrecedence:true,unknownMarkerAndUuidExcluded:false,privateMarkerValuesPublished:false};
 return h.public.auditCoverage;
}
