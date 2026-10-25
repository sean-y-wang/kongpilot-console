// @ts-nocheck -- synthetic JSON exercises the actual ESM provenance classifier.
import {describe,expect,it} from 'vitest';
import {createHash} from 'node:crypto';
import {auditSecretProvenance,classifyAuditCandidates} from './lib/m6-audit-secret-provenance.mjs';

const marker='[REDACTED:0123456789abcdef]',unknown='[REDACTED:fedcba9876543210]';
const clone=v=>JSON.parse(JSON.stringify(v));
const attempt=(responseData,extra={})=>({method:'POST',path:'/api/v1/portal/ordinary',state:'response_observed',httpStatus:201,responseData,...extra});
const retained=r=>classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained;
// Frozen pre-dedup classification oracle, copied from the reviewed original
// pure function. Small fixtures compare sets, since output insertion order has
// no authority. This oracle performs no transport or environment access.
function provenanceBeforeDedup(reference,environmentSecrets=[]){
  const names=new Set(['password','currentpassword','newpassword','resetpassword','initialpassword','apikey','clientsecret','csrf','csrftoken','accesstoken','refreshtoken','secret','token']);
  const actual=new Set(environmentSecrets.filter(v=>typeof v==='string'&&v.length)),rawKeys=new Set(),aggregateRoots=new WeakSet(),roots=[reference];let visited=0,journalVisited=0;
  while(roots.length){if(++journalVisited>16)throw Error('Audit journal history budget exceeded');const root=roots.shift();aggregateRoots.add(root);for(const prior of root.priorFixtureRuns??[]){if(!prior.checkpoint||prior.testTag!==prior.checkpoint.testTag||prior.checkpointSha256!==createHash('sha256').update(JSON.stringify(prior.checkpoint)).digest('hex'))throw Error('Audit historical journal SHA changed');roots.push(prior.checkpoint);}}
  const add=v=>{if(typeof v==='string'&&v.length)actual.add(v);},key=v=>{add(v);if(typeof v==='string'&&v.length)rawKeys.add(v);};
  function visit(object,path=[],attempt=null){
    if(++visited>200000)throw Error('Audit provenance traversal budget exceeded');
    if(typeof object==='string'&&path.includes('body')&&attempt&&['POST','PATCH','PUT','DELETE'].includes(attempt.method))add(object);
    if(!object||typeof object!=='object')return;
    if(Array.isArray(object)){for(const row of object)visit(row,path,attempt);return;}
    const insideTrustedBody=path.includes('body')&&attempt&&['POST','PATCH','PUT','DELETE'].includes(attempt.method),currentAttempt=insideTrustedBody?attempt:typeof object.method==='string'&&typeof object.path==='string'&&typeof object.state==='string'?object:attempt;
    for(const[name,value]of Object.entries(object)){
      if(name==='secrets'&&Array.isArray(value)&&aggregateRoots.has(object))continue;
      if(name==='secrets'&&Array.isArray(value))value.forEach(add);
      if(['privateKeys','capturedKeys'].includes(name)&&Array.isArray(value))value.forEach(key);
      const compact=name.replaceAll('_','').toLowerCase(),next=[...path,name];if(names.has(compact)){add(value);if(compact==='apikey')key(value);}
      if(/cookie$/i.test(name)&&typeof value==='string')for(const pair of value.split(';')){const at=pair.indexOf('=');if(at>0&&/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(pair.slice(0,at).trim()))add(pair.slice(at+1));}
      if(name==='key'&&typeof value==='string'){
        const body=path.includes('body')&&currentAttempt&&['POST','PATCH','PUT','DELETE'].includes(currentAttempt.method),revealed=path.includes('responseData')&&currentAttempt&&currentAttempt.httpStatus>=200&&currentAttempt.httpStatus<300&&(currentAttempt.path.endsWith('/reveal')||new URLSearchParams(currentAttempt.query??'').get('reveal')==='true'),journalMetadata=path.includes('writeAttempts')||path.includes('manualWriteAttempts'),privateKey=!path.includes('responseData')&&!journalMetadata;
        if(body||revealed||privateKey)key(value);
      }
      if(currentAttempt&&next.includes('body')&&['POST','PATCH','PUT','DELETE'].includes(currentAttempt.method)&&typeof value==='string')add(value);
      if(value&&typeof value==='object')visit(value,next,currentAttempt);
    }
  }
  visit(reference);return{actual:[...actual],rawKeys:[...rawKeys]};
}
const asSets=p=>({actual:[...new Set(p.actual)].sort(),rawKeys:[...new Set(p.rawKeys)].sort()});

describe('independent context-aware cloned-history provenance dedup',()=>{
  it('collapses complete JSON-cloned history beyond 200k physical scalar visits without deleting a real candidate',()=>{
    const history={publicSamples:Array.from({length:25000},()=> 'Synthetic public sample'),grant:{apiKey:'SyntheticTrustedRawKey'}};
    const reference={historicalCopies:Array.from({length:10},()=>clone(history)),writeAttempts:[attempt({key:marker})]};
    const before=JSON.stringify(reference),p=auditSecretProvenance(reference);
    expect(p.actual).toContain('SyntheticTrustedRawKey');expect(p.rawKeys).toContain('SyntheticTrustedRawKey');
    expect(classifyAuditCandidates([marker],p,[marker]).excluded).toEqual([marker]);
    expect(JSON.stringify(reference)).toBe(before);
  },15000);
  it('the same complete subtree first observed in an ordinary response remains protected in a later POST body',()=>{
    const value={unknown:[marker],nested:{key:marker}},reference={writeAttempts:[attempt(clone(value)),attempt({}, {body:clone(value)})]};
    expect(retained(reference)).toEqual([marker]);
  });
  it('successful reveal path and query contexts cannot be merged with an earlier non-reveal response',()=>{
    for(const reveal of [{path:'/api/v1/portal/credentials/id/reveal'},{query:'reveal=true'}]){
      const value={key:marker},reference={writeAttempts:[attempt(clone(value)),attempt(clone(value),reveal)]};
      const p=auditSecretProvenance(reference);expect(p.rawKeys).toContain(marker);expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);
    }
    expect(retained({writeAttempts:[attempt({key:marker}),attempt({key:marker},{path:'/api/v1/portal/credentials/id/reveal',httpStatus:403})]})).toEqual([]);
  });
  it('a cloned unknown checkpoint is protected even when identical content was a verified aggregate root',()=>{
    const checkpoint={testTag:'synthetic-prior',secrets:[marker],public:{text:'Synthetic public metadata'}},checkpointSha256=createHash('sha256').update(JSON.stringify(checkpoint)).digest('hex');
    const reference={priorFixtureRuns:[{testTag:checkpoint.testTag,checkpoint,checkpointSha256}],observation:{checkpoint:clone(checkpoint)}};
    expect(retained(reference)).toEqual([marker]);
    expect(retained({priorFixtureRuns:[{testTag:checkpoint.testTag,checkpoint,checkpointSha256}]})).toEqual([]);
  });
  it('journal key metadata cannot hide an identical originalRequest private Key subtree',()=>{
    const row={method:'GET',path:'/api/v1/ordinary',state:'response_observed',key:marker};
    expect(retained({writeAttempts:[clone(row)],originalRequest:clone(row)})).toEqual([marker]);
    expect(retained({writeAttempts:[clone(row)]})).toEqual([]);
  });
  it('nested fake GET fields and body secret arrays never remove inherited outer POST protection',()=>{
    const subtree={method:'GET',path:'/synthetic-read',state:'response_observed',config:{unknown:[marker]}};
    const reference={writeAttempts:[attempt(clone(subtree),{method:'GET'}),attempt({}, {body:clone(subtree)})]};
    expect(retained(reference)).toEqual([marker]);
    expect(retained({writeAttempts:[attempt({}, {body:{config:{secrets:[marker]}}})]})).toEqual([marker]);
    const p=auditSecretProvenance({copies:[clone(subtree),clone(subtree)],capturedKeys:[marker]},[marker]);
    expect(p.rawKeys).toContain(marker);expect(classifyAuditCandidates([marker,unknown],p,[marker]).retained).toEqual([marker,unknown]);
    const checkpoint={testTag:'synthetic-differential',secrets:[unknown],responseData:{key:marker}},checkpointSha256=createHash('sha256').update(JSON.stringify(checkpoint)).digest('hex');
    const small=[reference,
      {writeAttempts:[attempt({key:marker},{method:'GET',httpStatus:200,path:'/read/reveal'}),attempt({key:marker},{method:'GET',httpStatus:401,path:'/read/reveal'})]},
      {manualWriteAttempts:[attempt({key:marker},{query:'reveal=true',httpStatus:299}),attempt({key:marker},{query:'reveal=true',httpStatus:300})]},
      {writeAttempts:[attempt({key:marker}),attempt({key:marker},{query:'reveal=false'})],originalRequest:{key:marker}},
      {writeAttempts:[attempt({}, {body:{responseData:clone(subtree)}}),attempt(clone(subtree),{method:'GET'})]},
      {writeAttempts:[attempt({child:{method:'GET',path:'/synthetic/reveal',state:'observed',httpStatus:201,body:{key:marker}}})]},
      {priorFixtureRuns:[{testTag:checkpoint.testTag,checkpoint,checkpointSha256}],observation:{checkpoint:clone(checkpoint)}},
      {password:marker,cookie:`kongos_portal_access=${marker}; unrelated=public`,privateKeys:[unknown],copies:[clone(subtree),clone(subtree)]}];
    for(const input of small)expect(asSets(auditSecretProvenance(input,[unknown]))).toEqual(asSets(provenanceBeforeDedup(input,[unknown])));
  });
  it('the unchanged 200k semantic budget still rejects genuinely distinct scalar material',()=>{
    const reference={publicSamples:Array.from({length:200001},(_,i)=>`Synthetic unique public sample ${i}`)};
    expect(()=>auditSecretProvenance(reference)).toThrow('Audit provenance traversal budget exceeded');
  },15000);
  it('cycles and excessively deep histories fail closed before classification can drop candidates',()=>{
    const cycle={apiKey:marker};cycle.self=cycle;
    expect(()=>auditSecretProvenance(cycle)).toThrow('Audit provenance cycle rejected');
    const root={};let node=root;for(let i=0;i<514;i++){node.child={};node=node.child;}node.key=marker;
    expect(()=>auditSecretProvenance(root)).toThrow('Audit provenance structural depth exceeded');
  });
});
