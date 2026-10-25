import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import ts from 'typescript';

const identifierFields = new Set(['keyid','keyids','keyversion','credentialid','credentialids','secretid','secretids','tokenexpiration','tokenexpirationtime','tokenexp','tokentype','tokenendpoint','refreshtokenttl','requesthash','requesthmac','bodyhash','responsehash','claimhash']);
const compact = value => String(value).replace(/[^a-z0-9]/gi,'').toLowerCase();
const secretName = name => {
  const key = compact(name);
  return !identifierFields.has(key) && (key.includes('password') || key.includes('secret') || key.includes('privatekey')
    || key.includes('apikey') || key.includes('accesstoken') || key.includes('refreshtoken') || key.includes('csrftoken')
    || key === 'csrf' || key === 'token' || key === 'authorization' || key === 'proxyauthorization'
    || key === 'provisionkey' || key === 'signingkey' || key === 'clientkey');
};

/** Remove one explicitly controlled public rejection probe from an in-memory
 * material clone. Any other occurrence, issued value, packet or source shape
 * refuses the exception. Original private journals remain untouched. */
export function excludeControlledRejectedDraftProbe(material,environment,browserMaterial,sourceText,expected){
  const packet=material.requests?.[expected.index];assert(packet);
  for(const name of ['requestId','actorId','path','method','startedAt'])assert.equal(packet[name],expected[name]);
  assert.equal(packet.state,'response_observed');assert.equal(packet.status,400);assert.equal(packet.errorCode,'DRAFT_SECRET_FORBIDDEN');
  const candidate=packet.body?.payload?.password;assert.equal(typeof candidate,'string');assert(candidate.length>=8&&candidate.length<=16384);
  let nodes=0,outside=0;
  const search=(value,path,omitExact=false)=>{
    if(++nodes>250000)throw Error('NONCREDENTIAL_PROBE_NODE_BUDGET');
    if(value&&typeof value==='object'){for(const[name,child]of Object.entries(value))search(child,[...path,name],omitExact);}
    else if(typeof value==='string'&&value.includes(candidate)){
      const exact=omitExact&&path.join('.')===`requests.${expected.index}.body.payload.password`;
      if(!exact)outside++;
    }
  };
  search(material,[],true);search(environment,['environment']);search(browserMaterial,['browser']);
  assert.equal(outside,0,'The public probe cannot also be an issued or other private credential');
  const source=ts.createSourceFile('controlled-native.mjs',sourceText,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);assert.equal(source.parseDiagnostics.length,0);
  const property=(object,name)=>object.properties.find(value=>ts.isPropertyAssignment(value)&&(ts.isIdentifier(value.name)||ts.isStringLiteral(value.name))&&value.name.text===name);
  const links=[];
  const visit=node=>{
    if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&ts.isIdentifier(node.expression.expression)&&node.expression.expression.text==='h'&&node.expression.name.text==='request'){
      const args=node.arguments;
      if(args.length===5&&ts.isCallExpression(args[1])&&ts.isIdentifier(args[1].expression)&&args[1].expression.text==='path'
        &&args[1].arguments.length===1&&ts.isStringLiteral(args[1].arguments[0])&&args[1].arguments[0].text==='drafts'
        &&ts.isStringLiteral(args[2])&&args[2].text==='POST'&&ts.isObjectLiteralExpression(args[3])&&ts.isObjectLiteralExpression(args[4])){
        const payload=property(args[3],'payload'),expectedStatus=property(args[4],'expected');
        if(payload&&ts.isObjectLiteralExpression(payload.initializer)&&expectedStatus&&ts.isArrayLiteralExpression(expectedStatus.initializer)
          &&expectedStatus.initializer.elements.length===1&&ts.isNumericLiteral(expectedStatus.initializer.elements[0])&&expectedStatus.initializer.elements[0].text==='400'){
          const password=property(payload.initializer,'password');
          if(password&&ts.isStringLiteral(password.initializer)&&password.initializer.text===candidate)
            links.push(Buffer.byteLength(sourceText.slice(0,password.initializer.getStart(source)+1)));
        }
      }
    }
    ts.forEachChild(node,visit);
  };
  visit(source);assert.deepEqual(links,[expected.sourceByteOffset]);
  const requests=[...material.requests],payload={...packet.body.payload};delete payload.password;
  requests[expected.index]={...packet,body:{...packet.body,payload}};
  return {material:{...material,requests},evidence:{source:'native',index:expected.index,requestId:packet.requestId,kind:'controlled-public-noncredential-draft-rejection-probe',
    status:400,code:'DRAFT_SECRET_FORBIDDEN',sourcePath:expected.sourcePath,sourceByteOffset:links[0],sourceSha256:createHash('sha256').update(sourceText).digest('hex'),
    sourceLiteralLinked:true,privateOccurrenceOutsideExactRejectedField:false,issuedFixtureCredentialMatch:false,originalPacketsChanged:false,genericFailedPasswordExclusion:false}};
}

/** Derive actual private values without treating public idempotency UUIDs as credentials. */
export function collectSecretMaterial(harness, environment, browserMaterial = undefined) {
  const values = new Map();
  let visited = 0;
  const add = (value, kind) => {
    if (typeof value !== 'string' || value.length < 8 || value.startsWith('[REDACTED') || /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) return;
    if (value.length > 16384) throw Error('SECRET_MATERIAL_SIZE_BUDGET');
    if (values.size >= 4096 && !values.has(value)) throw Error('SECRET_MATERIAL_COUNT_BUDGET');
    const existing = values.get(value);
    if (existing) existing.kinds.add(kind); else values.set(value, {value,kinds:new Set([kind])});
    if (/^(?:Bearer|Basic)\s+/i.test(value)) add(value.replace(/^(?:Bearer|Basic)\s+/i,''),kind);
    const tokens = value.match(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g);
    for (const token of tokens ?? []) if (token !== value) add(token,'jwt');
  };
  const cookies = value => {
    if (typeof value !== 'string') return;
    add(value,'cookie');
    for (const piece of value.split(';')) {
      const at = piece.indexOf('=');
      if (at < 1) continue;
      const name = piece.slice(0,at).trim().toLowerCase();
      if (!name.startsWith('kongos_') && !name.startsWith('kongpilot_')) continue;
      add(piece.slice(at+1).trim(), name.includes('csrf')?'csrf':'cookie');
    }
  };
  const visit = (value, path, credential = false) => {
    if (++visited > 250000) throw Error('SECRET_MATERIAL_NODE_BUDGET');
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) { value.forEach((child,index)=>visit(child,[...path,String(index)],credential));return; }
    if (typeof value === 'object') {
      if (typeof value.name === 'string' && /^(?:kongos_|kongpilot_)/i.test(value.name) && typeof value.value === 'string')
        add(value.value,/csrf/i.test(value.name)?'csrf':'cookie');
      for (const [name,child] of Object.entries(value)) {
        const key = compact(name);
        // A request's key is the X-Idempotency-Key ledger identity, never its API Key.
        if (name === 'key' && path.length === 2 && path[0] === 'requests' && /^\d+$/.test(path[1])) continue;
        if (['xidempotencykey','idempotencykey'].includes(key)) continue;
        const context = credential || /(?:credentials?|key[-_]auth|basic[-_]auth|hmac[-_]auth|oauth2|jwt)/i.test(name)
          || path[0]?.startsWith('recycleFixture') || path[0] === 'compositeWorkspaceFixtures';
        if (typeof child === 'string') {
          if (key.includes('cookie')) cookies(child);
          else if (secretName(name)) add(child,key.includes('csrf')?'csrf':key.includes('password')?'password':'secret');
          else if (key === 'key' && context) add(child,'api-key');
        }
        visit(child,[...path,name],context);
      }
      return;
    }
    if (typeof value === 'string') {
      const parent = compact(path.at(-2));
      if (['secrets','secretmaterial','passwords','tokens','csrf','csrftokens'].includes(parent)) add(value,parent.includes('csrf')?'csrf':'secret');
      if (parent.includes('cookie')) cookies(value);
      if (path.includes('headers') || path.includes('responseCookies')) {
        if (/^(?:Bearer|Basic)\s+/i.test(value)) add(value,'authorization');
      }
    }
  };
  visit(harness,[]);
  for (const packet of harness.requests ?? []) {
    const credential = /\/credentials\/(?:key-auth|basic-auth|jwt|oauth2|hmac-auth)(?:\/|\?|$)/.test(packet.path ?? '');
    if (credential) { visit(packet.body,['requestCredentialBody'],true);visit(packet.responseData,['requestCredentialResponse'],true); }
    if (packet.headers?.['X-CSRF-Token']) add(packet.headers['X-CSRF-Token'],'csrf');
    if (typeof packet.rawResponseText === 'string' && packet.rawResponseText.trim().startsWith('{')) {
      try {visit(JSON.parse(packet.rawResponseText),['rawResponseObject'],credential);}catch(error){if(error?.message?.startsWith('SECRET_MATERIAL_'))throw error;}
    }
  }
  for (const [name,value] of Object.entries(environment)) if (secretName(name) || /(?:SIGNING|ENCRYPTION)_KEY$/.test(name)) add(value,'environment-secret');
  if (browserMaterial !== undefined) visit(browserMaterial,['browser']);
  return [...values.values()].map(row=>({...row,kinds:[...row.kinds].sort()}));
}

/** Aho-Corasick keeps work linear in scanned bytes rather than tokens × files. */
export function buildSecretMatcher(secrets) {
  const nodes = [{edges:new Map(),fail:0,out:[]}];
  const variants = new Map();
  const addVariant = (value,kinds,encoding) => {
    const bytes = Buffer.from(value);
    if (bytes.length < 8) return;
    const identity = bytes.toString('base64');
    const old = variants.get(identity);
    if (old) { kinds.forEach(kind=>old.kinds.add(kind));old.encodings.add(encoding);return; }
    variants.set(identity,{bytes,kinds:new Set(kinds),encodings:new Set([encoding])});
  };
  for (const {value,kinds} of secrets) {
    addVariant(value,kinds,'literal');
    addVariant(encodeURIComponent(value),kinds,'uri');
    addVariant(JSON.stringify(value).slice(1,-1),kinds,'json-escaped');
    addVariant(Buffer.from(value).toString('base64'),kinds,'base64');
    addVariant(Buffer.from(value).toString('base64url'),kinds,'base64url');
  }
  const patterns = [...variants.values()];
  patterns.forEach((pattern,id)=>{
    let current=0;
    for (const byte of pattern.bytes) {
      let child=nodes[current].edges.get(byte);
      if (child===undefined) {child=nodes.length;nodes.push({edges:new Map(),fail:0,out:[]});nodes[current].edges.set(byte,child);}
      current=child;
    }
    nodes[current].out.push(id);
  });
  const queue=[...nodes[0].edges.values()];
  for (let head=0;head<queue.length;head++) {
    const current=queue[head];
    for (const [byte,child] of nodes[current].edges) {
      let fallback=nodes[current].fail;
      while (fallback!==0&&!nodes[fallback].edges.has(byte))fallback=nodes[fallback].fail;
      const next=nodes[fallback].edges.get(byte);
      nodes[child].fail=next===undefined||next===child?0:next;
      nodes[child].out.push(...nodes[nodes[child].fail].out);
      queue.push(child);
    }
  }
  return {
    patternCount:patterns.length,
    scan(bytes) {
      let state=0;
      const found=new Map();
      for(let offset=0;offset<bytes.length;offset++) {
        const byte=bytes[offset];
        while(state!==0&&!nodes[state].edges.has(byte))state=nodes[state].fail;
        state=nodes[state].edges.get(byte)??0;
        for(const id of nodes[state].out) {
          const pattern=patterns[id];
          const prior=found.get(id);
          if(prior)prior.occurrences++;else found.set(id,{byteOffset:offset-pattern.bytes.length+1,occurrences:1,kinds:[...pattern.kinds].sort(),encodings:[...pattern.encodings].sort()});
        }
      }
      return [...found.values()];
    },
  };
}

export function secretScannerSelfTest() {
  const publicUUID='11111111-2222-4333-8444-555555555555',apiKey='SyntheticSecret!UniqueKey2026',csrf='SyntheticCsrf!Unique2026';
  const cookies='kongos_access=eyJabcdefghij.abcdefghij.abcdefghij; kongos_csrf='+csrf;
  const secrets=collectSecretMaterial({requests:[{key:publicUUID,path:'/clusters/x/consumers/y/credentials/key-auth',body:{key:apiKey},headers:{'X-Idempotency-Key':publicUUID,'X-CSRF-Token':csrf}}],sessions:{admin:{cookie:cookies,password:'SyntheticPassword!2026'}},fixtures:{service:{id:publicUUID}}},{LAB_BOOTSTRAP_USER:publicUUID,LAB_APP_SECRET:'SyntheticEnvironment!2026'});
  assert(!secrets.some(row=>row.value===publicUUID));assert(secrets.some(row=>row.value===apiKey));assert(secrets.some(row=>row.value===csrf));
  const matcher=buildSecretMatcher(secrets);
  assert.equal(matcher.scan(Buffer.from('safe identifier '+publicUUID)).length,0);
  assert(matcher.scan(Buffer.from('encoded '+encodeURIComponent(apiKey))).some(row=>row.encodings.includes('uri')));
  assert(matcher.scan(Buffer.from(Buffer.from(apiKey).toString('base64'))).some(row=>row.encodings.includes('base64')));
  assert(matcher.scan(Buffer.from(cookies)).some(row=>row.kinds.includes('csrf')));
  const overlap=buildSecretMatcher([{value:'Syntheticabcdefgh',kinds:['secret']},{value:'abcdefgh',kinds:['secret']}]);
  assert(overlap.scan(Buffer.from('Syntheticabcdefgh')).length>=2);
  return {passed:true,checks:7,actualPrivateMaterialsRead:false};
}
