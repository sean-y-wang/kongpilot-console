import { checkpointSha } from './m6-isolated-transition.mjs';

// The private historical snapshot is immutable evidence. Cleanup receives
// independent copies so session refresh or metadata updates cannot alter its SHA.
export function fixtureRuns(reference){
  const pending=[reference],seen=new Set(),runs=[];let visited=0;
  while(pending.length){
    if(++visited>16)throw new Error('M6 private fixture history exceeds its bounded run budget');
    const item=pending.shift();
    if(typeof item?.testTag!=='string'||!/^m6-(security|isolated)-[a-z0-9-]+$/.test(item.testTag))throw new Error('M6 fixture history has no exact owned tag');
    if(!seen.has(item.testTag)){
      seen.add(item.testTag);
      const run=structuredClone({testTag:item.testTag,fixtures:item.fixtures??[],portalUsers:item.portalUsers??[],accounts:item.accounts??{},physicalAliases:item.physicalAliases??[]});
      for(const fixture of run.fixtures){
        if(!fixture.cluster?.id||!fixture.workspace?.id||typeof fixture.workspace.code!=='string'||!fixture.workspace.code.startsWith(run.testTag))throw new Error('M6 cleanup scope is not the explicitly captured test workspace');
      }
      runs.push(run);
    }
    for(const prior of item.priorFixtureRuns??[]){
      if(prior.testTag!==prior.checkpoint?.testTag||prior.checkpointSha256!==checkpointSha(prior.checkpoint))throw new Error('M6 historical checkpoint SHA changed; cleanup must stop');
      pending.push(prior.checkpoint);
    }
  }
  return runs;
}

export function capturedPrivateSecrets(reference){
  const result=new Set(),pending=[[reference,null]],journalKeys=new Set(),requestMetadataKeys=[];let visited=0;
  const add=value=>{if(typeof value==='string'&&value.length>0)result.add(value);};
  while(pending.length){
    if(++visited>160_000)throw new Error('M6 private secret history exceeds its bounded traversal budget');
    const [object,owner]=pending.pop();if(!object||typeof object!=='object')continue;
    if(Array.isArray(object)){pending.push(...object.filter(value=>value&&typeof value==='object').map(value=>[value,owner]));continue;}
    // Diagnostics retain original idempotency keys outside their write-attempt
    // object. Exclude only those explicitly named request/execution metadata
    // values that also match a prejournaled HTTP attempt, never UUIDs generally.
    if(['writeAttempts','manualWriteAttempts'].includes(owner)&&typeof object.key==='string'&&typeof object.state==='string'&&['POST','PATCH','PUT','DELETE'].includes(object.method)&&typeof object.path==='string'&&object.path.startsWith('/api/v1/'))journalKeys.add(object.key);
    for(const[name,value]of Object.entries(object)){
      const normalized=name.replaceAll('_','').toLowerCase();
      if(['password','currentpassword','newpassword','resetpassword','initialpassword','apikey','clientsecret','csrf','csrftoken','accesstoken','refreshtoken','secret','token'].includes(normalized))add(value);
      if(name==='key'&&!('method'in object&&'path'in object&&'state'in object)&&!('state'in object&&'startedAt'in object)){
        if(['originalRequest','originalExecution'].includes(owner))requestMetadataKeys.push(value);else add(value);
      }
      if(/cookie$/i.test(name)&&typeof value==='string')for(const pair of value.split(';')){const index=pair.indexOf('=');if(index>0&&/^kongos_(?:portal_)?(?:access|refresh|csrf)$/.test(pair.slice(0,index).trim()))add(pair.slice(index+1));}
      if(name==='secrets'&&Array.isArray(value))value.forEach(add);
      if(value&&typeof value==='object')pending.push([value,name]);
    }
  }
  for(const value of requestMetadataKeys)if(!journalKeys.has(value))add(value);
  for(const row of reference.tokens??[]){
    add(row.token);
    if(row.purpose==='collector_ingest'){const encoded=Buffer.from(`kongos:${row.token}`).toString('base64');add(encoded);add(`Basic ${encoded}`);}
  }
  return [...result];
}
