import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { assertReleasePrivateDirectory, assertReleaseReportDirectory, releaseStorageBindingMatches,
  selectReleasePrivateDirectory, selectReleaseReportDirectory } from './release-private-directory.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const ledgerSnapshots=new WeakMap();
const privateFile=stat=>stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600&&stat.nlink===1;
const privateFolder=stat=>stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700;
const ledgerBytes=(path,{missing=false}={})=>{
  let stat;try{stat=lstatSync(path);}catch(error){if(missing&&error?.code==='ENOENT')return null;throw Error('RELEASE_LEDGER_PERMISSIONS_INVALID');}
  if(!privateFile(stat))throw Error('RELEASE_LEDGER_PERMISSIONS_INVALID');
  let fd;try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);const actual=fstatSync(fd);
    if(!privateFile(actual)||actual.dev!==stat.dev||actual.ino!==stat.ino)throw Error('RELEASE_LEDGER_PERMISSIONS_INVALID');
    return readFileSync(fd);
  }catch{throw Error('RELEASE_LEDGER_PERMISSIONS_INVALID');}finally{if(fd!==undefined)closeSync(fd);}
};
const sameNode=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const cookieMerge=(current,values)=>{
  const jar=new Map(current.split('; ').filter(Boolean).map(pair=>{const at=pair.indexOf('=');return[pair.slice(0,at),pair.slice(at+1)];}));
  for(const header of values){const pair=header.split(';')[0],at=pair.indexOf('=');jar.set(pair.slice(0,at),pair.slice(at+1));}
  return [...jar].map(([key,value])=>`${key}=${value}`).join('; ');
};
export const releasePassword=()=>`Release!Aa7${randomBytes(20).toString('hex')}`;
export const releaseScope=(cid,wid,path,extra={})=>`/clusters/${cid}/${path}?${new URLSearchParams({workspaceId:wid,...extra})}`;

/** Real HTTP sessions and original request receipts stay in a private file.
 * An unknown write is never retried or replaced by a newly generated request. */
export class ReleaseHarness {
  constructor(milestone,{resume=false}={}){
    if(process.env.RELEASE_LAB_READY!=='true'||!/^M(?:9|10|11)$/.test(milestone))throw Error('EXPLICIT_ISOLATED_RELEASE_LAB_REQUIRED');
    this.base=process.env.RELEASE_LAB_API??'http://172.29.250.10:5445/api/v1';
    const base=new URL(this.base);if(base.protocol!=='http:'||base.port!=='5445'||base.pathname!=='/api/v1')throw Error('RELEASE_LAB_ORIGIN_REQUIRED');
    const privateSelection=selectReleasePrivateDirectory(),reportSelection=selectReleaseReportDirectory(milestone);
    this.milestone=milestone;this.directory=privateSelection.directory;this.privatePath=`${this.directory}/${milestone.toLowerCase()}-harness.json`;
    this.reportPath=resolve(reportSelection.directory,'native-verification.json');
    let envBytes;try{envBytes=ledgerBytes(`${this.directory}/lab.env`);}catch{throw Error('RELEASE_LAB_PRIVATE_ENV_REQUIRED');}
    this.env=Object.fromEntries(envBytes.toString('utf8').trim().split('\n').map(line=>{const at=line.indexOf('=');return[line.slice(0,at),line.slice(at+1)];}));
    const original=ledgerBytes(this.privatePath,{missing:!resume});
    if(original&&!resume)throw Error('ORIGINAL_RELEASE_LEDGER_PRESENT_USE_EXPLICIT_RESUME');
    if(resume){try{this.state=JSON.parse(original.toString('utf8'));}catch{throw Error('RELEASE_LEDGER_FORMAT_INVALID');}}
    else this.state={version:1,milestone,tag:`${milestone.toLowerCase()}-${randomUUID().slice(0,8)}`,requests:[],checks:[],sessions:{},fixtures:{},phase:'created',
      ...(privateSelection.custom?{privateStorageBinding:{...privateSelection.binding}}:{})};
    if(this.state.version!==1||this.state.milestone!==milestone)throw Error('RELEASE_LEDGER_IDENTITY_INVALID');
    if(!releaseStorageBindingMatches(this.state,privateSelection))throw Error('RELEASE_LEDGER_STORAGE_BINDING_INVALID');
    ledgerSnapshots.set(this,{milestone,directory:this.directory,path:this.privatePath,reportPath:this.reportPath,
      privateSelection,reportSelection,digest:original?hash(original):null});
    // Resume adopts the exact original bytes as its CAS baseline. No read-only
    // constructor rewrites a previous milestone or invents a merged receipt.
    if(!resume)this.save();
  }
  save(){
    const snapshot=ledgerSnapshots.get(this);
    if(!snapshot||this.milestone!==snapshot.milestone||this.directory!==snapshot.directory||this.privatePath!==snapshot.path
      ||this.privatePath!==`${snapshot.privateSelection.directory}/${snapshot.milestone.toLowerCase()}-harness.json`
      ||this.state?.version!==1||this.state?.milestone!==snapshot.milestone)throw Error('RELEASE_LEDGER_SAVE_PATH_INVALID');
    if(!releaseStorageBindingMatches(this.state,snapshot.privateSelection))throw Error('RELEASE_LEDGER_STORAGE_BINDING_INVALID');
    assertReleasePrivateDirectory(snapshot.privateSelection);
    const lock=`${this.privatePath}.lock`,next=`${this.privatePath}.tmp.${process.pid}.${randomUUID()}`;
    let lockStat,tempStat,created=false;
    try{try{mkdirSync(lock,{mode:0o700});created=true;lockStat=lstatSync(lock);if(!privateFolder(lockStat))throw Error('RELEASE_LEDGER_LOCK_INVALID');}
      catch(error){if(error?.message==='RELEASE_LEDGER_LOCK_INVALID')throw error;throw Error('RELEASE_LEDGER_LOCK_UNAVAILABLE');}
      const current=ledgerBytes(this.privatePath,{missing:true});if((current?hash(current):null)!==snapshot.digest)throw Error('RELEASE_LEDGER_STALE_SNAPSHOT');
      const bytes=JSON.stringify(this.state,null,2)+'\n';writeFileSync(next,bytes,{mode:0o600,flag:'wx'});tempStat=lstatSync(next);
      if(!privateFile(tempStat)||!sameNode(lockStat,lstatSync(lock))||!privateFolder(lstatSync(lock)))throw Error('RELEASE_LEDGER_LOCK_INVALID');
      renameSync(next,this.privatePath);snapshot.digest=hash(bytes);tempStat=undefined;
    }finally{
      if(tempStat&&existsSync(next)){const stat=lstatSync(next);if(privateFile(stat)&&sameNode(stat,tempStat))unlinkSync(next);}
      if(created){const stat=lstatSync(lock);if(!lockStat||!privateFolder(stat)||!sameNode(stat,lockStat))throw Error('RELEASE_LEDGER_LOCK_INVALID');rmdirSync(lock);}
    }
  }
  check(condition,name,facts={}){assert(condition,name);this.state.checks.push({name,passed:true,...facts});this.save();}
  assertWritable(operation){
    // A Root-certified fixed OAuth probe GET cannot issue an OAuth grant or
    // an Admin mutation. Its missing response remains unknown in the journal;
    // this exception never applies to a POST or any authentication endpoint.
    const readonlyTransportClosed=packet=>packet.transport==='business-https'&&packet.method==='GET'&&packet.state==='response_unknown'
      &&packet.status===undefined&&packet.body===null&&packet.rejectUnauthorized===true
      &&/^https:\/\/127\.0\.0\.1:5463\/m11-oauth2-[a-f0-9-]{36}$/.test(packet.path??'')
      &&/^[a-f0-9]{64}$/.test(packet.publicCaSha256??'')&&packet.servername==='kongpilot-m11-oauth.invalid'
      &&packet.resolution?.kind==='business-https-readonly-transport-observation'&&packet.resolution?.originalResponseUnknownRetained===true
      &&packet.resolution?.knownReadOnly===true&&packet.resolution?.adminNativeRequestsSent===0&&packet.resolution?.oauthPostRequestsSent===0
      &&/^[a-f0-9]{64}$/.test(packet.resolution?.factProofSha256??'');
    const metadataClosed=packet=>packet.state==='response_observed'&&packet.status===503&&packet.resolution?.knownNativeComplete===true
      &&packet.resolution?.metadataRecovered===true&&packet.resolution?.receiptVerified===true&&packet.resolution?.finalState==='succeeded'
      &&/^[a-f0-9]{64}$/.test(packet.resolution?.factProofSha256??'');
    const terminalMetadataClosed=packet=>packet.state==='response_observed'&&packet.status===503
      &&packet.resolution?.metadataRecovery?.kind==='entity-change-terminal-metadata'
      &&packet.resolution?.knownNativePartial===true&&packet.resolution?.knownNativeComplete===false
      &&packet.resolution?.metadataRecovered===true&&packet.resolution?.receiptVerified===true&&packet.resolution?.finalState==='partial'
      &&packet.resolution?.nativeSuccesses===5&&packet.resolution?.knownNotSent===1&&packet.resolution?.unattempted===1
      &&packet.resolution?.unresolvedMutations===0&&packet.resolution?.metadataNativeRequestsSent===0
      &&/^[a-f0-9]{64}$/.test(packet.resolution?.factProofSha256??'');
    const targetMetadataClosed=packet=>packet.state==='response_observed'&&packet.status===503
      &&packet.resolution?.metadataRecovery?.kind==='entity-change-target-result'
      &&packet.resolution?.originalResponseAuthenticated===true&&packet.resolution?.originalNativeStatus===null
      &&packet.resolution?.statusInferredViaContract===201&&packet.resolution?.originalUnknownOutcomeRetained===true
      &&packet.resolution?.metadataRecovered===true&&packet.resolution?.receiptVerified===true&&packet.resolution?.currentStateObserved===true
      &&packet.resolution?.finalState==='succeeded'&&packet.resolution?.unresolvedMutations===0&&packet.resolution?.metadataNativeRequestsSent===0
      &&typeof packet.resolution?.observationId==='string'&&typeof packet.resolution?.auditId==='string'
      &&/^[a-f0-9]{64}$/.test(packet.resolution?.factProofSha256??'');
    const pending=this.state.requests.filter(packet=>!packet.resolution?.authSessionReplaced&&!readonlyTransportClosed(packet)&&!metadataClosed(packet)&&!terminalMetadataClosed(packet)&&!targetMetadataClosed(packet)
      &&(['prepared','response_unknown'].includes(packet.state)||packet.status>=500&&!packet.resolution?.knownNoNativeSend));
    if(!pending.length)return;
    // A proven native success may close its own ledger using the exact original
    // execution key. It never authorizes a fresh native operation or auth refresh.
    const original=pending[0],proof=original?.resolution?.metadataRecovery;
    if(pending.length===1&&operation?.metadataOnlyFor===original.requestId&&original.state==='response_observed'&&original.status===503
      &&/^[a-f0-9]{64}$/.test(original.resolution?.factProofSha256??'')&&proof?.kind==='entity-change-target-result'
      &&original.resolution?.originalResponseAuthenticated===true&&original.resolution?.originalNativeStatus===null
      &&original.resolution?.statusInferredViaContract===201&&original.resolution?.originalUnknownOutcomeRetained===true
      &&operation.method==='POST'&&operation.key===original.key&&operation.session?.user?.id===original.actorId
      &&operation.path===releaseScope(proof.clusterId,proof.workspaceId,`workflows/${proof.workflowId}/reconcile-target-result`)
      &&operation.body&&Object.keys(operation.body).sort().join(',')==='confirm_name,confirmed,executionId,planHash,revision'
      &&operation.body.confirmed===true&&operation.body.confirm_name==='native-change'&&operation.body.executionId===proof.executionId
      &&operation.body.planHash===proof.planHash&&operation.body.revision===proof.revision)return;
    if(pending.length===1&&operation?.metadataOnlyFor===original.requestId&&original.state==='response_observed'&&original.status===503
      &&/^[a-f0-9]{64}$/.test(original.resolution?.factProofSha256??'')&&proof?.kind==='entity-change-terminal-metadata'
      &&original.resolution?.nativeSuccesses===5&&original.resolution?.knownNotSent===1&&original.resolution?.unattempted===1
      &&operation.method==='POST'&&operation.key===original.key&&operation.session?.user?.id===original.actorId
      &&operation.path===releaseScope(proof.clusterId,proof.workspaceId,`workflows/${proof.workflowId}/reconcile-terminal-metadata`)
      &&operation.body&&Object.keys(operation.body).sort().join(',')==='confirm_name,confirmed,executionId,planHash,revision'
      &&operation.body.confirmed===true&&operation.body.confirm_name==='native-change'&&operation.body.executionId===proof.executionId
      &&operation.body.planHash===proof.planHash&&operation.body.revision===proof.revision)return;
    if(pending.length===1&&operation?.metadataOnlyFor===original.requestId&&original.state==='response_observed'&&original.status===503
      &&/^[a-f0-9]{64}$/.test(original.resolution?.factProofSha256??'')&&proof?.kind==='entity-change-no-send'
      &&operation.method==='POST'&&operation.key===original.key&&operation.session?.user?.id===original.actorId
      &&operation.path===releaseScope(proof.clusterId,proof.workspaceId,`workflows/${proof.workflowId}/reconcile-no-send`)
      &&operation.body&&Object.keys(operation.body).sort().join(',')==='confirm_name,confirmed,executionId,planHash,revision'
      &&operation.body.confirmed===true&&operation.body.confirm_name==='native-change'&&operation.body.executionId===proof.executionId
      &&operation.body.planHash===proof.planHash&&operation.body.revision===proof.revision)return;
    if(pending.length===1&&operation?.metadataOnlyFor===original.requestId&&original.state==='response_observed'&&original.status===503
      &&original.resolution?.knownNativeComplete===true&&/^[a-f0-9]{64}$/.test(original.resolution?.factProofSha256??'')
      &&proof?.kind==='workspace-migration'&&operation.method==='POST'&&operation.key===original.key&&operation.session?.user?.id===original.actorId
      &&operation.path===releaseScope(proof.clusterId,proof.workspaceId,`workflows/${proof.workflowId}/reconcile-metadata`)
      &&operation.body&&Object.keys(operation.body).sort().join(',')==='confirm_name,confirmed,executionId,planHash,revision'
      &&operation.body.confirmed===true&&operation.body.confirm_name==='workspace-migration'&&operation.body.executionId===proof.executionId
      &&operation.body.planHash===proof.planHash&&operation.body.revision===proof.revision)return;
    throw Error('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY');
  }
  async request(session,path,method='GET',body,{expected=[200,201],key=randomUUID(),raw=false,metadataOnlyFor}={}){
    if(!path.startsWith('/')||path.startsWith('//')||path.includes('://')||path.includes('\\'))throw Error('RELATIVE_BFF_PATH_REQUIRED');
    // A stale CLI snapshot cannot renew a session or send any next request.
    // The per-write prepared packet below remains a second durable CAS gate.
    this.save();
    if(session&&path!=='/auth/refresh'&&path!=='/auth/me/password'){
      const access=session.cookie.split('; ').find(pair=>pair.startsWith('kongos_access='));
      const claims=access?JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1],'base64url')):null;
      if(!claims||claims.exp*1000<Date.now()+90000){
        const oldSid=session.sid,oldActor=session.user.id,renewed=await this.request(session,'/auth/refresh','POST',undefined,{expected:[201]});
        const next=session.cookie.split('; ').find(pair=>pair.startsWith('kongos_access=')),identity=JSON.parse(Buffer.from(next.slice('kongos_access='.length).split('.')[1],'base64url'));
        assert.equal(identity.sid,oldSid);assert.equal(identity.sub,oldActor);session.user=renewed.data.user;session.csrf=session.cookie.split('; ').find(pair=>pair.startsWith('kongos_csrf='))?.slice('kongos_csrf='.length);this.save();
      }
    }
    const write=!['GET','HEAD'].includes(method);if(write&&path!=='/auth/login')this.assertWritable({session,path,method,body,key,metadataOnlyFor});
    const serialized=body===undefined?undefined:JSON.stringify(body),headers={...(session?.cookie?{Cookie:session.cookie}:{}),...(serialized===undefined?{}:{'Content-Type':'application/json'}),...(write?{'X-CSRF-Token':session?.csrf??'','X-Idempotency-Key':key}:{})};
    const packet=write?{method,path,key,actorId:session?.user?.id??null,sessionId:session?.sid??null,body:serialized===undefined?null:JSON.parse(serialized),bodyHash:hash(serialized??'null'),headers,state:'prepared',startedAt:new Date().toISOString()}:null;
    if(packet){this.state.requests.push(packet);this.save();}
    let response,bytes;try{
      response=await fetch(this.base+path,{method,headers,redirect:'manual',signal:AbortSignal.timeout(180000),...(serialized===undefined?{}:{body:serialized})});
      const cookies=response.headers.getSetCookie();if(session&&cookies.length)session.cookie=cookieMerge(session.cookie,cookies);
      if(packet)packet.responseCookies=cookies;this.save();bytes=Buffer.from(await response.arrayBuffer());
    }catch{if(packet){packet.state='response_unknown';this.save();}throw Error('RELEASE_WRITE_RESPONSE_UNKNOWN_ORIGINAL_RETAINED');}
    let payload;try{payload=JSON.parse(bytes.toString());}catch{payload=null;}
    if(packet){Object.assign(packet,{state:'response_observed',status:response.status,responseData:payload?.data??null,errorCode:payload?.error?.code??null,requestId:payload?.meta?.requestId??response.headers.get('x-request-id'),responseHash:hash(bytes)});this.save();}
    if(packet&&raw){packet.rawResponseText=bytes.toString();this.save();}
    assert(expected.includes(response.status),`${method} ${path.split('?')[0]} expected ${expected.join('/')} received ${response.status} ${payload?.error?.code??''}`);
    return{status:response.status,data:payload?.data,payload,bytes,headers:response.headers,requestId:payload?.meta?.requestId??response.headers.get('x-request-id')};
  }
  async login(label,username,password){
    const result=await this.request(null,'/auth/login','POST',{username,password},{expected:[201]}),session={user:result.data.user,csrf:result.data.csrfToken,cookie:cookieMerge('',result.headers.getSetCookie()),username,password};
    const access=session.cookie.split('; ').find(pair=>pair.startsWith('kongos_access='));assert(access,'Access cookie required');
    const token=JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1],'base64url'));assert.equal(token.sub,session.user.id);session.sid=token.sid;
    this.state.sessions[label]=session;this.save();return session;
  }
  async once(label,session,path,method,body,options={}){
    const old=this.state.requests.find(packet=>packet.label===label);
    if(old){assert.equal(old.path,path);assert.equal(old.method,method);assert.equal(old.actorId,session?.user?.id??null);assert.equal(old.bodyHash,hash(JSON.stringify(body)??'null'));
      if(old.state!=='response_observed'||old.status<200||old.status>=300)throw Error('ORIGINAL_FIXTURE_RECEIPT_NOT_SUCCESSFUL_NO_REPLAY');
      return{status:old.status,data:old.responseData,requestId:old.requestId,...(old.rawResponseText?{bytes:Buffer.from(old.rawResponseText)}:{})};
    }
    const index=this.state.requests.length,key=options.key??randomUUID();
    const result=await this.request(session,path,method,body,{...options,key});
    // A normal access-token renewal can add its own packet first. Bind the
    // label to the actual operation key/body/response, never its array index.
    const packets=this.state.requests.slice(index).filter(packet=>packet.key===key&&packet.path===path&&packet.method===method&&packet.actorId===(session?.user?.id??null)&&packet.bodyHash===hash(JSON.stringify(body)??'null')&&packet.state==='response_observed'&&packet.status===result.status&&packet.requestId===result.requestId);
    assert.equal(packets.length,1,'The original operation packet must be identified before recording fixture completion');
    packets[0].label=label;this.save();return result;
  }
  async administrator(){
    if(this.state.sessions.admin)return this.state.sessions.admin;
    const original=await this.login('bootstrap',this.env.LAB_BOOTSTRAP_USER,this.env.LAB_BOOTSTRAP_PASSWORD),password=releasePassword();
    this.state.adminPassword=password;this.save();
    await this.request(original,'/auth/me/password','POST',{revision:original.user.revision,current_password:original.password,new_password:password,confirmed:true});
    return this.login('admin',original.username,password);
  }
  async poll(fn,predicate,name,timeout=30000){const deadline=Date.now()+timeout;do{const value=await fn();if(predicate(value))return value;await new Promise(resolve=>setTimeout(resolve,200));}while(Date.now()<deadline);throw Error(name);}
  report(passed,errorCode){
    const snapshot=ledgerSnapshots.get(this);
    if(!snapshot||this.milestone!==snapshot.milestone||this.reportPath!==snapshot.reportPath)
      throw Error('RELEASE_REPORT_SAVE_PATH_INVALID');
    assertReleasePrivateDirectory(snapshot.privateSelection);
    assertReleaseReportDirectory(snapshot.reportSelection,{create:true});
    if(!snapshot.reportSelection.custom)mkdirSync(snapshot.reportSelection.directory,{recursive:true});
    const report={passed,phase:this.state.phase,milestone:this.milestone,environment:'isolated real Kong OSS 1.5.1 + PostgreSQL 16 + Redis 7',productionDeployment:false,originalServicesChanged:false,credentialsRecorded:false,checks:this.state.checks,requests:this.state.requests.map(packet=>({method:packet.method,path:packet.path.split('?')[0],key:packet.key,actorId:packet.actorId,sessionId:packet.sessionId,state:packet.state,status:packet.status,requestId:packet.requestId,errorCode:packet.errorCode,bodyHash:packet.bodyHash,responseHash:packet.responseHash})),...(errorCode?{errorCode}:{})};
    try{writeFileSync(this.reportPath,JSON.stringify(report,null,2)+'\n',snapshot.reportSelection.custom?{flag:'wx'}:undefined);}
    catch(error){if(snapshot.reportSelection.custom&&error?.code==='EEXIST')throw Error('ORIGINAL_RELEASE_REPORT_PRESENT_NO_OVERWRITE');throw error;}
    return report;
  }
}
