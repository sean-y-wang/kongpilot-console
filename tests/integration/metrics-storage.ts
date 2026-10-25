import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import { execFileSync } from 'node:child_process';
import { randomBytes,randomUUID } from 'node:crypto';
import { mkdirSync,writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { MetricsCredentialsService } from '../../apps/console-api/src/modules/metrics/metrics-credentials.service';
import { MetricsRepositoryService } from '../../apps/console-api/src/modules/metrics/metrics-repository.service';
import { MetricsSettingsService } from '../../apps/console-api/src/modules/metrics/metrics-settings.service';
import { MetricsWriteFenceService } from '../../apps/console-api/src/modules/metrics/metrics-write-fence.service';
import { METRICS_AUDIENCE,METRICS_PURPOSES,type MetricsCatalogInput } from '../../apps/console-api/src/modules/metrics/metrics.types';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { workspaceTag } from '../../apps/console-api/src/infrastructure/kong/tags';

async function main():Promise<void>{
 const container=`kongos-m5-storage-${randomUUID().slice(0,8)}`,checks:any[]=[],c1=randomUUID(),c2=randomUUID(),c3=randomUUID();let db:DbService|undefined;
 const assert=(condition:any)=>{if(!condition)throw new Error('Metrics storage assertion failed');};
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error){console.error(`Failed safe check: ${name}`);throw error;}};
 const rejected=async(fn:()=>Promise<any>,expected:number|string)=>{try{await fn();throw new Error('Expected rejection');}catch(error:any){
  if(typeof expected==='number'?error.getStatus?.()!==expected:error.code!==expected)throw new Error(`Expected ${expected}, received ${error.getStatus?.()??error.code??'unknown'}`);}};
 const family=()=>METRICS_PURPOSES.map(purpose=>({purpose,audience:METRICS_AUDIENCE[purpose],token:randomBytes(32).toString('base64url')}));
 try{
  execFileSync('docker',['run','-d','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
  const port=execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.CONSOLE_ENCRYPTION_KEY='ed'.repeat(32);
  process.env.BOOTSTRAP_ADMIN_USERNAME='metrics-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!Metrics2026Password';
  db=new DbService();for(let i=0;i<60;i++){try{await db.one('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,100));if(i===59)throw new Error('Disposable PostgreSQL unavailable');}}
  await db.migrateAndSeed();const secrets=new SecretService(),audit=new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)),workspaces=new WorkspaceResolverService(db),
    credentials=new MetricsCredentialsService(db,secrets,audit),repository=new MetricsRepositoryService(db,secrets,workspaces),settings=new MetricsSettingsService(db,secrets,audit),fence=new MetricsWriteFenceService(db);
  await db.exec("INSERT INTO clusters(id,name,admin_url) VALUES($1,'metrics-a','http://kong-metrics:8001'),($2,'legacy-alias','http://kong-metrics:8001'),($3,'different','http://kong-other:8001')",[c1,c2,c3]);
  const w1=randomUUID(),w2=randomUUID();await db.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'pay','pay'),($3,$2,'ops','ops')",[w1,c1,w2]);
  await workspaces.ensureDefault(c1);await workspaces.ensureDefault(c2);await workspaces.ensureDefault(c3);
  let keys=family();await check('all migrations through007 execute and new settings remain inert until enrollment',async()=>{
   assert((await settings.get(c1)).credentialGeneration===0);assert((await settings.get(c1)).enabled===false);assert(!await db!.one('SELECT cluster_id FROM metrics_settings WHERE cluster_id=$1',[c1]));});
  await check('four-purpose enrollment commits encrypted keys, safe fingerprints and no raw secrets in audit',async()=>{
   const result=await credentials.trustedEnroll({clusterId:c1,generation:1,credentials:keys});assert(result.credentials.length===4);
   const rows=await db!.query<any>('SELECT token_secret FROM metrics_credentials WHERE cluster_id=$1',[c1]);assert(rows.every(row=>row.token_secret.startsWith('v1.')));
   const audits=JSON.stringify(await db!.query('SELECT before,after,json_patch FROM audit_events'));assert(keys.every(item=>!audits.includes(item.token)));});
  await check('same generation and keys replay idempotently; changed contents and reused purpose keys fail',async()=>{
   const before=await db!.one<any>('SELECT count(*)::int AS n FROM metrics_credentials');await credentials.trustedEnroll({clusterId:c1,generation:1,credentials:keys});
   assert((await db!.one<any>('SELECT count(*)::int AS n FROM metrics_credentials')).n===before.n);
   await rejected(()=>credentials.trustedEnroll({clusterId:c1,generation:1,credentials:family()}),409);
   await rejected(()=>credentials.trustedEnroll({clusterId:c1,generation:2,credentials:keys.map(item=>({...item,token:keys[0].token}))}),400);});
  const oldIdentity=await credentials.validate(keys[0].token,c1,keys[0].purpose,keys[0].audience);
  await check('cross-cluster and cross-purpose bearer keys reject with no identity fallback',async()=>{
   await rejected(()=>credentials.validate(keys[0].token,c2,'native_scrape','bff'),401);
   await rejected(()=>credentials.validate(keys[0].token,c1,'collector_catalog','bff'),401);
   await rejected(()=>credentials.assertCurrent({...oldIdentity}),401);});
  await check('atomic generation rotation immediately invalidates every old key and issued identity',async()=>{
   const old=keys;keys=family();await credentials.trustedEnroll({clusterId:c1,generation:2,credentials:keys});
   for(const item of old)await rejected(()=>credentials.validate(item.token,c1,item.purpose,item.audience),401);
   await rejected(()=>credentials.assertCurrent(oldIdentity),401);assert((await db!.one<any>("SELECT count(*)::int AS n FROM metrics_credentials WHERE cluster_id=$1 AND status='active'",[c1])).n===4);});
  await check('audit failure rolls back the complete four-key rotation rather than leaving a partial family',async()=>{
   const failing=new MetricsCredentialsService(db!,secrets,{append:async()=>{throw new Error('controlled audit failure');}} as any);
   try{await failing.trustedEnroll({clusterId:c1,generation:3,credentials:family()});throw new Error('Expected rollback');}catch(error:any){assert(error.message==='controlled audit failure');}
   assert((await credentials.currentGeneration(c1)).generation===2);await credentials.validate(keys[0].token,c1,keys[0].purpose,keys[0].audience);});
  await check('deferred SQL constraint rejects an incomplete current credential generation',async()=>{
   await rejected(()=>db!.exec('UPDATE metrics_settings SET credential_generation=3 WHERE cluster_id=$1',[c1]),'P0001');
   await rejected(()=>db!.exec("UPDATE metrics_credentials SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days' WHERE cluster_id=$1 AND purpose='native_scrape' AND status='active'",[c1]),'P0001');});
  await check('credential identity is immutable and revoked keys cannot reactivate or be prematurely deleted',async()=>{
   await rejected(()=>db!.exec("UPDATE metrics_credentials SET token_fingerprint=$2 WHERE cluster_id=$1 AND status='active'",[c1,'a'.repeat(64)]),'P0001');
   await rejected(()=>db!.exec("UPDATE metrics_credentials SET status='active',revoked_at=NULL,retention_until=NULL WHERE cluster_id=$1 AND generation=1",[c1]),'P0001');
   await rejected(()=>db!.exec('DELETE FROM metrics_credentials WHERE cluster_id=$1',[c1]),'P0001');});
  const source=randomUUID(),other=randomUUID();await db.exec("INSERT INTO data_sources(id,cluster_id,name,type,base_url) VALUES($1,$2,'same','prometheus','http://prometheus:9090'),($3,$4,'other','prometheus','http://other-prom:9090')",[source,c1,other,c3]);
  const user=await db.one<any>('SELECT id FROM users WHERE super_admin');
  await check('settings active source requires current same-cluster Prometheus and revision CAS',async()=>{
   await rejected(()=>settings.configure(c1,{revision:2,activeSourceId:other},{actorId:user.id}),400);
   const before=await settings.get(c1);await settings.configure(c1,{revision:before.revision,activeSourceId:source,enabled:true},{actorId:user.id});
   await rejected(()=>settings.configure(c1,{revision:before.revision,activeSourceId:source},{actorId:user.id}),409);
   await rejected(()=>db!.exec('UPDATE metrics_settings SET active_source_id=$2 WHERE cluster_id=$1',[c1,other]),'23503');});
  const service1=randomUUID(),service2=randomUUID(),route1=randomUUID(),route2=randomUUID(),consumer=randomUUID(),scope=transportScopeFor('http://kong-metrics:8001');
  let observedNode:string|undefined;
  let pairs:MetricsCatalogInput['routePairs']=[{service:{id:service1,host:'shared-host',tags:[workspaceTag('pay'),'team-pay']},route:{id:route1,name:'route-pay',service:{id:service1},tags:[workspaceTag('pay'),'route-blue']}},
   {service:{id:service2,host:'shared-host',tags:[workspaceTag('ops')]},route:{id:route2,name:'route-ops',service:{id:service2},tags:[workspaceTag('ops')]}}];
  let consumers=[{id:consumer,username:'verified-consumer',tags:[workspaceTag('pay'),'team-pay']}];
  const publish=async(cid=c1,rows=pairs,cs=consumers)=>repository.publishVerifiedCatalog({cid,nodeId:scope,transportScope:scope,expectedCatalogRevision:(await settings.get(cid)).catalogRevision,
   observedAt:Date.now(),observedKongNodeId:observedNode,complete:true,routePairs:rows,consumers:cs});
  await check('paired Route labels resolve unnamed shared-host Services; ambiguous service-only labels remain unassigned',async()=>{
   await publish();const a=await repository.resolvePair(c1,'shared-host','route-pay'),b=await repository.resolvePair(c1,'shared-host','route-ops');
   assert(a.quality==='verified'&&a.assignment.service_id===service1&&a.assignment.workspace_id===w1);
   assert(b.quality==='verified'&&b.assignment.service_id===service2&&b.assignment.workspace_id===w2);assert((await repository.resolvePair(c1,'shared-host')).quality!=='verified');});
  await check('quarantined native objects still participate in label collision proof and cannot contaminate another workspace',async()=>{
   const collision=structuredClone(pairs);collision[0].route!.name=null;collision[1].route!.name=route1;
   collision[1].route!.tags=['kos-ws-unknown'];await publish(c1,collision);
   const result=await repository.resolvePair(c1,'shared-host',route1);assert(result.quality==='ambiguous'&&result.assignment===null);
   const issues=await db!.query<any>('SELECT * FROM metrics_label_issues');assert(!JSON.stringify(issues).includes('shared-host'));await publish();});
  let initial:any;await check('pure catalog refresh preserves revision, immutable opening time and membership epoch',async()=>{
   initial=await repository.resolvePair(c1,'shared-host','route-pay');const revision=(await settings.get(c1)).catalogRevision;
   await publish();const updated=await repository.resolvePair(c1,'shared-host','route-pay');
   assert((await settings.get(c1)).catalogRevision===revision);
   assert(initial.quality==='verified'&&updated.quality==='verified'&&updated.assignment.epoch_id===initial.assignment.epoch_id&&updated.assignment.valid_from===initial.assignment.valid_from);});
  await check('business tag provenance changes rotate epochs even when the combined tag set stays the same',async()=>{
   pairs[0].service.tags=[workspaceTag('pay'),'route-blue'];pairs[0].route!.tags=[workspaceTag('pay'),'team-pay'];await publish();const moved=await repository.resolvePair(c1,'shared-host','route-pay');
   assert(moved.quality==='verified'&&moved.assignment.epoch_id!==initial.assignment.epoch_id);});
  await check('service name changes create new series without relabeling historical rows',async()=>{
   pairs[0].service.name='renamed-service';await publish();assert((await repository.resolvePair(c1,'shared-host','route-pay')).quality!=='verified');
   const newer=await repository.resolvePair(c1,'renamed-service','route-pay');assert(newer.quality==='verified');
   assert((await db!.one<any>('SELECT service_label FROM metrics_assignment_epochs WHERE id=$1',[initial.assignment.epoch_id])).service_label==='shared-host');});
  await check('malformed or cross-workspace Route membership never emits an authorized workspace label',async()=>{
   const bad=structuredClone(pairs);bad[0].route!.tags=[workspaceTag('ops')];await publish(c1,bad);assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');
   bad[0].route!.tags=[workspaceTag('pay'),workspaceTag('ops')];await publish(c1,bad);assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');await publish();});
  await check('duplicate reserved tags quarantine instead of silently collapsing into a valid workspace',async()=>{
   const bad=structuredClone(pairs);bad[0].route!.tags=[workspaceTag('pay'),workspaceTag('pay')];await publish(c1,bad);
   assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');await publish();});
  await check('catalog cursors bind generation and catalog revision, preventing mixed snapshots',async()=>{
   const page=await repository.catalog(c1,{size:1});assert(page.nextCursor);await publish();
   assert((await repository.catalog(c1,{size:1,cursor:page.nextCursor!})).items.length===1);
   pairs[0].route!.tags!.push('cursor-identity-change');await publish();await rejected(()=>repository.catalog(c1,{size:1,cursor:page.nextCursor!}),409);});
  await check('explicitly empty authorized-ID arrays never become unrestricted candidate inventory',async()=>{
   assert((await repository.currentAllowedEpochs(c1,{})).items.length>0);
   assert((await repository.currentAllowedEpochs(c1,{authorizedServiceIds:[]})).items.length===0);
   assert((await repository.currentAllowedEpochs(c1,{authorizedServiceIds:[],authorizedRouteIds:[],authorizedConsumerIds:[]})).items.length===0);});
  await check('private Consumer candidate inventory remains current and cannot widen explicit Consumer-ID scopes',async()=>{
   const included=await repository.currentAllowedEpochs(c1,{workspaceId:w1,authorizedServiceIds:[service1],includeConsumerCandidates:true});
   assert(included.items.some(item=>item.consumer_id===consumer));
   const denied=await repository.currentAllowedEpochs(c1,{workspaceId:w1,authorizedServiceIds:[service1],authorizedConsumerIds:[],includeConsumerCandidates:true});
   assert(denied.items.every(item=>item.consumer_id===null));});
  await check('immutable historical attribution cannot be reassigned, reopened, or erased before retention',async()=>{
   await rejected(()=>db!.exec('UPDATE metrics_assignment_epochs SET workspace_id=$2 WHERE id=$1',[initial.assignment.epoch_id,w2]),'P0001');
   await rejected(()=>db!.exec('UPDATE metrics_assignment_epochs SET closed_at=NULL,close_reason=NULL,retention_until=NULL WHERE id=$1',[initial.assignment.epoch_id]),'P0001');
   await rejected(()=>db!.exec('DELETE FROM metrics_assignment_epochs WHERE id=$1',[initial.assignment.epoch_id]),'P0001');});
  await check('closed epochs may validate queued events only inside their complete original interval; public selectors remain current',async()=>{
   const epoch=await repository.resolvePair(c1,'renamed-service','route-pay');assert(epoch.quality==='verified');if(epoch.quality!=='verified')return;
   const t=Math.max(Date.now(),Date.parse(epoch.assignment.valid_from));await new Promise(r=>setTimeout(r,10));
   pairs[0].service.tags=[workspaceTag('ops'),'team-pay'];pairs[0].route!.tags=[workspaceTag('ops'),'team-pay'];consumers[0].tags=[workspaceTag('ops'),'team-pay'];await publish();
   const valid=await repository.validateEventBindings(c1,{credentialGeneration:2,items:[{index:0,serviceId:service1,routeId:route1,startedAt:t,endedAt:t,epochIds:[epoch.assignment.epoch_id]}]});
   assert(valid.items[0].quality==='verified'&&valid.items[0].routeEpoch!.workspace_id===w1);
   const row=await db!.one<any>('SELECT closed_at FROM metrics_assignment_epochs WHERE id=$1',[epoch.assignment.epoch_id]);
   const crossing=await repository.validateEventBindings(c1,{credentialGeneration:2,items:[{index:0,serviceId:service1,routeId:route1,startedAt:t,endedAt:new Date(row.closed_at).getTime()+1,epochIds:[epoch.assignment.epoch_id]}]});assert(crossing.items[0].quality!=='verified');
   const current=await repository.currentAllowedEpochs(c1,{workspaceId:w1,authorizedRouteIds:[route1]});assert(current.items.length===0);
   await rejected(()=>repository.currentAllowedEpochs(c1,{platformHistory:true}),400);});
  await check('event validation is bounded by aggregate UUID references and rejects stale credential families',async()=>{
   await rejected(()=>repository.validateEventBindings(c1,{credentialGeneration:1,items:[]}),409);
   const now=Date.now();await rejected(()=>repository.validateEventBindings(c1,{credentialGeneration:2,items:Array.from({length:86},(_,index)=>({index,serviceId:service1,routeId:route1,consumerId:consumer,startedAt:now,endedAt:now}))}),400);});
  await db.exec("INSERT INTO workspaces(cluster_id,code,name) VALUES($1,'ops','ops')",[c2]);await publish(c2);
  let op=randomUUID(),receipt:any;await db.exec("INSERT INTO mutation_operations(id,cluster_id,action,idempotency_key,request_hash,state,transport_scope) VALUES($1,$2,'update',$3,$4,'running',$5)",[op,c1,randomUUID(),'b'.repeat(64),scope]);
  await check('durable fence closes every physical alias before transport; duplicate prepares are idempotent',async()=>{
   const input={cid:c1,transportScope:scope,operationId:op,requestFingerprint:'c'.repeat(64),entityType:'services',entityId:service1,method:'PATCH',path:`/services/${service1}`,body:{tags:['secret-never-stored']}};
   receipt=await fence.beforeNativeWrite(input);const second=await fence.beforeNativeWrite(input);assert(receipt.id===second.id&&receipt.clusterIds.includes(c2)&&receipt.closed>0);
   assert(!(await db!.one<any>('SELECT count(*)::int AS n FROM metrics_assignment_epochs WHERE cluster_id=ANY($1::uuid[]) AND closed_at IS NULL',[ [c1,c2] ])).n);
   assert(!JSON.stringify(await db!.query('SELECT * FROM metrics_write_fences')).includes('secret-never-stored'));});
  await check('native200 acknowledgement cannot unblock a running or uncertain durable parent',async()=>{
   await fence.settle(receipt.id,'success');const result=await publish();assert(result.blocked&&result.opened===0);
   await db!.exec("UPDATE mutation_operations SET state='uncertain',remote_completed=true WHERE id=$1",[op]);assert((await publish()).blocked);
   await rejected(()=>fence.beforeNativeWrite({cid:c1,transportScope:scope,operationId:op,requestFingerprint:'d'.repeat(64),entityType:'services',method:'PATCH',path:`/services/${service1}`}),409);});
  await check('known native400 parent failure resumes only after fresh complete proof, despite remote_completed false',async()=>{
   await db!.exec("UPDATE mutation_operations SET state='failed',remote_completed=false WHERE id=$1",[op]);const result=await publish();assert(!result.blocked&&result.opened>0);
   const current=await repository.resolvePair(c1,'renamed-service','route-pay');assert(current.quality==='verified'&&current.assignment.epoch_id!==initial.assignment.epoch_id);});
  await check('actual Kong node replacement rotates every endpoint epoch without mixing reset counters',async()=>{
   observedNode='native-node-a';await publish();const before=await repository.resolvePair(c1,'renamed-service','route-pay');assert(before.quality==='verified');
   observedNode='native-node-b';await publish();const after=await repository.resolvePair(c1,'renamed-service','route-pay');assert(after.quality==='verified');
   if(before.quality==='verified'&&after.quality==='verified')assert(before.assignment.epoch_id!==after.assignment.epoch_id);
   assert((await repository.getObservedNode(c1,scope))!.observedKongNodeId==='native-node-b');
   const revision=(await settings.get(c1)).catalogRevision;await rejected(()=>repository.publishVerifiedCatalog({cid:c1,nodeId:scope,transportScope:scope,expectedCatalogRevision:revision,
    observedAt:Date.now(),complete:true,routePairs:pairs,consumers}),400);});
  await check('scan revision CAS refuses evidence captured before a fence',async()=>{
   const revision=(await settings.get(c1)).catalogRevision;op=randomUUID();await db!.exec("INSERT INTO mutation_operations(id,cluster_id,action,idempotency_key,request_hash,state,transport_scope) VALUES($1,$2,'update',$3,$4,'running',$5)",[op,c1,randomUUID(),'e'.repeat(64),scope]);
   await fence.beforeNativeWrite({cid:c1,transportScope:scope,operationId:op,requestFingerprint:'f'.repeat(64),entityType:'routes',method:'PATCH',path:`/routes/${route1}`});
   await rejected(()=>repository.publishVerifiedCatalog({cid:c1,nodeId:scope,transportScope:scope,expectedCatalogRevision:revision,observedAt:Date.now(),observedKongNodeId:observedNode,complete:true,routePairs:pairs,consumers}),409);
   await db!.exec("UPDATE mutation_operations SET state='succeeded',remote_completed=true WHERE id=$1",[op]);await publish();});
  await check('incomplete catalogs close attribution rather than claiming label uniqueness',async()=>{
   const revision=(await settings.get(c1)).catalogRevision;await repository.publishVerifiedCatalog({cid:c1,nodeId:scope,transportScope:scope,expectedCatalogRevision:revision,observedAt:Date.now(),complete:false,routePairs:[],consumers:[]});
   assert((await repository.catalog(c1)).complete===false);assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');});
  await check('cluster connection metadata edits invalidate old proof while routine health probes preserve the epoch',async()=>{
   await publish();const before=await repository.resolvePair(c1,'renamed-service','route-pay');assert(before.quality==='verified');
   let revision=(await settings.get(c1)).catalogRevision;await db!.exec("UPDATE clusters SET status='healthy' WHERE id=$1",[c1]);assert((await settings.get(c1)).catalogRevision===revision);
   const cursor=await repository.catalog(c1,{size:1});assert(cursor.nextCursor);
   await db!.exec('UPDATE clusters SET connection_secret=$2 WHERE id=$1',[c1,secrets.encrypt({header_value:'synthetic-key'},`cluster:${c1}:connection`)]);
   assert((await settings.get(c1)).catalogRevision===revision+1);assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');
   await rejected(()=>repository.catalog(c1,{size:1,cursor:cursor.nextCursor!}),409);await publish();
   await db!.exec("UPDATE clusters SET status='disabled' WHERE id=$1",[c1]);assert((await publish()).blocked);
   await db!.exec("UPDATE clusters SET status='healthy' WHERE id=$1",[c1]);assert((await repository.resolvePair(c1,'renamed-service','route-pay')).quality!=='verified');await publish();
   const after=await repository.resolvePair(c1,'renamed-service','route-pay');assert(after.quality==='verified');
   if(before.quality==='verified'&&after.quality==='verified')assert(before.assignment.epoch_id!==after.assignment.epoch_id);});
  await check('pure refresh never extends an existing cursor expiration, and stale proof yields no attributed data',async()=>{
   await db!.exec("INSERT INTO workspaces(cluster_id,code,name) VALUES($1,'ops','ops')",[c3]);
   await db!.exec('INSERT INTO metrics_settings(cluster_id,max_age_ms) VALUES($1,1000)',[c3]);
   const otherScope=transportScopeFor('http://kong-other:8001');
   const shortProof=async()=>repository.publishVerifiedCatalog({cid:c3,nodeId:otherScope,transportScope:otherScope,expectedCatalogRevision:(await settings.get(c3)).catalogRevision,
    observedKongNodeId:'native-node-other',observedAt:Date.now(),complete:true,routePairs:pairs,consumers});
   await shortProof();const page=await repository.catalog(c3,{size:1}),revision=page.catalogRevision;assert(page.nextCursor);
   await new Promise(r=>setTimeout(r,550));await shortProof();assert((await settings.get(c3)).catalogRevision===revision);
   await new Promise(r=>setTimeout(r,650));await rejected(()=>repository.catalog(c3,{size:1,cursor:page.nextCursor!}),409);
   assert((await repository.catalog(c3)).complete===true);
   await new Promise(r=>setTimeout(r,450));const expired=await repository.currentAllowedEpochs(c3,{authorizedRouteIds:[route1]});
   assert(expired.items.length===0&&expired.warnings.includes('METRICS_CATALOG_STALE'));});
  mkdirSync('artifacts/M5',{recursive:true});writeFileSync('artifacts/M5/storage-postgres.json',JSON.stringify({milestone:'M5',database:'isolated disposable PostgreSQL16; no primary runtime or native calls',passed:checks.length,checks},null,2));
  console.log(`Metrics PostgreSQL storage: ${checks.length}/${checks.length} passed`);
 }finally{await db?.onModuleDestroy();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}
}
main().catch(()=>{console.error('Metrics PostgreSQL storage verification failed');process.exitCode=1;});
