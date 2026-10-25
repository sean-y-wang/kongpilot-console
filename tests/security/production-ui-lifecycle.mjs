import { chromium, expect } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { PRODUCTION_UI_ACTIONS, PRODUCTION_ENTITY_TYPES, PRODUCTION_ENTITY_LABELS, PRODUCTION_PLUGIN_NAMES, productionPluginConfigurations, productionEntityInput, productionEntityEdit } from './lib/production-ui-fixtures.mjs';
import * as formModelModule from './lib/production-form-model.ts';
import { fillSchemaUi, chooseUiOption } from './lib/production-schema-fill.mjs';
import { productionSha, productionUuid, validateProductionHandoff, createProductionUiJournal, proveProductionActor, revalidateProductionAuthority, armProductionUi, beforeProductionUiPacket, packetForProductionUi, productionAttemptFor, observeProductionUiAck, confirmProductionUiReceipt, productionReceiptPath, stopProductionUi, productionUiSecrets, proveProductionIsolation, armProductionUiToggle } from './lib/production-ui-journal.mjs';
import { PRODUCTION_UI_JOURNAL, readProductionUiReference, readProductionPrivateFile, durableProductionJson, productionCookies } from './lib/production-ui-storage.mjs';
import { PRODUCTION_UI_PAUSE_CODE, pauseProductionUiIfNeeded, prepareProductionUnusedTail, productionActionAlreadyCompleted } from './lib/production-ui-continuation.mjs';
const { productionEditorSchema, productionExpectedBody, productionNonSecretExpected } = formModelModule.default ?? formModelModule;

// Source imports do not read an environment, private reference, browser, or API.
// Root releases this independent fresh production fixture only after M8 UI12.
if (process.env.PRODUCTION_UI_EXCLUSIVE_READY !== 'true' && process.env.PRODUCTION_UI_UNUSED_TAIL_READY !== 'true') throw Error('PRODUCTION_ROOT_EXCLUSIVE_HANDOFF_REQUIRED');
if(process.env.PRODUCTION_UI_EXCLUSIVE_READY==='true'&&process.env.PRODUCTION_UI_UNUSED_TAIL_READY==='true')throw Error('PRODUCTION_EXCLUSIVE_ENTRY_REQUIRED');
const unusedTail=process.env.PRODUCTION_UI_UNUSED_TAIL_READY==='true',reference=readProductionUiReference();
const acknowledgedTail=process.env.PRODUCTION_UI_ACKNOWLEDGED_TAIL_READY==='true';
let reportPath,journal;
if(acknowledgedTail){
 journal=readProductionPrivateFile(PRODUCTION_UI_JOURNAL).value;
 if(unusedTail||journal.phase!=='active'||journal.nextIndex!==1||journal.attempts.length!==1||journal.attempts[0].state!=='succeeded'||journal.reviews.some(p=>p.state!=='succeeded')||journal.inFlight!==null||journal.acknowledgedCarrierContinuation?.actualOriginalReceiptConfirmed!==true)throw Error('PRODUCTION_EXACT_ONE_CONFIRMED_CARRIER_REQUIRED');
 reportPath='artifacts/production/ui-lifecycle-unused-authority-tail.json';if(existsSync(reportPath))throw Error('PRODUCTION_UNUSED_AUTHORITY_TAIL_ALREADY_USED');
}else if(unusedTail){
  const old=readProductionPrivateFile(PRODUCTION_UI_JOURNAL),oldReportPath=old.value.currentReportPath;
  if(!/^artifacts\/production\/ui-lifecycle(?:-unused-preflight|-safe-destinations|-unused-authority-tail|-known-fixture-checkpoint(?:-[1-9]\d?)?|-known-validation-checkpoint|-known-normalization-checkpoint|-unused-tail-[1-9]\d?)?\.json$/.test(oldReportPath??''))throw Error('PRODUCTION_FIXED_PREVIOUS_REPORT_REQUIRED');
  const oldReportBytes=readFileSync(oldReportPath),h=reference.uiUnusedTailHandoff;
  if(h?.renewalReportPath!==`artifacts/production/ui-original-session-maintenance-${(old.value.continuations?.length??0)+1}.json`)throw Error('PRODUCTION_FIXED_MAINTENANCE_REPORT_REQUIRED');
  const renewalBytes=readFileSync(h.renewalReportPath),prepared=prepareProductionUnusedTail(old.value,old.bytes,JSON.parse(oldReportBytes),oldReportBytes,reference,JSON.parse(renewalBytes),renewalBytes);
  const archivePath=`/tmp/kongos-production-ui-unused-tail-${prepared.marker.generation}-history.json`;reportPath=`artifacts/production/ui-lifecycle-unused-tail-${prepared.marker.generation}.json`;
  if(existsSync(archivePath)||existsSync(reportPath))throw Error('PRODUCTION_UNUSED_TAIL_ENTRY_ALREADY_USED');
  durableProductionJson(archivePath,prepared.history,true);const archiveBytes=readFileSync(archivePath);
  journal=prepared.journal;journal.continuations.at(-1).history={path:archivePath,sha256:productionSha(archiveBytes),bytes:archiveBytes.length};
}else{
  reportPath=process.env.PRODUCTION_UI_SAFE_DESTINATION_READY==='true'?'artifacts/production/ui-lifecycle-safe-destinations.json':process.env.PRODUCTION_UI_UNUSED_PREFLIGHT_READY==='true'?'artifacts/production/ui-lifecycle-unused-preflight.json':'artifacts/production/ui-lifecycle.json';const historyPath='/tmp/kongos-production-ui-original-handoff.json';
  if (existsSync(PRODUCTION_UI_JOURNAL)||existsSync(historyPath)||existsSync(reportPath)) throw Error('PRODUCTION_ORIGINAL_JOURNAL_EXISTS_NO_REPLAY');
  if(process.env.PRODUCTION_UI_UNUSED_PREFLIGHT_READY==='true'&&reference.zeroUiPreflightContinuation?.zeroPriorBusinessTransports!==true)throw Error('PRODUCTION_ZERO_TRANSPORT_PREFLIGHT_PROOF_REQUIRED');
  if(process.env.PRODUCTION_UI_SAFE_DESTINATION_READY==='true'&&reference.historicalRejectedCarrier?.state!=='server-rejected-native-post-not-issued')throw Error('PRODUCTION_ORIGINAL_DENIAL_PROOF_REQUIRED');
  const reportBytes=readFileSync(['artifacts/production/production-ui-handoff.json','artifacts/production/production-ui-handoff-unused-session.json','artifacts/production/production-ui-handoff-unused-preflight.json','artifacts/production/production-ui-handoff-safe-destinations.json'].includes(reference.uiHandoff?.securityReportPath) ? reference.uiHandoff.securityReportPath : (()=>{throw Error('PRODUCTION_FIXED_HANDOFF_REPORT_REQUIRED');})());
  journal=createProductionUiJournal(validateProductionHandoff(reference,JSON.parse(reportBytes),reportBytes));journal.scopeLabels={clusterLabel:reference.uiHandoff.clusterLabel,workspaceName:reference.uiHandoff.workspaceName};journal.pem=structuredClone(reference.pem);
  durableProductionJson(historyPath,reference,true);const historyBytes=readFileSync(historyPath);
  journal.history={path:historyPath,sha256:productionSha(historyBytes),bytes:historyBytes.length,originalReferenceSha256:productionSha(reference),originalRequestPrefixSha256:productionSha(reference.requests),originalRequestCount:reference.requests.length};
  journal.originalHandoffSha256=reference.uiHandoff.securityReportSha256;
}
const originalRequestPrefixSha256=journal.history.originalRequestPrefixSha256;journal.currentReportPath=reportPath;
const secrets=new Set(reference.secrets);for(const pair of reference.session.cookie.split('; '))secrets.add(pair.slice(pair.indexOf('=')+1));
for(const value of journal.secrets??[])secrets.add(value);productionUiSecrets(journal.pem,secrets);
const pluginConfigs=journal.pluginConfigs??productionPluginConfigurations(()=>{const value=`prod-${randomUUID()}-${randomUUID()}`;secrets.add(value);return value;});journal.pluginConfigs=pluginConfigs;
const inherited=journal.progress??{},checks=inherited.checks??[],screenshots=inherited.screenshots??[],reads=inherited.reads??[],domActions=inherited.domActions??[],coverage=inherited.coverage??[],report={version:1,milestone:'M0-M8-production-ui',testTag:journal.tag,origin:journal.origin,clusterId:journal.cid,workspaceId:journal.wid,allPassed:false,checks,screenshots,reads,domActions,coverage,
  entityTypes:[...PRODUCTION_ENTITY_TYPES],pluginNames:[...PRODUCTION_PLUGIN_NAMES],plannedBusinessWrites:177,plannedCoreCoverageWrites:169,plannedRepresentativeBindingWrites:8,plannedCleanupWrites:1,plannedActions:[...PRODUCTION_UI_ACTIONS],actualNativeReadbackInherited:false,nativeComparisonOwner:'Security',loginWrites:0,refreshWrites:0,externalNormalSessionRenewalWrites:(journal.continuations?.length??0),directAdminRequests:0,originalHandoffSha256:journal.originalHandoffSha256,originalRequestPrefixSha256,inheritedConfirmedUiWrites:unusedTail?journal.nextIndex:0,priorReports:journal.continuations?.map(row=>({generation:row.generation,sha256:row.originalReportSha256,history:row.history}))??[]};
let browser,context,page,phase='preflight',chain=Promise.resolve(),asyncError=null;const runtimeStartedAt=Date.now();
function retain(){durableProductionJson(PRODUCTION_UI_JOURNAL,{...journal,secrets:[...secrets]},false);}
durableProductionJson(PRODUCTION_UI_JOURNAL,{...journal,secrets:[...secrets]},!unusedTail&&!acknowledgedTail);
function saveReport(){Object.assign(report,{phase,performedAt:new Date().toISOString(),passed:checks.filter(row=>row.passed).length,failed:checks.filter(row=>!row.passed).length,successfulUiWrites:journal.attempts.filter(row=>row.state==='succeeded'&&!row.action.startsWith('cleanup.')).length,successfulCleanupWrites:journal.attempts.filter(row=>row.state==='succeeded'&&row.action.startsWith('cleanup.')).length,unknownUiWrites:journal.attempts.filter(row=>row.state==='response_unknown').length,readonlyPostReviews:journal.reviews.length,journalPhase:journal.phase});durableProductionJson(reportPath,report,false,0o644);}
function check(name,condition,facts={}){phase=name;checks.push({name,passed:!!condition,...facts});saveReport();if(!condition)throw Error('PRODUCTION_UI_ASSERTION_FAILED');}
async function settle(){
  await chain;
  // Route interception records a capability read before its response callback
  // joins the chain. Wait for those read-only packets before checkpointing.
  await expect.poll(async()=>{await chain;return !journal.reviews.some(r=>r.state==='prepared');},{timeout:10000,intervals:[50,100,250]}).toBe(true);
  if(asyncError||journal.phase==='stopped-without-replay')throw Error('PRODUCTION_ORIGINAL_UNKNOWN_OR_BLOCKED_NO_REPLAY');
}
async function runAction(action,perform){
  if(productionActionAlreadyCompleted(journal,action))return;
  await settle();journal.progress={checks,screenshots,reads,domActions,coverage};
  if(pauseProductionUiIfNeeded(journal,retain,Date.now(),Date.now()-runtimeStartedAt>120000)){phase='safe bounded-runner/session-window checkpoint';saveReport();throw Error(PRODUCTION_UI_PAUSE_CODE);}
  await perform();await settle();journal.progress={checks,screenshots,reads,domActions,coverage};retain();
}
function q(suffix){return `/api/v1/clusters/${journal.cid}/${suffix}?workspaceId=${journal.wid}`;}
async function protectedRead(path,expectedStatus=200){
  if(!path.startsWith('/api/v1/')||path.includes('reveal=')||path.includes('://'))throw Error('PRODUCTION_BFF_READ_ONLY_PATH_REQUIRED');
  const response=await context.request.get(journal.origin+path,{maxRedirects:0}),payload=await response.json();const requestId=payload.meta?.requestId??response.headers()['x-request-id'];
  reads.push({method:'GET',path:new URL(response.url()).pathname,query:new URL(response.url()).search,status:response.status(),requestId});
  check('protected BFF GET actual status and request ID',response.status()===expectedStatus&&productionUuid(requestId));return {data:payload.data,requestId,response};
}
async function boundary(){
  await context.route('**/*',async route=>{
    const request=route.request(),url=new URL(request.url());
    if(url.origin!==journal.origin||url.searchParams.has('reveal')||url.pathname.includes('/schemas/plugins/')||['8001','8000'].includes(url.port)){
      try{stopProductionUi(journal,'production-browser-origin-or-reveal-forbidden',retain);}catch{}await route.abort('blockedbyclient');return;
    }
    if(['GET','HEAD','OPTIONS'].includes(request.method())){await route.continue();return;}
    try{beforeProductionUiPacket(journal,packetForProductionUi(request,await request.allHeaders()),await context.cookies(),retain);await route.continue();}catch(error){asyncError=error;await route.abort('blockedbyclient');}
  });
  context.on('response',response=>{
    if(!response.url().startsWith(journal.origin+'/api/v1/'))return;
    chain=chain.then(async()=>{
      const request=response.request();if(['GET','HEAD','OPTIONS'].includes(request.method()))return;
      const attempt=productionAttemptFor(journal,packetForProductionUi(request,await request.allHeaders()));
      if(attempt){attempt.status=response.status();attempt.requestId=response.headers()['x-request-id'];retain();}
      let payload;try{payload=await response.json();}catch(error){if(attempt?.category==='readonly-authorization-review'){attempt.state='cancelled-readonly-no-write';attempt.responseDeliveryProven=false;retain();return;}throw error;}
      if(attempt?.category==='readonly-authorization-review'&&payload.data?.permissionsVersion!==(journal.currentPermissionsVersion??journal.session.user.permissionsVersion)){
        const me=await protectedRead('/api/v1/auth/me');revalidateProductionAuthority(journal,me.data,me.requestId,payload.data.permissionsVersion);retain();
      }
      observeProductionUiAck(journal,attempt,{status:response.status(),data:payload.data,requestId:payload.meta?.requestId??response.headers()['x-request-id']},retain);saveReport();
    }).catch(error=>{asyncError=error;journal.privateAsyncFailure={name:error.name,message:error.message,stack:error.stack};const attempt=journal.attempts[journal.inFlight];if(attempt?.state==='prepared')attempt.state='response_unknown';try{stopProductionUi(journal,'production-response-not-proven',retain);}catch{}});
  });
  context.on('requestfailed',request=>{if(!['GET','HEAD','OPTIONS'].includes(request.method())){chain=chain.then(async()=>{const attempt=productionAttemptFor(journal,packetForProductionUi(request,await request.allHeaders()));if(attempt?.category==='readonly-authorization-review'){attempt.state='cancelled-readonly-no-write';attempt.responseDeliveryProven=false;retain();return;}if(attempt)attempt.state='response_unknown';asyncError=Error('PRODUCTION_TRANSPORT_UNKNOWN');try{stopProductionUi(journal,'production-transport-unknown',retain);}catch{}});}});
}
async function choose(label,text){const input=page.getByLabel(label,{exact:true}).and(page.locator('input[role="combobox"]'));await chooseUiOption(page,input,text,expect);}
async function scopePage(path){
  // Set scope on the overview before navigating to a URL that opens a modal
  // drawer. The drawer deliberately blocks clicks on the background selectors.
  await page.goto(journal.origin+'/');
  await expect(page.getByLabel('选择集群',{exact:true}).and(page.locator('input[role="combobox"]'))).toBeVisible();
  await choose('选择集群',journal.scopeLabels.clusterLabel);await choose('选择工作区',journal.scopeLabels.workspaceName);await settle();
  if(path!=='/')await page.goto(journal.origin+path);await settle();
}
async function stable(){await expect(page.locator('.ant-spin-spinning:visible')).toHaveCount(0);await settle();}
async function screenshot(name){await stable();await expect(page.locator('input[type="password"]:visible')).toHaveCount(0);await expect(page.locator('.ant-drawer-title').filter({hasText:/^(创建|编辑) /})).toHaveCount(0);const visibleText=await page.locator('body').innerText();if([...secrets].some(value=>value.length>=8&&visibleText.includes(value)))throw Error('PRODUCTION_VISIBLE_SECRET_SCREENSHOT_BLOCKED');await page.evaluate(()=>window.scrollTo(0,0));await expect.poll(()=>page.evaluate(()=>window.scrollY)).toBe(0);const path=`artifacts/production/ui-${name}.png`;if(existsSync(path))throw Error('PRODUCTION_SCREENSHOT_EXISTS_NO_OVERWRITE');await page.screenshot({path,fullPage:true,animations:'disabled'});screenshots.push({path,sha256:productionSha(readFileSync(path)),viewport:page.viewportSize(),actionIndex:journal.nextIndex});saveReport();}
function nameOf(entity){return entity.name||entity.username||entity.target||entity.id;}
async function rowFor(id){for(let count=0;count<12;count++){await expect.poll(()=>page.locator('tr[data-row-key]').count(),{timeout:20000}).toBeGreaterThan(0);await stable();const row=page.locator(`tr[data-row-key="${id}"]`);if(await row.count()===1)return row;const next=page.getByRole('button',{name:/^下一页(?:\s+right)?$/}).last();if(!await next.isEnabled())break;const before=await page.locator('tr[data-row-key]').evaluateAll(rows=>rows.map(row=>row.getAttribute('data-row-key')).join('|'));await next.click();await expect.poll(()=>page.locator('tr[data-row-key]').evaluateAll(rows=>rows.map(row=>row.getAttribute('data-row-key')).join('|'))).not.toBe(before);}throw Error('PRODUCTION_KNOWN_ID_NOT_IN_BOUNDED_CURSOR_PAGES');}
async function confirm(title,name,okText='确认执行'){
  const dialog=page.getByRole('dialog').filter({has:page.getByText(title,{exact:true})}),input=dialog.getByLabel('确认名称',{exact:true}),button=dialog.getByRole('button',{name:okText,exact:true});await expect(dialog).toHaveCount(1);await expect(button).toBeDisabled();await input.fill(name+'-wrong');await expect(button).toBeDisabled();await input.fill(name);await expect(button).toBeEnabled();await button.click();
}
async function waitMutation(){await expect.poll(async()=>{await settle();return journal.attempts[journal.inFlight]?.state;},{timeout:60000}).toBe('acknowledged');const attempt=journal.attempts[journal.inFlight],path=productionReceiptPath(journal,attempt);const {data,requestId}=await protectedRead(path);confirmProductionUiReceipt(journal,attempt,{method:'GET',url:journal.origin+path},data,requestId,retain);check('DOM write has exact original actor/scope/key terminal Native-ledger receipt',attempt.state==='succeeded',{action:attempt.action,key:attempt.key,requestId:attempt.requestId,receiptId:attempt.receiptId,receiptRequestId:attempt.receiptRequestId,bodySha256:attempt.bodySha256});return attempt;}
function assertSubset(actual,expected,path=[]){
  if(Array.isArray(expected)){
    if(path.join('.')==='tags'){expect(Array.isArray(actual)).toBe(true);expect(actual.filter(tag=>!/^workspace:|^kos-ws-/i.test(tag)).sort()).toEqual([...expected].sort());return;}
    expect(Array.isArray(actual)).toBe(true);expect(actual).toHaveLength(expected.length);for(const[index,value]of expected.entries())assertSubset(actual[index],value,[...path,index]);return;
  }
  if(expected&&typeof expected==='object'){for(const[key,value]of Object.entries(expected))assertSubset(actual?.[key],value,[...path,key]);return;}
  expect(actual).toEqual(expected);
}
async function readback(type,id,expected){
  const projection=productionNonSecretExpected(expected);let current;
  await expect.poll(async()=>{current=await protectedRead(q(`entities/${type}/${id}`));if(current.data?.entity?.id!==id)return false;try{assertSubset(current.data.entity,projection);return true;}catch{return false;}},{timeout:20000,intervals:[250,500,1000]}).toBe(true);
  const {data,requestId}=current;check('readback returns same original entity UUID and propagated configuration',data?.entity?.id===id);assertSubset(data.entity,projection);
  if(type==='plugins'&&Object.hasOwn(expected,'enabled'))check('plugin actual enabled state matches explicit isolated plan',data.entity.enabled===expected.enabled);return {entity:data.entity,requestId};
}
async function viewDetails(type,binding,shot){await scopePage(`/entities/${type}/${binding.id}`);const drawer=page.getByRole('dialog').filter({has:page.getByRole('tab',{name:'Configuration',exact:true})});await expect(drawer).toHaveCount(1);await expect(drawer.getByText(binding.id,{exact:true}).first()).toBeVisible();await screenshot(shot);await drawer.locator('.ant-drawer-close').click();}
function labelsForForeign(){return new Map(Object.values(journal.bindings).filter(row=>row?.entity&&row?.id).map(row=>[row.id,`${row.entity.name??row.entity.username??row.id} · ${row.id.slice(0,8)}`]));}
async function editEntity(type,action,desired,original,pluginName,pluginSweep=false){
  // Edit from the protected current detail DTO, never a stale create response
  // or a differently projected list row (Certificate.snis changes by relation).
  if(original)original=(await readback(type,original.id,{})).entity;
  const binding=original?{id:original.id,entity:original}:null;
  if(pluginSweep&&!original){await scopePage('/plugin-center');const search=page.getByLabel('搜索插件市场',{exact:true});await search.fill(pluginName);await page.getByRole('button',{name:`配置 ${pluginName}`,exact:true}).click();}
  else{await scopePage(`/entities/${type}${binding?'/'+binding.id:''}`);if(binding){const details=page.getByRole('dialog').filter({has:page.getByRole('tab',{name:'Configuration',exact:true})});await expect(details).toHaveCount(1);await details.getByRole('button',{name:/^(?:edit\s+)?编\s*辑$/}).click();}else await page.getByRole('button',{name:new RegExp(`^(?:plus\\s+)?创建 ${PRODUCTION_ENTITY_LABELS[type]}$`)}).click();}
  const title=original?`编辑 ${PRODUCTION_ENTITY_LABELS[type]} · ${nameOf(original)}`:`创建 ${PRODUCTION_ENTITY_LABELS[type]}`,editor=page.getByRole('dialog').filter({has:page.getByText(title,{exact:true})});await expect(editor).toHaveCount(1);
  const rootSchema=(await protectedRead(q(`schemas/${type}`))).data;let pluginSchema;
  if(type==='plugins'){
    if(!pluginSweep||original)await chooseUiOption(page,editor.getByLabel('name',{exact:true}).and(editor.locator('input[role="combobox"]')),pluginName,expect);
    const data=(await protectedRead(q(`plugin-center/schemas/${pluginName}`))).data;pluginSchema=data.form_schema;
    check('plugin actual schema binding constraints match disabled isolation plan',data.metadata?.constraints?.known===true&&(pluginName==='kubernetes-sidecar-injector'?data.metadata.constraints.service===false:data.metadata.constraints.service===true),{pluginName});
    await expect(editor.locator('.plugin-schema-help')).toContainText(pluginName);await expect(editor.getByTestId('schema-field-config')).toBeVisible();
  }
  const schema=productionEditorSchema(rootSchema,pluginSchema,type==='plugins'?PRODUCTION_PLUGIN_NAMES:undefined),trace=await fillSchemaUi(page,editor,schema,desired,expect,[],[],labelsForForeign());
  if(type==='plugins')await expect(editor.getByRole('switch',{name:'enabled',exact:true})).toHaveAttribute('aria-checked','false');
  domActions.push({action,entityType:type,pluginName:pluginName??null,formTitle:title,fields:trace});
  const body=productionExpectedBody(rootSchema,desired,original,pluginSchema);
  armProductionUi(journal,{action,method:original?'PATCH':'POST',path:`/api/v1/clusters/${journal.cid}/entities/${type}${original?'/'+original.id:''}`,body,entityType:type,entityId:original?.id,mutationAction:original?'update':'create',pluginName,pluginSweep},retain);
  await editor.getByRole('button',{name:'保存配置',exact:true}).click();const attempt=await waitMutation();await expect(editor).toHaveCount(0);
  const id=attempt.responseData.entity.id,read=await readback(type,id,desired);return {id,entity:read.entity,requestId:read.requestId,createRequestId:original?undefined:attempt.requestId};
}
async function archive(type,binding,action){await scopePage(`/entities/${type}`);const row=await rowFor(binding.id);await row.getByRole('button',{name:/删\s*除/}).click();const name=nameOf(binding.entity);armProductionUi(journal,{action,method:'DELETE',path:`/api/v1/clusters/${journal.cid}/entities/${type}/${binding.id}`,body:{confirmed:true,confirm_name:name},entityType:type,entityId:binding.id,mutationAction:'delete'},retain);await confirm('移入回收站',name);const attempt=await waitMutation();const entryId=attempt.responseData.entryId;
  await protectedRead(q(`entities/${type}/${binding.id}`),404);const preview=(await protectedRead(q(`recycle-bin/${entryId}`))).data;
  check('archive owns exact root and preserves classified graph references',preview.entry?.id===entryId&&preview.entry.original_id===binding.id&&preview.entry.root_type===type&&preview.entry.state==='deleted'&&Array.isArray(preview.nodes));
  binding.entryId=entryId;binding.archiveRequestId=attempt.requestId;retain();return preview;
}
async function restore(type,binding,action=`entity.${type}.restore`,pluginName){await scopePage(`/recycle-bin?clusterId=${journal.cid}&workspaceId=${journal.wid}`);const row=await rowFor(binding.entryId);await row.getByRole('button',{name:/恢\s*复/}).click();const name=nameOf(binding.entity);armProductionUi(journal,{action,method:'POST',path:`/api/v1/clusters/${journal.cid}/recycle-bin/${binding.entryId}/restore`,body:{confirmed:true,confirm_name:name},entityType:type,entityId:binding.id,entryId:binding.entryId,mutationAction:'restore'},retain);await confirm('恢复对象图',name,'确认恢复');const attempt=await waitMutation();binding.restoreRequestId=attempt.requestId;await readback(type,binding.id,{});const preview=(await protectedRead(q(`recycle-bin/${binding.entryId}`))).data;
  check('restored root preserves original ID and affected node results',preview.entry?.state==='restored'&&preview.nodes.filter(node=>node.affected===true).every(node=>node.restore_state==='restored'&&node.restored_id===node.original_id));await viewDetails(type,binding,pluginName?`plugin-${pluginName}-restored`:`entity-${type}-restored`);if(!pluginName)coverage.push({kind:'entity',type,id:binding.id,entryId:binding.entryId,createRequestId:binding.createRequestId,editRequestId:binding.editRequestId,archiveRequestId:binding.archiveRequestId,restoreRequestId:binding.restoreRequestId,uiLifecycle:true,nativeComparisonPending:true});retain();}
async function representativeBindings(){
  for(const level of ['route','consumer','global']){
    await runAction(`bindings.${level}.create`,async()=>{
    const references=level==='route'?{route:{id:journal.bindings.routes.id}}:level==='consumer'?{consumer:{id:journal.bindings.consumers.id}}:{};
    const desired={name:'rate-limiting',...references,enabled:false,config:{minute:2,policy:'local'},tags:[journal.tag,`${journal.tag}-binding-${level}`,`owner:${journal.actorId}`]};
    const binding=await editEntity('plugins',`bindings.${level}.create`,desired,undefined,'rate-limiting');journal.bindings[`binding:${level}`]=binding;retain();await viewDetails('plugins',binding,`binding-${level}-created-disabled`);
    });
  }
  for(const enabled of [true,false]){
    await runAction(enabled?'bindings.service.enable':'bindings.service.disable',async()=>{
    const binding=journal.bindings['plugin:rate-limiting'];await scopePage('/plugin-center');await page.getByRole('tab',{name:'插件实例',exact:true}).click();await choose('按插件名过滤','rate-limiting');await choose('按绑定层级过滤','Service');const row=await rowFor(binding.id);
    const isolationPath=q(`entities/services/${journal.bindings.services.id}`),isolation=await protectedRead(isolationPath);proveProductionIsolation(journal,{method:'GET',url:journal.origin+isolationPath},isolation.data,isolation.requestId,retain);
    armProductionUiToggle(journal,enabled,retain);domActions.push({action:enabled?'bindings.service.enable':'bindings.service.disable',entityType:'plugins',pluginName:'rate-limiting',control:`启停 rate-limiting ${binding.id}`,isolatedServiceId:journal.bindings.services.id});await row.getByRole('switch',{name:`启停 rate-limiting ${binding.id}`,exact:true}).click();await waitMutation();
    const actual=await readback('plugins',binding.id,{enabled,service:{id:journal.bindings.services.id}});binding.entity=actual.entity;retain();await viewDetails('plugins',binding,`binding-service-${enabled?'enabled':'disabled'}-unrouted`);
    });
  }
  for(const level of ['route','consumer','global']){
    await runAction(`bindings.${level}.archive`,async()=>{
    const binding=journal.bindings[`binding:${level}`];await archive('plugins',binding,`bindings.${level}.archive`);await scopePage(`/recycle-bin?clusterId=${journal.cid}&workspaceId=${journal.wid}`);const row=await rowFor(binding.entryId);await row.getByRole('button',{name:'rate-limiting',exact:true}).click();await expect(page.getByText(binding.id,{exact:true}).first()).toBeVisible();await screenshot(`binding-${level}-archived-graph`);
    coverage.push({kind:'representative-binding',level,id:binding.id,entryId:binding.entryId,createRequestId:binding.createRequestId,archiveRequestId:binding.archiveRequestId,disabledThroughout:true,nativeComparisonPending:true});
    });
  }
}
try{
  saveReport();const executablePath=process.env.CHROMIUM_EXECUTABLE_PATH||(existsSync('/usr/bin/chromium')?'/usr/bin/chromium':undefined);browser=await chromium.launch({headless:true,...(executablePath?{executablePath}:{})});context=await browser.newContext({baseURL:journal.origin,viewport:{width:1440,height:1050},serviceWorkers:'block'});await context.addCookies(productionCookies(journal.origin,journal.session.cookie));await boundary();
  const me=(await protectedRead('/api/v1/auth/me')).data;proveProductionActor(journal,me);retain();page=await context.newPage();await scopePage('/');
  const cluster=(await protectedRead(`/api/v1/clusters/${journal.cid}`)).data;
  check('actual fresh Kong OSS 1.5.1 direct cluster exposes exact 34 enabled plugin names',cluster.version==='1.5.1'&&cluster.execution_mode==='direct'&&Array.isArray(cluster.enabled_plugins)&&[...cluster.enabled_plugins].sort().join() === [...PRODUCTION_PLUGIN_NAMES].sort().join());
  await runAction('carrier.create',async()=>{journal.bindings.carrier=await editEntity('services','carrier.create',{name:`${journal.tag}-carrier`,protocol:'http',host:'198.51.100.1',port:9,tags:[journal.tag,`owner:${journal.actorId}`]});retain();});
  for(const type of PRODUCTION_ENTITY_TYPES)await runAction(`entity.${type}.create`,async()=>{const desired=productionEntityInput(type,{tag:journal.tag,actorId:journal.actorId,bindings:journal.bindings,pem:journal.pem});journal.bindings[type]=await editEntity(type,`entity.${type}.create`,desired,undefined,type==='plugins'?'rate-limiting':undefined);retain();await viewDetails(type,journal.bindings[type],`entity-${type}-created`);});
  for(const type of PRODUCTION_ENTITY_TYPES)await runAction(`entity.${type}.edit`,async()=>{const prior=journal.bindings[type];const desired={...productionEntityEdit(type,journal.tag),tags:[journal.tag,`${journal.tag}-edited`,`owner:${journal.actorId}`]};if(type==='plugins')desired.name=prior.entity.name;const edited=await editEntity(type,`entity.${type}.edit`,desired,prior.entity,type==='plugins'?prior.entity.name:undefined);journal.bindings[type]={...prior,...edited,createRequestId:prior.createRequestId,editRequestId:journal.attempts.at(-1).requestId};retain();await viewDetails(type,journal.bindings[type],`entity-${type}-edited`);});
  for(const type of [...PRODUCTION_ENTITY_TYPES].reverse())await runAction(`entity.${type}.archive`,async()=>{const binding=journal.bindings[type],preview=await archive(type,binding,`entity.${type}.archive`);await scopePage(`/recycle-bin?clusterId=${journal.cid}&workspaceId=${journal.wid}`);const row=await rowFor(binding.entryId);await row.getByRole('button',{name:nameOf(binding.entity),exact:true}).click();await expect(page.getByText(binding.id,{exact:true}).first()).toBeVisible();await screenshot(`entity-${type}-archived-graph`);check('graph object ownership metadata retained without secret material',{nodes:preview.nodes}.nodes.every(node=>typeof node.affected==='boolean'),{entityType:type,nodeCount:preview.nodes.length});});
  for(const type of PRODUCTION_ENTITY_TYPES)await runAction(`entity.${type}.restore`,()=>restore(type,journal.bindings[type]));
  const relations=(await protectedRead(q(`entities/services/${journal.bindings.services.id}`))).data;check('34-plugin isolation Service has no Routes before sweep',relations.relations?.routes?.items?.length===0&&relations.relations.routes.nextCursor==null);
  for(const name of PRODUCTION_PLUGIN_NAMES){const [initial,edit]=pluginConfigs[name],service=name==='kubernetes-sidecar-injector'?{}:{service:{id:journal.bindings.services.id}},desired={name,enabled:false,...service,config:initial,tags:[journal.tag,`owner:${journal.actorId}`]};
    await runAction(`plugin.${name}.create`,async()=>{const created=await editEntity('plugins',`plugin.${name}.create`,desired,undefined,name,true);journal.bindings[`plugin:${name}`]=created;retain();await viewDetails('plugins',created,`plugin-${name}-created`);});
    await runAction(`plugin.${name}.edit`,async()=>{const created=journal.bindings[`plugin:${name}`],changes={name,enabled:false,...service,config:edit,tags:[journal.tag,`${journal.tag}-edited`,`owner:${journal.actorId}`]},updated=await editEntity('plugins',`plugin.${name}.edit`,changes,created.entity,name,true);journal.bindings[`plugin:${name}`]={...created,...updated,createRequestId:created.createRequestId,editRequestId:journal.attempts.at(-1).requestId};retain();await viewDetails('plugins',updated,`plugin-${name}-edited`);});
    await runAction(`plugin.${name}.archive`,async()=>{const binding=journal.bindings[`plugin:${name}`];await archive('plugins',binding,`plugin.${name}.archive`);await scopePage(`/recycle-bin?clusterId=${journal.cid}&workspaceId=${journal.wid}`);const archivedRow=await rowFor(binding.entryId);await archivedRow.getByRole('button',{name:name,exact:true}).click();await expect(page.getByText(binding.id,{exact:true}).first()).toBeVisible();await screenshot(`plugin-${name}-archived-graph`);});
    await runAction(`plugin.${name}.restore`,async()=>{const binding=journal.bindings[`plugin:${name}`];await restore('plugins',binding,`plugin.${name}.restore`,name);coverage.push({kind:'plugin',name,id:binding.id,entryId:binding.entryId,createRequestId:binding.createRequestId,editRequestId:binding.editRequestId,archiveRequestId:binding.archiveRequestId,restoreRequestId:binding.restoreRequestId,disabled:true,binding:name==='kubernetes-sidecar-injector'?'global':`service:${journal.bindings.services.id}`,configEdit:name!=='prometheus',tagsEdit:true,uiLifecycle:true,nativeComparisonPending:true});saveReport();});}
  await representativeBindings();
  await runAction('cleanup.carrier.archive',async()=>{await page.setViewportSize({width:390,height:844});await scopePage('/plugin-center');await page.getByRole('tab',{name:'优先级与冲突',exact:true}).click();await expect(page.getByTestId('plugin-precedence-flow')).toBeVisible();await screenshot('plugin-precedence-mobile');await page.setViewportSize({width:1440,height:1050});await archive('services',journal.bindings.carrier,'cleanup.carrier.archive');check('carrier cleanup is a distinct confirmed recycle action',journal.attempts.at(-1).action==='cleanup.carrier.archive');});
  check('all 8 UI lifecycles, 34 disabled plugin form edits and exact 8 representative bindings have terminal receipts',journal.phase==='complete'&&coverage.filter(row=>row.kind==='entity').length===8&&coverage.filter(row=>row.kind==='plugin').length===34&&coverage.filter(row=>row.kind==='representative-binding').length===3&&journal.attempts.filter(row=>row.action.startsWith('bindings.')).length===8&&journal.attempts.length===178);
  report.allPassed=true;report.actualNativeReadbackInherited=false;report.pendingSecurityNativeComparison=true;report.pendingSecretScan=true;saveReport();
}catch(error){journal.privateFailure={name:error.name,message:error.message,stack:error.stack,phase};retain();report.allPassed=false;if(error.message!==PRODUCTION_UI_PAUSE_CODE){if(!checks.some(row=>!row.passed))checks.push({name:`harness stopped at ${phase}`,passed:false,code:'PRODUCTION_UI_STOP_NO_REPLAY'});if(journal.phase!=='stopped-without-replay')try{stopProductionUi(journal,'production-ui-stopped-no-replay',retain);}catch{}}saveReport();process.exitCode=1;}
finally{await browser?.close();retain();saveReport();}
