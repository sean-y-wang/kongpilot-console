import type { OpenAPIObject } from '@nestjs/swagger';

/** Runtime Kong schemas remain authoritative; generic bodies are deliberately extensible. */
export function describeConsoleApi(document:OpenAPIObject):OpenAPIObject {
 document.components??={};document.components.schemas??={};
 document.components.schemas.ErrorEnvelope={type:'object',required:['error','meta'],properties:{error:{type:'object',required:['code','message'],properties:{code:{type:'string'},message:{type:'string'},fields:{type:'object',additionalProperties:true},operationId:{type:'string',format:'uuid'},entryId:{type:'string',format:'uuid'},state:{type:'string'}}},meta:{type:'object',properties:{requestId:{type:'string',format:'uuid'}}}}};
 document.components.schemas.Confirmation={type:'object',required:['confirmed','confirm_name'],properties:{confirmed:{type:'boolean',enum:[true]},confirm_name:{type:'string',description:'输入待删除、恢复或清理对象的公开名称；以详情返回值为准'}}};
 document.components.schemas.KongEntityInput={type:'object',additionalProperties:true,description:'先读取 clusters/{clusterId}/schemas/{entityType}；插件 config 使用 plugin-schemas/{name}。仅接受 Kong 当前 schema 字段。'};
 document.components.schemas.PortalInput={type:'object',additionalProperties:true,description:'门户元数据请求。开发者接口必须包含 clusterId、workspaceId；字段白名单由该接口验证，不接受任意 Kong 配置、控制台角色或原生执行标志。'};
 document.components.schemas.VitalsSetup={type:'object',additionalProperties:false,required:['sourceId','mode','confirmed','confirm_name'],properties:{sourceId:{type:'string',format:'uuid'},mode:{type:'string',enum:['native_prometheus','collector']},confirmed:{type:'boolean',enum:[true]},confirm_name:{type:'string',description:'当前集群的公开名称。设置全局插件会影响整个集群；审批集群在工作流启用前拒绝执行。'}}};
 document.components.securitySchemes??={};
 document.components.securitySchemes.portalCookie={type:'apiKey',in:'cookie',name:'kongos_portal_access',description:'独立开发者门户会话；控制台 Cookie、Bearer 和用户权限不能替代此会话。'};
 document.components.schemas.WorkflowDecision={type:'object',additionalProperties:false,required:['revision','planHash','confirmed','confirm_name'],properties:{revision:{type:'integer',minimum:1},planHash:{type:'string',pattern:'^[a-f0-9]{64}$'},confirmed:{type:'boolean',enum:[true]},confirm_name:{type:'string',description:'当前工作流 kind；使用详情中的值'},reason:{type:'string',maxLength:2048},execute:{type:'boolean',description:'批准后由当前真实会话执行；执行仍独立校验写权限。'}}};
 document.components.schemas.IssueMetadataRecovery={type:'object',additionalProperties:false,required:['revision','planHash','executionId','confirmed','confirm_name'],properties:{revision:{type:'integer',minimum:1},planHash:{type:'string',pattern:'^[a-f0-9]{64}$'},executionId:{type:'string',format:'uuid',description:'原执行回执 ID；不得新建或替换执行。'},confirmed:{type:'boolean',enum:[true]},confirm_name:{type:'string',enum:['portal-credential-issue']}}};
 document.components.schemas.EventMetadataInput={type:'object',additionalProperties:true,description:'事件渠道/订阅使用固定字段、当前 revision 和明确二次确认；地址与认证只在写入时接收并加密，不在详情、审计、回执中返回。渠道配置测试和重放在审批集群中经过工作流。'};
 document.components.schemas.NotificationRevision={type:'object',additionalProperties:false,required:['revision'],properties:{revision:{type:'integer',minimum:1}}};
 document.components.schemas.AuditExportInput={type:'object',additionalProperties:true,description:'当前账号自己的有界只读导出任务。format只允许ndjson/csv；scope、workspaceId与完整筛选绑定原幂等键，下载重新校验当前audit.read，不接受目标URL、文件路径或任意账号。'};
 document.components.schemas.RejectedIssueAbandonment={...document.components.schemas.IssueMetadataRecovery,description:'关闭已经明确失败且尚未产生原生对象的首次发放预留身份；不修改原失败执行、已封存计划或密钥密文。'};
 for(const [path,item] of Object.entries(document.paths))for(const method of ['get','post','patch','put','delete'] as const){
  const operation=item[method];if(!operation)continue;
  const issueRecovery=method==='post'&&/\/workflows\/[^/]+\/reconcile-metadata$/.test(path);
  const issueAbandonment=method==='post'&&/\/workflows\/[^/]+\/abandon-rejected-issue$/.test(path);
  if(issueRecovery){
   operation.description='仅适用于原生 Consumer、ACL、Key 三个步骤已经成功、最后门户激活元数据仍未知的首次发放。需要原执行者的当前会话、当前权限和原执行幂等键；只提交门户元数据，不重发原生请求。相同键及相同内容只核验原成功回执。';
   operation.parameters??=[];
   if(!operation.parameters.some(parameter=>'name'in parameter&&parameter.name==='workspaceId'))operation.parameters.push({in:'query',name:'workspaceId',required:true,schema:{type:'string',format:'uuid'}});
  }
  if(issueAbandonment){
   operation.description='仅适用于首次 Consumer 创建明确校验失败、其他步骤尚未执行且原物理端点中分配的 Consumer、ACL、Key 均不存在的首次发放。需要原执行者的当前控制台会话、当前权限及原执行幂等键。只关闭预留身份并返回持久证明；原执行仍为 failed，不重发原生请求。结果未知时按原执行键读取回执，核验关闭证明后才可提交新的申请。';
   operation.parameters??=[];
   if(!operation.parameters.some(parameter=>'name'in parameter&&parameter.name==='workspaceId'))operation.parameters.push({in:'query',name:'workspaceId',required:true,schema:{type:'string',format:'uuid'}});
  }
  if(/\/vitals\/(capabilities|overview|entities)$/.test(path)&&method==='get'){
   operation.parameters??=[];
   const definitions:Record<string,any>={workspaceId:{type:'string',format:'uuid'},scope:{type:'string',enum:['workspace','cluster'],default:'workspace'},sourceId:{type:'string',format:'uuid'},serviceId:{type:'string',format:'uuid'},routeId:{type:'string',format:'uuid'},start:{type:'string',format:'date-time'},end:{type:'string',format:'date-time'},step:{type:'integer',minimum:15},type:{type:'string',enum:['services','routes','consumers']},size:{type:'integer',minimum:1,maximum:100,default:20},cursor:{type:'string'},search:{type:'string',maxLength:100}};
   const names=path.endsWith('/entities')?['workspaceId','scope','type','size','cursor','search']:path.endsWith('/overview')?['workspaceId','scope','sourceId','serviceId','routeId','start','end','step']:['workspaceId','scope','sourceId'];
   for(const name of names)if(!operation.parameters.some(parameter=>'name' in parameter&&parameter.name===name))operation.parameters.push({in:'query',name,required:name==='type',schema:definitions[name]});
   operation.description='监控只接受结构化查询。范围由服务器当前权限、原生实体归属与指标归属区间共同限定；不接收 PromQL、LogQL 或数据源地址。缺失采样返回 null。';
  }
  if(method==='get'&&/\/clusters\/[^/]+\/portal\/(?:(?:developers|applications)(?:\/[^/]+(?:\/(?:grants|requests))?)?|requests)$/.test(path)){
   operation.parameters??=[];
   const directory=/\/portal\/(developers|applications)$/.test(path),grants=path.endsWith('/grants'),requests=path.endsWith('/requests'),paged=directory||grants||requests;
   const definitions:Record<string,any>={workspaceId:{type:'string',format:'uuid'},size:{type:'integer',minimum:1,maximum:100,default:20},cursor:{type:'string',description:'绑定原账号、工作区、权限版本和筛选的签名游标。'},search:{type:'string',maxLength:128},status:{type:'string',enum:['pending','active','disabled','rejected','deleted']},state:{type:'string',enum:grants?['pending','active','partial','rotating','revoking','revoked','uncertain','disabled']:requests?['draft','pending','approved','executing','succeeded','partial','failed','uncertain','rejected','cancelled','expired']:['active','disabled','archived']}};
   const names=['workspaceId',...(paged?['size','cursor']:[]),...(directory?['search',path.endsWith('/developers')?'status':'state']:[]),...(grants||requests?['state']:[])];
   for(const name of names){
    const existing=operation.parameters.find(parameter=>'name'in parameter&&parameter.in==='query'&&parameter.name===name);
    if(existing&&'name'in existing){existing.required=name==='workspaceId';existing.schema=definitions[name];}
    else operation.parameters.push({in:'query',name,required:name==='workspaceId',schema:definitions[name]});
   }
   operation.description='控制台元数据只读查询；必须显式提供 workspaceId。根详情与关系列表分别检查当前完整模块授权，历史停用或归档记录仍可读取；不返回凭证、密文或原生配置。应用关系能力仅表示当前账号可否读取对应分页。';
  }
  if(method==='get'&&/\/portal\/publications$/.test(path)&&!path.includes('/clusters/')){
   operation.parameters??=[];
   const definitions:Record<string,any>={size:{type:'integer',minimum:1,maximum:100,default:20},cursor:{type:'string'},search:{type:'string',maxLength:128},category:{type:'string',maxLength:128}};
   for(const[name,schema]of Object.entries(definitions))if(!operation.parameters.some(parameter=>'name'in parameter&&parameter.in==='query'&&parameter.name===name))operation.parameters.push({in:'query',name,required:false,schema});
   operation.description='分类和搜索以成功发布的加密证明为准；扫描最多 500 候选，预算结束时返回 scanIncomplete、searchedRows 和后续 cursor，不把未完成的空页当作完整无匹配。';
  }
  const portalRoute=/\/portal(?:\/|$)/.test(path)&&!path.includes('/clusters/');
  const publicRoute=/\/auth\/(login|csrf|refresh)$|\/health\/(live|ready)$/.test(path)
   ||portalRoute&&(/\/portal\/(?:tenants|publications|catalog|pages)(?:\/|$)/.test(path)||path.endsWith('/auth/register'));
  operation.security=publicRoute?[]:portalRoute?[{portalCookie:[]}]:[{cookie:[]}];
  if(portalRoute){
   operation.description=`${operation.description??''} 门户身份、来源和租户由服务端独立验证；不会建立控制台原生执行上下文。`;
   if(method==='get'&&!/\/portal\/tenants(?:\/|$)/.test(path)){
    operation.parameters??=[];
    for(const name of ['clusterId','workspaceId'])if(!operation.parameters.some(parameter=>'name'in parameter&&parameter.name===name))
     operation.parameters.push({in:'query',name,required:true,schema:{type:'string',format:'uuid'}});
   }
  }
  for(const [code,description] of Object.entries({'400':'输入字段校验失败','401':'登录会话失效','403':'作用域或操作权限不足','404':'对象不存在','409':'配置已变更、需要确认或审批','429':'调用速率超过限制','503':'服务不可用或远程变更结果待核验'}))operation.responses[code]??={description,content:{'application/json':{schema:{$ref:'#/components/schemas/ErrorEnvelope'}}}};
  const m7Event=/\/clusters\/[^/]+\/events(?:\/|$)/.test(path),m7Notification=/\/notifications(?:\/|$)/.test(path),auditExport=/\/audit(?:\/global)?\/exports$/.test(path);
  if(method==='get'&&(/\/audit(?:\/global)?(?:\/|$)/.test(path)||m7Event||m7Notification)){
   operation.description=(operation.description??'')+' 读取和分页使用当前完整授权；签名游标、原事件或下载任务不代替授权。仅返回脱敏结果，列表total为null。';
  }
  if(['post','patch','put','delete'].includes(method)){
   operation.parameters??=[];
   if(portalRoute)operation.parameters.push({in:'header',name:'X-Portal-CSRF',required:true,description:'通过门户 auth/csrf 恢复当前会话校验令牌；写请求同时要求登记的精确门户 Origin。',schema:{type:'string'}});
   else if(!publicRoute)operation.parameters.push({in:'header',name:'X-CSRF-Token',required:false,description:'Cookie 登录的写请求必填；通过 GET auth/me 获取。Bearer 调用免 CSRF。',schema:{type:'string'}});
   const portalDurableWrite=portalRoute&&!/\/auth\/(?:register|login|refresh|logout)$|\/reveal$/.test(path);
   operation.parameters.push({in:'header',name:'X-Idempotency-Key',required:portalDurableWrite||m7Event||m7Notification||auditExport||/\/clusters\/[^/]+\/(?:portal|workflows)(?:\/|$)/.test(path),description:issueRecovery||issueAbandonment?'必须提供原执行的幂等键；不能使用新的恢复键或原申请键。':portalRoute?'需要回执的门户变更使用原操作人、原租户及原键；结果未知时查询 portal/operations/by-key/{key}，禁止自动重发。':'同一变更必须保持原键和内容；结果未知时查询所属门户、工作流或 mutations 回执，禁止自动重发。',schema:{type:'string',minLength:8,maxLength:128}});
   if(!operation.requestBody){
    const schema=auditExport?{$ref:'#/components/schemas/AuditExportInput'}:m7Event?{$ref:'#/components/schemas/EventMetadataInput'}:m7Notification&&/\/(read|dismiss)$/.test(path)?{$ref:'#/components/schemas/NotificationRevision'}:issueAbandonment?{$ref:'#/components/schemas/RejectedIssueAbandonment'}:issueRecovery?{$ref:'#/components/schemas/IssueMetadataRecovery'}:/\/workflows\/[^/]+\/(approve|reject|execute)$/.test(path)?{$ref:'#/components/schemas/WorkflowDecision'}:path.endsWith('/login')?{type:'object' as const,required:[...(portalRoute?['clusterId','workspaceId']:[]),'username','password'],properties:{...(portalRoute?{clusterId:{type:'string' as const,format:'uuid'},workspaceId:{type:'string' as const,format:'uuid'}}:{}),username:{type:'string' as const},password:{type:'string' as const,format:'password'}}}:path.endsWith('/vitals/setup')?{$ref:'#/components/schemas/VitalsSetup'}:/\/portal(?:\/|$)/.test(path)?{$ref:'#/components/schemas/PortalInput'}:method==='delete'||/\/(restore|purge)$/.test(path)?{$ref:'#/components/schemas/Confirmation'}:{$ref:'#/components/schemas/KongEntityInput'};
    operation.requestBody={required:true,content:{'application/json':{schema}}};
   }
  }
 }
 return document;
}
