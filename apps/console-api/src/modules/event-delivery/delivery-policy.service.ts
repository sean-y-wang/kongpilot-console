import{BadRequestException,ForbiddenException,Inject,Injectable,ServiceUnavailableException}from'@nestjs/common';
import{lookup}from'node:dns/promises';
import{isIP}from'node:net';
import{networkInterfaces}from'node:os';
import{DbService}from'../../infrastructure/db.service';
import{DELIVERY_POLICY_OPTIONS,DeliveryChannelInput,DeliveryDestination,DeliveryPolicyOptions,DeliveryProviderDescriptor,DeliveryProviderType,DeliverySafeSummary,ValidatedDeliveryChannel}from'./delivery.types';

const bad=()=>new BadRequestException({code:'EVENT_CHANNEL_CONFIG_INVALID',message:'通知渠道配置无效'});
const denied=()=>new ForbiddenException({code:'EVENT_DELIVERY_DESTINATION_DENIED',message:'通知目标未登记或属于受保护地址'});
const unavailable=()=>new ServiceUnavailableException({code:'EVENT_DELIVERY_POLICY_UNAVAILABLE',message:'无法安全核验通知目标'});
const own=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const controls=/[\u0000-\u0020\u007f]/;
export function deliverySystemAddress(value:string):boolean{
 const host=value.replace(/^\[|\]$/g,'').toLowerCase();
 return !isIP(host)||host==='::'||host==='::1'||/^0\.|^127\.|^169\.254\.|^22[4-9]\.|^23\d\./.test(host)||host==='255.255.255.255'
  ||host.startsWith('::ffff:')||/^fe[89ab]/.test(host)||host.startsWith('ff');
}
function hostname(value:string):string{
 const host=value.replace(/^\[|\]$/g,'').toLowerCase();
 if(!host||controls.test(host)||host.endsWith('.')||host==='localhost'||host.endsWith('.localhost')||!isIP(host)&&!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(host))throw bad();
 return host;
}
function authority(host:string,port:number){return`${isIP(host)===6?'['+host+']':host}:${port}`;}
function email(value:unknown):value is string{return typeof value==='string'&&value.length<=254&&!controls.test(value)&&/^[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(value);}

@Injectable()
export class DeliveryPolicyService{
 constructor(private readonly db:DbService,@Inject(DELIVERY_POLICY_OPTIONS)private readonly options:DeliveryPolicyOptions){}
 describeProviders():DeliveryProviderDescriptor[]{
  return(['webhook','email','slack','feishu'] as const).map(type=>({type,label:{webhook:'Webhook',email:'邮件',slack:'Slack',feishu:'飞书'}[type],
   available:type==='email'?!!this.options.smtp:this.options.allowedAuthorities.length>0,
   ...(type==='email'&&!this.options.smtp?{reasonCode:'SMTP_NOT_CONFIGURED'}:type!=='email'&&!this.options.allowedAuthorities.length?{reasonCode:'DELIVERY_ALLOWLIST_EMPTY'}:{}),
   authTypes:type==='webhook'?['none','bearer','basic']:type==='feishu'?['none','feishu-signature']:['none']}));
 }
 safeSummary(channel:Pick<ValidatedDeliveryChannel,'type'|'endpoint'|'auth'>):DeliverySafeSummary{
  if('recipients'in channel.endpoint)return{destinationHost:null,maskedDestination:`${channel.endpoint.recipients.length} 位收件人`,recipientCount:channel.endpoint.recipients.length,authConfigured:false};
  const url=this.parseHttpUrl(channel.endpoint.url);return{destinationHost:url.hostname,maskedDestination:`https://${url.host}/•••`,authConfigured:channel.auth.type!=='none'};
 }
 private parseHttpUrl(value:unknown):URL{
  if(typeof value!=='string'||value.length>4096||controls.test(value)||/%(?:2f|5c|00|0[ad]|20|40|3a)/i.test(value)||value.includes('\\'))throw bad();
  let url:URL;try{url=new URL(value);}catch{throw bad();}
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||!url.hostname||url.toString()!==value)throw bad();
  hostname(url.hostname);return url;
 }
 async validateChannelConfig(input:DeliveryChannelInput):Promise<ValidatedDeliveryChannel>{
  if(!own(input)||Object.keys(input).some(k=>!['type','endpoint','auth','options'].includes(k))||!['webhook','email','slack','feishu'].includes(input.type))throw bad();
  if(input.options!==undefined&&(!own(input.options)||Object.keys(input.options).length))throw bad();
  const auth=input.auth??{type:'none'};
  if(!own(auth)||!['none','bearer','basic','feishu-signature'].includes(auth.type as string))throw bad();
  const keys={none:['type'],bearer:['type','token'],basic:['type','username','password'],'feishu-signature':['type','secret']}[auth.type];
  if(Object.keys(auth).sort().join(',')!==[...keys].sort().join(','))throw bad();
  for(const key of keys.filter(k=>k!=='type')){const value=(auth as unknown as Record<string,unknown>)[key];if(typeof value!=='string'||!value||value.length>4096||/[\r\n\u0000]/.test(value))throw bad();}
  if(auth.type==='basic'&&auth.username.includes(':')||auth.type==='bearer'&&!/^[\x21-\x7e]+$/.test(auth.token))throw bad();
  let endpoint:ValidatedDeliveryChannel['endpoint'];
  if(input.type==='email'){
   if(!this.options.smtp)throw new ServiceUnavailableException({code:'SMTP_NOT_CONFIGURED',message:'SMTP 未配置'});
   if(auth.type!=='none'||!own(input.endpoint)||Object.keys(input.endpoint).join(',')!=='recipients'||!Array.isArray(input.endpoint.recipients)
    ||input.endpoint.recipients.length<1||input.endpoint.recipients.length>20||!input.endpoint.recipients.every(email)||new Set(input.endpoint.recipients).size!==input.endpoint.recipients.length)throw bad();
   endpoint={recipients:Object.freeze([...input.endpoint.recipients])};await this.resolveDestination(this.options.smtp.host,this.options.smtp.port);
  }else{
   if(input.type==='slack'&&auth.type!=='none'||input.type==='feishu'&&!['none','feishu-signature'].includes(auth.type)||input.type==='webhook'&&auth.type==='feishu-signature')throw bad();
   const url=this.parseHttpUrl(input.endpoint);await this.resolveDestination(url.hostname,Number(url.port||443));endpoint={url:url.toString()};
  }
  const channel={type:input.type,endpoint:Object.freeze(endpoint),auth:Object.freeze({...auth}),optionsSafe:Object.freeze({})};
  return Object.freeze({...channel,safeSummary:Object.freeze(this.safeSummary(channel))});
 }
 httpUrl(value:string){return this.parseHttpUrl(value);}
 smtpConfig(){if(!this.options.smtp)throw new ServiceUnavailableException({code:'SMTP_NOT_CONFIGURED',message:'SMTP 未配置'});return this.options.smtp;}
 httpsCa(){return this.options.httpsCa;}
 async resolveDestination(rawHost:string,port:number):Promise<DeliveryDestination>{
  const host=hostname(rawHost);if(!Number.isInteger(port)||port<1||port>65535)throw bad();const target=authority(host,port);
  if(!this.options.allowedAuthorities.includes(target))throw denied();
  const dbRows=await this.db.query<{admin_url:string}>('SELECT admin_url FROM clusters WHERE deleted_at IS NULL LIMIT 257');
  const sources=await this.db.query<{base_url:string}>('SELECT base_url FROM data_sources WHERE deleted_at IS NULL LIMIT 257');
  if(dbRows.length>256||sources.length>256)throw unavailable();
  const receiverIPs=this.options.testReceivers?.[target];
  const hardOrigins=new Set(['console-api','console-web','portal-web','console-db','kong-db','kong-secondary-db','kong-portal-db','redis','prometheus','loki','telemetry-collector','metrics-bff','metrics-collector']);
  const critical=new Set<string>();
  for(const row of [...dbRows.map(r=>r.admin_url),...sources.map(r=>r.base_url)]){try{const name=new URL(row).hostname.replace(/^\[|\]$/g,'').toLowerCase();hardOrigins.add(name);critical.add(name);}catch{throw unavailable();}}
  // Only the explicitly pinned local receiver identity may omit its own
  // protected interfaces. Registered Admin/data sources remain hard origins.
  const hard=new Set([...hardOrigins,...this.options.protectedHosts.filter(value=>!receiverIPs||value!==host&&!receiverIPs.includes(value))]);
  if(hardOrigins.has(host))throw denied();
  if(hard.has(host)&&!receiverIPs)throw denied();
  const resolver=this.options.lookupAll??((name:string)=>lookup(name,{all:true}));
  const resolveAll=async(name:string)=>{
   if(isIP(name))return[{address:name,family:isIP(name)}];let timer:NodeJS.Timeout|undefined;
   try{return await Promise.race([resolver(name),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(unavailable()),1000);})]);}finally{if(timer)clearTimeout(timer);}
  };
  const addresses=await resolveAll(host).catch(()=>{throw unavailable();});
  if(!addresses.length||addresses.length>32||addresses.some(row=>deliverySystemAddress(row.address)||![4,6].includes(row.family)))throw denied();
  if(receiverIPs&&addresses.some(row=>!receiverIPs.includes(row.address)))throw denied();
  const hardHosts=[...hard].filter(name=>!(name===host&&receiverIPs)).map(name=>name.replace(/^\[|\]$/g,''));
  const resolved=await Promise.all(hardHosts.map(async name=>{const rows=await resolveAll(name).catch(()=>{if(critical.has(name))throw unavailable();return[];});
   if(critical.has(name)&&(!rows.length||rows.length>32||rows.some(row=>!isIP(row.address))))throw unavailable();return rows;}));
  // Every BFF interface is protected even when Docker DNS returns just one of
  // its Admin/frontend/telemetry interfaces. This is server-owned OS data.
  const selfIPs=this.options.ownAddresses??Object.values(networkInterfaces()).flatMap(rows=>rows?.map(row=>row.address)??[]);
  const protectedIPs=new Set([...selfIPs,...resolved.flat().map(row=>row.address)]);
  if(addresses.some(row=>protectedIPs.has(row.address)))throw denied();
  return Object.freeze({hostname:host,port,addresses:Object.freeze(addresses.map(row=>Object.freeze({...row}))),pinned:Object.freeze({...addresses[0]})});
 }
}
