import{Module}from'@nestjs/common';
import{closeSync,constants,fstatSync,openSync,readFileSync}from'node:fs';
import{DeliveryPolicyService}from'./delivery-policy.service';
import{DELIVERY_POLICY_OPTIONS,DeliveryPolicyOptions,DeliverySmtpConfig}from'./delivery.types';
import{HttpDeliveryTransport}from'./http-delivery.transport';
import{SmtpDeliveryTransport}from'./smtp-delivery.transport';
import{DELIVERY_WORKER_OPTIONS,DeliveryWorkerService}from'./delivery-worker.service';
import{EventCoreModule}from'../event-core/event-core.module';

export function boundedPrivateText(path:string|undefined,secret=false):string|undefined{
 if(!path)return undefined;let fd:number|undefined;
 try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const info=fstatSync(fd);
  if(!info.isFile()||info.nlink!==1||info.size<1||info.size>65536||(info.mode&0o022)!==0||secret&&((info.mode&0o077)!==0||info.uid!==process.getuid?.()))throw new Error();
  const bytes=readFileSync(fd);try{if(bytes.length!==info.size||bytes.length>65536)throw new Error();return bytes.toString('utf8');}finally{bytes.fill(0);}
 }catch{throw new Error('EVENT_DELIVERY_PRIVATE_CONFIG_INVALID');}finally{if(fd!==undefined)closeSync(fd);}
}
export function deliveryPolicyEnvironment():DeliveryPolicyOptions{
 const allowedAuthorities=(process.env.EVENT_DELIVERY_ALLOWED_HOSTS??'').split(',').filter(Boolean).map(v=>v.trim().toLowerCase());
 if(allowedAuthorities.length>100||allowedAuthorities.some(v=>!/^([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\]):[0-9]{1,5}$/.test(v)||Number(v.slice(v.lastIndexOf(':')+1))<1||Number(v.slice(v.lastIndexOf(':')+1))>65535))throw new Error('EVENT_DELIVERY_ALLOWLIST_INVALID');
 let smtp:DeliverySmtpConfig|undefined;
 if(process.env.EVENT_SMTP_HOST){
  const mode=process.env.EVENT_SMTP_MODE??'starttls',port=Number(process.env.EVENT_SMTP_PORT??587),from=process.env.EVENT_SMTP_FROM??'';
  if(!['starttls','implicit-tls'].includes(mode)||!Number.isInteger(port)||port<1||port>65535||!from||/[\r\n\u0000]/.test(from)||!!process.env.EVENT_SMTP_USERNAME!==!!process.env.EVENT_SMTP_PASSWORD_FILE)throw new Error('EVENT_SMTP_CONFIG_INVALID');
  smtp={host:process.env.EVENT_SMTP_HOST.toLowerCase(),port,mode:mode as DeliverySmtpConfig['mode'],servername:process.env.EVENT_SMTP_SERVERNAME||process.env.EVENT_SMTP_HOST,
   from,username:process.env.EVENT_SMTP_USERNAME,password:boundedPrivateText(process.env.EVENT_SMTP_PASSWORD_FILE,true)?.trimEnd(),ca:boundedPrivateText(process.env.EVENT_SMTP_CA_FILE)};
  if(smtp.username&&(!smtp.password||/[\r\n\u0000]/.test(smtp.username+smtp.password)||smtp.username.length>4096||smtp.password.length>4096))throw new Error('EVENT_SMTP_CONFIG_INVALID');
 }
 let testReceivers:DeliveryPolicyOptions['testReceivers'];
 if(process.env.EVENT_DELIVERY_TEST_RECEIVERS_JSON){
  if(process.env.NODE_ENV!=='development')throw new Error('EVENT_TEST_RECEIVER_ENV_FORBIDDEN');
  if(process.env.EVENT_DELIVERY_TEST_RECEIVERS_JSON.length>4096)throw new Error('EVENT_TEST_RECEIVER_CONFIG_INVALID');
  let value:Record<string,unknown>;try{value=JSON.parse(process.env.EVENT_DELIVERY_TEST_RECEIVERS_JSON);}catch{throw new Error('EVENT_TEST_RECEIVER_CONFIG_INVALID');}
  const expected:Record<string,string>={'event-receiver:9087':'172.28.51.20','event-mail:2465':'172.28.51.30'};
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length>2||Object.entries(value).some(([key,ips])=>!Object.hasOwn(expected,key)||!Array.isArray(ips)||ips.length!==1||ips[0]!==expected[key]))throw new Error('EVENT_TEST_RECEIVER_CONFIG_INVALID');
  testReceivers=value as DeliveryPolicyOptions['testReceivers'];
 }
 return{allowedAuthorities,protectedHosts:(process.env.PROTECTED_DESTINATION_HOSTS??'').split(',').filter(Boolean).map(v=>v.trim().toLowerCase()),smtp,
  httpsCa:boundedPrivateText(process.env.EVENT_DELIVERY_HTTPS_CA_FILE),testReceivers};
}
@Module({imports:[EventCoreModule],providers:[{provide:DELIVERY_POLICY_OPTIONS,useFactory:deliveryPolicyEnvironment},DeliveryPolicyService,HttpDeliveryTransport,SmtpDeliveryTransport,
 {provide:DELIVERY_WORKER_OPTIONS,useFactory:()=>({enabled:process.env.EVENT_DELIVERY_WORKER_ENABLED==='true'})},DeliveryWorkerService],exports:[DeliveryPolicyService,DeliveryWorkerService]})
export class EventDeliveryModule{}
