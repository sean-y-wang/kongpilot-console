import{describe,it,expect}from'vitest';
import{mkdtempSync,readFileSync,rmSync,chmodSync,existsSync,statSync,symlinkSync}from'node:fs';
import{createHash}from'node:crypto';
import{tmpdir}from'node:os';
import{join}from'node:path';
import{createRequire}from'node:module';
import{prepareEventReceivers}from'../../deploy/scripts/prepare-event-receivers.mjs';
import{eventReceiverChecks}from'../../deploy/scripts/event-receiver-policy.mjs';
import{stagePlan}from'../../deploy/scripts/stage-plan.mjs';
const require=createRequire(new URL('../../apps/console-api/package.json',import.meta.url)),{parse}=require('yaml');
const source=()=>parse(readFileSync('deploy/compose.notifications-test.yml','utf8'));
describe('M7 synthetic receiver deployment policy',()=>{
 it('validates the actual source overlay using pure Compose facts',()=>{expect(eventReceiverChecks(source()).filter((row:any)=>!row.passed)).toEqual([]);});
 it('adds isolated delivery startup without reenrolling or rotating metrics and without restarting their services',()=>{const steps=stagePlan({stage:'M7',compose:['compose'],multicluster:true,observability:true,portal:true,notificationsTest:true});expect(steps.map((s:any)=>s[0])).toContain('isolated-delivery-materials');expect(steps.map((s:any)=>s[0])).toContain('start-isolated-delivery-receivers');const text=JSON.stringify(steps);expect(text).not.toContain('enroll-metrics');expect(text).not.toContain('rotate-metrics');expect(steps.find((s:any)=>s[0]==='restart')?.[2]).toEqual(['compose','restart','console-web','portal-web']);});
 it.each(['host-port','admin-network','foreign-member','root','writeable-material','capability','host-pid','wrong-ip','cleartext-smtp','unprotected-interface'])('rejects %s deployment widening',kind=>{
  const config=source(),receiver=config.services['event-receiver'];
  if(kind==='host-port')receiver.ports=['9087:9087'];if(kind==='admin-network')receiver.networks['kong-admin']={};if(kind==='foreign-member')config.services.kong={networks:{'delivery-test':{}}};
  if(kind==='root')receiver.user='0:0';if(kind==='writeable-material')receiver.volumes[0]=receiver.volumes[0].slice(0,-3);if(kind==='capability')receiver.cap_add=['NET_ADMIN'];if(kind==='host-pid')receiver.pid='host';
  if(kind==='wrong-ip')receiver.networks['delivery-test'].ipv4_address='172.28.51.99';if(kind==='cleartext-smtp')config.services['console-api'].environment.EVENT_SMTP_MODE='plain';if(kind==='unprotected-interface')config.services['console-api'].environment.PROTECTED_DESTINATION_HOSTS=config.services['console-api'].environment.PROTECTED_DESTINATION_HOSTS.replace(',172.28.51.30','');
  expect(eventReceiverChecks(config).some((row:any)=>!row.passed)).toBe(true);
 });
 it('generates distinct synthetic credentials and SAN-limited TLS materials without overwriting',()=>{
  const parent=mkdtempSync(join(tmpdir(),'kongos-m7-material-test-')),target=join(parent,'materials');
  const uid=process.getuid()||1000,gid=process.getuid()===0?1000:process.getgid();
  try{const result=prepareEventReceivers(target,{uid,gid});expect(result.credentialsPrinted).toBe(false);const secrets=JSON.parse(readFileSync(join(target,'test-only-materials.json'),'utf8'));expect(new Set(secrets.secrets).size).toBe(3);
   for(const path of['api/ca.crt','api/smtp-password','https/tls.key','https/tls.crt','https/config.json','smtp/tls.key','smtp/config.json'])expect(statSync(join(target,path)).mode&0o777).toBe(0o400);
   expect(existsSync(join(target,'ca.key'))).toBe(false);expect(statSync(join(target,'test-only-materials.json')).mode&0o777).toBe(0o600);
   const sha=createHash('sha256').update(readFileSync(join(target,'api/smtp-password'))).digest('hex');expect(()=>prepareEventReceivers(target)).toThrow('EVENT_RECEIVER_DIRECTORY_UNSAFE');expect(createHash('sha256').update(readFileSync(join(target,'api/smtp-password'))).digest('hex')).toBe(sha);
  }finally{rmSync(parent,{recursive:true,force:true});}
 });
 it.each([{uid:0},{gid:0},{uid:-1},{gid:1.5}])('refuses invalid ownership before generating material %j',ownership=>{const parent=mkdtempSync(join(tmpdir(),'kongos-m7-owner-test-'));try{expect(()=>prepareEventReceivers(join(parent,'materials'),ownership)).toThrow('EVENT_RECEIVER_GENERATOR_INVALID');expect(existsSync(join(parent,'materials'))).toBe(false);}finally{rmSync(parent,{recursive:true,force:true});}});
 it('rejects an unsafe writable or symlink parent before any key is generated',()=>{const parent=mkdtempSync(join(tmpdir(),'kongos-m7-parent-test-'));try{chmodSync(parent,0o770);expect(()=>prepareEventReceivers(join(parent,'materials'))).toThrow('EVENT_RECEIVER_DIRECTORY_UNSAFE');chmodSync(parent,0o700);const link=parent+'-link';symlinkSync(parent,link);try{expect(()=>prepareEventReceivers(join(link,'materials'))).toThrow('EVENT_RECEIVER_DIRECTORY_UNSAFE');}finally{rmSync(link);}}finally{rmSync(parent,{recursive:true,force:true});}});
});
