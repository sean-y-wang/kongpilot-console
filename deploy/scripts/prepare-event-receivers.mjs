import{execFileSync}from'node:child_process';
import{createHash,randomBytes}from'node:crypto';
import{chmodSync,chownSync,constants,existsSync,lstatSync,mkdirSync,readFileSync,realpathSync,unlinkSync,writeFileSync}from'node:fs';
import{dirname,resolve}from'node:path';
import{fileURLToPath}from'node:url';
const hash=value=>createHash('sha256').update(value).digest('hex');
function privateFile(path,bytes,uid,gid){writeFileSync(path,bytes,{flag:'wx',mode:0o400});chownSync(path,uid,gid);chmodSync(path,0o400);}
export function prepareEventReceivers(directory,{uid=1000,gid=uid,openssl=execFileSync}={}){
 const target=resolve(directory),parent=dirname(target);let created=false;
 if(!Number.isInteger(uid)||uid<1||!Number.isInteger(gid)||gid<1)throw new Error('EVENT_RECEIVER_GENERATOR_INVALID');
 try{
  const info=lstatSync(parent);if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o022)!==0||realpathSync(parent)!==parent||existsSync(target))throw new Error();
  mkdirSync(target,{mode:0o700});created=true;
  for(const name of ['api','https','smtp']){mkdirSync(resolve(target,name),{mode:0o700});chownSync(resolve(target,name),uid,gid);}
  const caKey=resolve(target,'ca.key'),ca=resolve(target,'ca.crt');
  openssl('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',caKey,'-out',ca,'-days','7','-subj','/CN=KongPilot Isolated Event Acceptance CA','-addext','basicConstraints=critical,CA:TRUE'],{stdio:'ignore',timeout:10000});
  for(const [name,host]of[['https','event-receiver'],['smtp','event-mail']]){
   const dir=resolve(target,name),key=resolve(dir,'tls.key'),request=resolve(dir,'tls.csr'),cert=resolve(dir,'tls.crt'),extension=resolve(dir,'extensions');
   writeFileSync(extension,`subjectAltName=DNS:${host}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n`,{flag:'wx',mode:0o600});
   openssl('openssl',['req','-new','-newkey','rsa:2048','-nodes','-keyout',key,'-out',request,'-subj',`/CN=${host}`],{stdio:'ignore',timeout:10000});
   openssl('openssl',['x509','-req','-in',request,'-CA',ca,'-CAkey',caKey,'-set_serial',name==='https'?'1001':'1002','-out',cert,'-days','7','-extfile',extension],{stdio:'ignore',timeout:10000});
   unlinkSync(request);unlinkSync(extension);for(const path of[key,cert]){chmodSync(path,0o400);chownSync(path,uid,gid);}
  }
  const bearer=randomBytes(32).toString('base64url'),basicPassword=randomBytes(32).toString('base64url'),smtpPassword=randomBytes(32).toString('base64url');
  privateFile(resolve(target,'https/config.json'),JSON.stringify({credentialDigests:[hash('Bearer '+bearer),hash('Basic '+Buffer.from('kongos:'+basicPassword).toString('base64'))]}),uid,gid);
  privateFile(resolve(target,'smtp/config.json'),JSON.stringify({username:'kongos',passwordDigest:hash(smtpPassword)}),uid,gid);
  privateFile(resolve(target,'api/ca.crt'),readFileSync(ca),uid,gid);privateFile(resolve(target,'api/smtp-password'),smtpPassword,uid,gid);
  // Explicit test-only private input for the acceptance harness/scanner. It is
  // neither a product HTTP export nor a credential printed to stdout.
  writeFileSync(resolve(target,'test-only-materials.json'),JSON.stringify({testOnly:true,httpBearer:bearer,httpBasic:{username:'kongos',password:basicPassword},smtp:{username:'kongos',password:smtpPassword},secrets:[bearer,basicPassword,smtpPassword]}),{flag:'wx',mode:0o600});
  unlinkSync(caKey);chmodSync(ca,0o400);
  return{created:true,directory:target,uid,testOnly:true,credentialsPrinted:false};
 }catch{throw new Error(created?'EVENT_RECEIVER_GENERATION_FAILED':'EVENT_RECEIVER_DIRECTORY_UNSAFE');}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const parent=resolve('deploy/private');if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const result=prepareEventReceivers(resolve(parent,'event-delivery'));process.stdout.write(JSON.stringify(result)+'\n');}
 catch(error){process.stderr.write(JSON.stringify({code:error instanceof Error?error.message:'EVENT_RECEIVER_GENERATION_FAILED'})+'\n');process.exitCode=1;}
}
