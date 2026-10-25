import{createServer}from'node:net';
import{createSecureContext,TLSSocket}from'node:tls';
import{bodyIdentity,createFaultState,createSafeRecords,equalDigest,UUID}from'./safe-records.mjs';
export function createEventSmtpReceiver({key,cert,username,passwordDigest}){
 const records=createSafeRecords(),faults=createFaultState(),context=createSecureContext({key,cert,minVersion:'TLSv1.2'});
 const server=createServer(plain=>{
  let socket=plain,secure=false,authenticated=false,buffer='',data=false,mail=false,recipients=0;const chunks=[];
  const error=()=>socket.destroy();plain.on('error',()=>undefined);plain.setTimeout(20000,error);
  const write=value=>socket.write(value+'\r\n');
  const lines=bytes=>{
   buffer+=bytes.toString('utf8');if(Buffer.byteLength(buffer)+chunks.reduce((n,s)=>n+Buffer.byteLength(s),0)>8192){records.reject();socket.destroy();return;}
   for(;;){const newline=buffer.indexOf('\r\n');if(newline<0)return;const line=buffer.slice(0,newline);buffer=buffer.slice(newline+2);
    if(data){if(line==='.'){
      data=false;const message=chunks.join('\r\n'),split=message.indexOf('\r\n\r\n'),id=/^Message-ID: <([a-f0-9-]{36})@kongos\.local>\r?$/m.exec(message),bytes=Buffer.from(message.slice(split+4)),identity=split>=0?bodyIdentity(bytes):null;
      if(!id||!UUID.test(id[1])||!identity||identity.deliveryId!==id[1]){records.reject();write('554 Invalid message');continue;}
      records.record(bytes,identity,id[1]);const fault=faults.take();setTimeout(()=>{if(fault.dropAfterBody)socket.destroy();else write(fault.status===200?'250 Accepted':fault.status===429?'451 Temporary rejection':'550 Rejected');},fault.delayMs).unref();chunks.length=0;
     }else chunks.push(line.startsWith('..')?line.slice(1):line);continue;}
    if(/^EHLO [a-zA-Z0-9.-]+$/.test(line)){write(secure?'250-kongos.local\r\n250 AUTH PLAIN':faults.peek().starttlsDisabled?'250 kongos.local':'250-kongos.local\r\n250 STARTTLS');continue;}
    if(line==='STARTTLS'&&!secure&&!faults.peek().starttlsDisabled){write('220 Begin TLS');plain.removeListener('data',lines);buffer='';const upgraded=new TLSSocket(plain,{isServer:true,secureContext:context});socket=upgraded;secure=true;upgraded.on('error',()=>undefined);upgraded.setTimeout(20000,error);upgraded.on('data',lines);return;}
    if(!secure){records.reject();write('530 STARTTLS required');continue;}
    if(line.startsWith('AUTH PLAIN ')){
     let valid=false;try{const value=Buffer.from(line.slice(11),'base64').toString('utf8'),parts=value.split('\0');valid=parts.length===3&&parts[0]===''&&parts[1]===username&&equalDigest(parts[2],passwordDigest);}catch{}
     if(!valid){records.reject();write('535 Authentication rejected');continue;}authenticated=true;records.auth();write('235 Authenticated');continue;
    }
    if(!authenticated){records.reject();write('530 Authentication required');continue;}
    if(/^MAIL FROM:<[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9.-]+>$/.test(line)){mail=true;recipients=0;write('250 Sender accepted');continue;}
    if(mail&&/^RCPT TO:<[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9.-]+>$/.test(line)&&recipients<20){recipients++;write('250 Recipient accepted');continue;}
    if(line==='DATA'&&mail&&recipients){data=true;chunks.length=0;write('354 End with dot');continue;}
    if(line==='QUIT'){write('221 Closing');socket.end();return;}records.reject();write('500 Command denied');
   }
  };plain.on('data',lines);write('220 kongos.local ESMTP');
 });server.maxConnections=20;return{server,records,faults};
}
