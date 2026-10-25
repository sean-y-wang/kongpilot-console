import{createServer}from'node:https';
import{bodyIdentity,createFaultState,createSafeRecords,equalDigest}from'./safe-records.mjs';
export function createEventHttpReceiver({key,cert,credentialDigests=[]}){
 const records=createSafeRecords(),faults=createFaultState();
 const server=createServer({key,cert,minVersion:'TLSv1.2',maxHeaderSize:8192},(request,response)=>{
  request.on('error',()=>undefined);response.on('error',()=>undefined);
  if(request.url==='/health'&&request.method==='GET'){response.end('{"ready":true}');return;}
  if(request.url!=='/hook'||request.method!=='POST'){response.writeHead(404);response.end();return;}
  const authorization=request.headers.authorization;
  if(authorization!==undefined&&(!credentialDigests.some(expected=>equalDigest(authorization,expected))||request.rawHeaders.filter((_,i)=>i%2===0&&request.rawHeaders[i].toLowerCase()==='authorization').length!==1)){records.reject();response.writeHead(401);response.end();return;}
  if(authorization)records.auth();
  let size=0;const chunks=[];request.on('data',chunk=>{size+=chunk.length;if(size>8192){response.writeHead(413);response.end();request.destroy();}else chunks.push(chunk);});
  request.once('end',()=>{if(size>8192)return;const bytes=Buffer.concat(chunks),identity=bodyIdentity(bytes),key=request.headers['idempotency-key'];
   if(!identity||typeof key!=='string'||!/^[a-zA-Z0-9_.:-]{8,128}$/.test(key)){records.reject();response.writeHead(400);response.end();return;}
   records.record(bytes,identity,key);const fault=faults.take();
   setTimeout(()=>{if(fault.dropAfterBody){response.destroy();return;}response.writeHead(fault.status,{'content-type':'application/json',...(fault.status===429?{'retry-after':'1'}:{})});
    const payload=JSON.parse(bytes.toString('utf8'));response.end(payload.msg_type==='text'?'{"code":0}':typeof payload.text==='string'?'ok':'{"accepted":true}');
   },fault.delayMs).unref();
  });
 });server.requestTimeout=5000;server.headersTimeout=5000;server.maxConnections=20;
 return{server,records,faults};
}
