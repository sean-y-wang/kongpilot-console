import {describe,it,expect} from 'vitest';
import {createServer} from 'node:http';
import {randomBytes,randomUUID} from 'node:crypto';
import {stringify} from 'yaml';
import {runDeck,DECK_BINARY_SHA256} from '../../deploy/deck-runner/runner.mjs';

// The verified binary can contact only this new synthetic loopback fixture.
// No deployment env, private runtime receipt, Kong, database, or real BFF.
describe('current fixed decK SDK Service PUT body source contract',()=>{
 it('records full Service replacement fields when only retries changes',async()=>{
  const id=randomUUID(),sid=randomUUID(),token=randomBytes(32).toString('base64url');
  let current={id,name:'synthetic-service',host:'synthetic.example.test',port:80,protocol:'http',retries:0,connect_timeout:60000,read_timeout:60000,write_timeout:60000};
  const writes:Array<{method:string,path:string,body:Record<string,unknown>}>=[],reads:string[]=[];
  const server=createServer(async(req,res)=>{
   if(req.headers.authorization!==`KongOS-Deck ${token}`){res.writeHead(403);res.end('{}');return;}
   const path=new URL(req.url!,'http://127.0.0.1').pathname,prefix=`/api/v1/deck/${sid}`;
   res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
   if(!path.startsWith(prefix)){res.writeHead(404);res.end('{}');return;}
   const native=path.slice(prefix.length)||'/';
   if(req.method==='GET'){
    reads.push(native);
    if(native==='/'){res.end(JSON.stringify({version:'1.5.1'}));return;}
    if(native==='/mtls-auths'){res.writeHead(404);res.end(JSON.stringify({message:'DECK_CAPABILITY_UNAVAILABLE'}));return;}
    if(native===`/services/${id}`){res.end(JSON.stringify(current));return;}
    if(/^\/[a-z_-]+$/.test(native)){res.end(JSON.stringify({data:native==='/services'?[current]:[],next:null}));return;}
    res.writeHead(404);res.end('{}');return;
   }
   if(req.method==='PUT'&&native===`/services/${id}`){
    const chunks:Buffer[]=[];for await(const chunk of req)chunks.push(Buffer.from(chunk));
    const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));writes.push({method:req.method,path:native,body});current={...body,id};res.end(JSON.stringify(current));return;
   }
   res.writeHead(405);res.end('{}');
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${(server.address() as {port:number}).port}`;
  try{
   const result=await runDeck({command:'sync',sessionId:sid,tokenSecret:token,stateYaml:stringify({_format_version:'1.1',services:[{...current,retries:2}]})},{binaryPath:'/tmp/kongos-deck124-cli/deck',origin,allowLocalTestBff:true,timeoutMs:15000,environment:{PATH:process.env.PATH}});
   try{
    expect(result.safe).toMatchObject({exitCode:0,toolVersion:'1.2.4',toolCommit:'8e68931',toolBinarySha256:DECK_BINARY_SHA256,possibleUnknown:false,consoleJobSuccessProved:false});
    expect(writes).toHaveLength(1);expect(writes[0].method).toBe('PUT');expect(writes[0].path).toBe(`/services/${id}`);
    expect(Object.keys(writes[0].body).sort()).toEqual(['connect_timeout','host','id','name','port','protocol','read_timeout','retries','write_timeout']);
    expect(writes[0].body.retries).toBe(2);expect(writes[0].body.host).toBe('synthetic.example.test');
    expect(Object.keys(writes[0].body)).not.toEqual(['retries']);expect(reads).toContain('/services');
   }finally{result.dispose();}
  }finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
 },20000);
});
