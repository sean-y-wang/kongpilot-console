import net from 'node:net';

export const FIXED_TLS_PORTS=Object.freeze([{kind:'fresh-console',listen:28443,target:18443},{kind:'fresh-portal',listen:29443,target:19443},{kind:'restore-console',listen:31443,target:21443},{kind:'restore-portal',listen:32443,target:22443}].map(Object.freeze));
/** TCP only: no TLS termination, HTTP parser, header/log content or caller URL. */
export function startFixedTlsPassthrough({netImplementation=net,maxConnections=128}={}){
 if(maxConnections!==128)throw new Error('RAM_TLS_RELAY_CONFIGURATION_INVALID');
 const servers=[],sockets=new Set();let stopped=false;
 const ready=Promise.all(FIXED_TLS_PORTS.map(binding=>new Promise((resolve,reject)=>{
  const server=netImplementation.createServer(client=>{
   if(stopped||sockets.size>=maxConnections){client.destroy();return;}
   sockets.add(client);let remote,closed=false;
   const close=()=>{if(closed)return;closed=true;clearTimeout(deadline);sockets.delete(client);client.destroy();remote?.destroy();};
   const deadline=setTimeout(close,315000);deadline.unref();
   client.setTimeout(315000,close);client.once('error',close);client.once('close',close);
   remote=netImplementation.createConnection({host:'127.0.0.1',port:binding.target});
   remote.setTimeout(5000,close);remote.once('error',close);remote.once('close',close);
   remote.once('connect',()=>{remote.setTimeout(315000,close);client.pipe(remote);remote.pipe(client);});
  });
  servers.push(server);server.once('error',()=>reject(new Error('RAM_TLS_RELAY_LISTEN_FAILED')));server.listen({host:'0.0.0.0',port:binding.listen,exclusive:true},()=>resolve());
 })));
 const close=()=>{stopped=true;for(const socket of sockets)socket.destroy();for(const server of servers)server.close();};
 return {ready:ready.catch(error=>{close();throw error;}),close,bindings:FIXED_TLS_PORTS};
}
