import{createServer}from'node:net';
import{chmodSync}from'node:fs';
export function createReceiverControl({socketPath,records,faults}){
 const server=createServer(socket=>{let bytes=0,buffer='';socket.setTimeout(2000,()=>socket.destroy());
  socket.on('error',()=>undefined);socket.on('data',chunk=>{bytes+=chunk.length;if(bytes>2048){socket.destroy();return;}buffer+=chunk.toString('utf8');
   const newline=buffer.indexOf('\n');if(newline<0)return;if(newline!==buffer.length-1){socket.destroy();return;}
   try{const input=JSON.parse(buffer);if(!input||typeof input!=='object'||Array.isArray(input))throw new Error();
    if(input.action==='stats'&&Object.keys(input).join(',')==='action')socket.end(JSON.stringify({ok:true,...records.snapshot()})+'\n');
    else if(input.action==='fault'&&Object.keys(input).sort().join(',')==='action,fault'){faults.set(input.fault);socket.end('{"ok":true}\n');}
    else throw new Error();
   }catch{socket.end('{"ok":false,"code":"RECEIVER_CONTROL_INVALID"}\n');}
  });
 });server.listen(socketPath,()=>chmodSync(socketPath,0o600));return server;
}
