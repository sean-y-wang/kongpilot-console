import{connect}from'node:net';
const socket=connect({host:'127.0.0.1',port:process.env.RECEIVER_KIND==='https'?9087:2465});
socket.setTimeout(2000,()=>process.exit(1));socket.once('error',()=>process.exit(1));socket.once('connect',()=>{socket.end();process.exit(0);});
