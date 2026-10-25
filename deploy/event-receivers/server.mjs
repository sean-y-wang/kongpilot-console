import{readFileSync}from'node:fs';
import{createEventHttpReceiver}from'./http.mjs';
import{createEventSmtpReceiver}from'./smtp.mjs';
import{createReceiverControl}from'./control.mjs';
const kind=process.env.RECEIVER_KIND,materials='/run/receiver';
try{
 const key=readFileSync(materials+'/tls.key'),cert=readFileSync(materials+'/tls.crt'),config=JSON.parse(readFileSync(materials+'/config.json','utf8'));
 const receiver=kind==='https'?createEventHttpReceiver({key,cert,credentialDigests:config.credentialDigests}):kind==='smtp'?createEventSmtpReceiver({key,cert,username:config.username,passwordDigest:config.passwordDigest}):null;
 if(!receiver)throw new Error();const control=createReceiverControl({socketPath:'/tmp/receiver-control.sock',records:receiver.records,faults:receiver.faults});
 receiver.server.listen(kind==='https'?9087:2465,'0.0.0.0');
 const close=()=>{control.close();receiver.server.close();setTimeout(()=>process.exit(0),500).unref();};process.once('SIGTERM',close);process.once('SIGINT',close);
}catch{process.stderr.write('{"code":"EVENT_RECEIVER_STARTUP_FAILED"}\n');process.exit(1);}
