import {createServer} from 'node:http';
createServer((request,response)=>{
  if(request.url==='/redirect'){response.writeHead(302,{location:'http://kong:8001/'});response.end();return;}
  response.writeHead(200,{'content-type':'application/json'});
  response.end(JSON.stringify({method:request.method,path:request.url,host:request.headers.host,healthy:true,upstream:'kongos-test',consumerId:request.headers['x-consumer-id']??null}));
}).listen(8080,'0.0.0.0');
