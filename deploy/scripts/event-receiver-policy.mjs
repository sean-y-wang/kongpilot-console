export function eventReceiverChecks(config){
 const checks=[],add=(name,value)=>checks.push({name,passed:!!value}),services=config.services??{},network=config.networks?.['delivery-test'];
 add('isolated .51 bridge network',network?.driver==='bridge'&&network.internal===true&&network.ipam?.config?.length===1&&network.ipam.config[0].subnet==='172.28.51.0/24');
 const members=Object.entries(services).filter(([,s])=>Object.hasOwn(s.networks??{},'delivery-test')).map(([name])=>name).sort();
 add('only API and two receivers join delivery network',JSON.stringify(members)===JSON.stringify(['console-api','event-mail','event-receiver']));
 for(const[name,kind,ip]of[['event-receiver','https','172.28.51.20'],['event-mail','smtp','172.28.51.30']]){
  const value=services[name]??{},mounts=value.volumes??[];
  add(name+' exact sole interface',JSON.stringify(Object.keys(value.networks??{}))==='["delivery-test"]'&&value.networks['delivery-test'].ipv4_address===ip);
  add(name+' no host ports or namespaces',!value.ports?.length&&!value.network_mode&&!value.pid&&!value.ipc&&!value.privileged&&!value.devices?.length&&!value.extra_hosts?.length);
  add(name+' nonroot readonly capability-free',value.user==='1000:1000'&&value.read_only===true&&JSON.stringify(value.cap_drop)==='["ALL"]'&&!value.cap_add?.length&&value.security_opt?.includes('no-new-privileges:true'));
  add(name+' fixed receiver kind',JSON.stringify(value.environment)===JSON.stringify({RECEIVER_KIND:kind}));
  add(name+' private materials and owned source readonly',mounts.length===2&&mounts.includes(`./deploy/private/event-delivery/${kind==='https'?'https':'smtp'}:/run/receiver:ro`)&&mounts.includes('./deploy/event-receivers:/opt/kongos-event-receiver:ro'));
  add(name+' bounded owned tmpfs',JSON.stringify(value.tmpfs)==='["/tmp:rw,noexec,nosuid,size=8m,uid=1000,gid=1000,mode=0700"]');
  add(name+' explicit test profile and fixed image',JSON.stringify(value.profiles)==='["notifications-test"]'&&value.image==='kongpilot/event-receivers:local');
 }
 const api=services['console-api']??{},env=api.environment??{};
 add('API fixed delivery address',api.networks?.['delivery-test']?.ipv4_address==='172.28.51.10');
 add('both receivers and API interface protected for native sinks',['event-receiver','event-mail','172.28.51.20','172.28.51.30','172.28.51.10'].every(host=>(env.PROTECTED_DESTINATION_HOSTS??'').split(',').includes(host)));
 add('fixed narrow provider authority',env.EVENT_DELIVERY_ALLOWED_HOSTS==='event-receiver:9087,event-mail:2465'&&env.EVENT_SMTP_HOST==='event-mail'&&env.EVENT_SMTP_PORT==='2465'&&env.EVENT_SMTP_MODE==='starttls'&&env.EVENT_SMTP_SERVERNAME==='event-mail');
 add('separate readonly TLS and SMTP materials',env.EVENT_DELIVERY_HTTPS_CA_FILE==='/run/event-delivery/ca.crt'&&env.EVENT_SMTP_CA_FILE==='/run/event-delivery/ca.crt'&&env.EVENT_SMTP_PASSWORD_FILE==='/run/event-delivery/smtp-password'&&(api.volumes??[]).includes('./deploy/private/event-delivery/api:/run/event-delivery:ro'));
 add('worker explicit activation',env.EVENT_DELIVERY_WORKER_ENABLED==='true');
 add('no database/admin nodes or existing receivers redirected',Object.keys(services).filter(name=>!['console-api','event-receiver','event-mail'].includes(name)).every(name=>!Object.hasOwn(services[name].networks??{},'delivery-test')));
 return checks;
}
