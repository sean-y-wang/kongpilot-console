/** Kong OSS 1.5.1 plugins_iterator.lua should_process_plugin selects the ngx
 * subsystem. It does not select a plugin by an individual request protocol. */
const http=new Set(['http','https','grpc','grpcs']);
const stream=new Set(['tcp','tls']);
export function kong15PluginSubsystem(protocol:string):'http'|'stream'|null{return http.has(protocol)?'http':stream.has(protocol)?'stream':null;}
export function kong15ProtocolMatches(pluginProtocols:unknown,requestProtocol:string):boolean{
 const requested=kong15PluginSubsystem(requestProtocol);
 return !!requested&&Array.isArray(pluginProtocols)&&pluginProtocols.some(protocol=>typeof protocol==='string'&&kong15PluginSubsystem(protocol)===requested);
}
/** Ordinary proxy requests skip second-hop service-mesh-only configurations.
 * Missing run_on uses the actual 1.5 default first in prospective fixtures. */
export function kong15ExternalPluginEligible(plugin:{enabled?:unknown;run_on?:unknown}):boolean{
 return plugin.enabled!==false&&(plugin.run_on===undefined||plugin.run_on==='first'||plugin.run_on==='all');
}
