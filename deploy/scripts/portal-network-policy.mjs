import {isIP} from 'node:net';
const exact=(value,expected)=>Array.isArray(value)&&value.length===expected.length&&JSON.stringify([...value].sort())===JSON.stringify([...expected].sort());
const port=(value)=>Array.isArray(value)&&value.length===1&&value[0].hostIp==='127.0.0.1'&&String(value[0].hostPort)==='8082'&&Number(value[0].containerPort)===8080;
/** Pure facts only: neither Docker calls nor environment/credential reads. */
export function portalTopologyChecks(facts){
  return[
    {name:'Portal network mode does not bypass bridge isolation',passed:typeof facts?.networkMode==='string'&&!['host','none'].includes(facts.networkMode)&&!facts.networkMode.startsWith('container:')},
    {name:'Portal joins exactly private backend and dedicated entry networks',passed:exact(facts?.portalNetworks,['portal-edge','portal-entry'])},
    {name:'private backend is internal bridge with exactly API and Portal',passed:facts?.edge?.internal===true&&facts?.edge?.driver==='bridge'&&exact(facts?.edge?.members,['console-api','portal-web'])},
    {name:'external entry is bridge with Portal as sole member',passed:facts?.entry?.internal===false&&facts?.entry?.driver==='bridge'&&exact(facts?.entry?.members,['portal-web'])},
    {name:'API joins private backend and never external entry',passed:Array.isArray(facts?.apiNetworks)&&facts.apiNetworks.includes('portal-edge')&&!facts.apiNetworks.includes('portal-entry')},
    {name:'both Portal interfaces have distinct fixed IPv4s',passed:isIP(facts?.edgeAddress||'')===4&&isIP(facts?.entryAddress||'')===4&&facts.edgeAddress!==facts.entryAddress},
    {name:'Portal publishes localhost8082 to container8080 only',passed:port(facts?.published)},
    {name:'actual effective localhost publication exists',passed:port(facts?.runtime?facts?.effectivePublished:facts?.published)},
    {name:'ordinary destinations protect hostname and both Portal interfaces',passed:Array.isArray(facts?.protectedHosts)&&['portal-web',facts?.edgeAddress,facts?.entryAddress].every(host=>facts.protectedHosts.includes(host))},
  ];
}
