import { createHmac, randomUUID } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { entity, scope, sha256 } from './m8-harness.mjs';
import { nativeCreate } from './m8-fixtures.mjs';

export const CREDENTIAL_KINDS = Object.freeze(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']);
export const CREDENTIAL_SCHEMA_NAMES = Object.freeze(['keyauth_credentials', 'basicauth_credentials', 'jwt_secrets', 'oauth2_credentials', 'hmacauth_credentials', 'acls']);
const route = (area, path) => scope(area.cid, area.wid, path);
export async function nativeRead(h, actor, area, type, id, reveal = false) {
  return entity(h.data(await h.request(actor, scope(area.cid, area.wid, `entities/${type}/${id}`, reveal ? { reveal: 'true' } : {}))));
}
/** Trust is selected before recording an outgoing packet, from the complete
 * original successful native-create tuple, never merely a matching UUID. */
export function resolveM8TlsTrust(state, area) {
  const f=state.nativeFixture,actor=state.sessions?.admin;
  const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
  const matches=(p,path,id)=>p.method==='POST'&&p.path===`/api/v1/clusters/${area.cid}/${path}`
    &&p.query===`?workspaceId=${area.wid}`&&p.state==='response_observed'&&p.status===201&&p.clusterId===area.cid&&p.workspaceId===area.wid
    &&p.actorId===actor?.user?.id&&p.sessionId===actor?.sid&&p.responseData?.entity?.id===id
    &&uuid(p.key)&&uuid(p.requestId)&&p.body&&p.bodySha256===sha256(JSON.stringify(p.body))
    &&typeof p.headers?.Cookie==='string'&&p.headers.Cookie.length>0&&p.headers?.['X-Idempotency-Key']===p.key;
  if(!f||f.area.cid!==area.cid||f.area.wid!==area.wid||area.cid!==state.scopes.direct.cid
    ||!uuid(actor?.user?.id)||!uuid(actor?.sid)||!uuid(f.certificate.id)||!uuid(f.sni.id)
    ||f.sni.certificate?.id!==f.certificate.id||f.sni.name!==`${state.testTag}.invalid`)throw Error('M8_TLS_EXACT_FIXTURE_CERTIFICATE_REQUIRED');
  const certificates=state.requests.filter(p=>matches(p,'entities/certificates',f.certificate.id));
  const snis=state.requests.filter(p=>matches(p,'entities/snis',f.sni.id));
  if(certificates.length!==1||snis.length!==1)throw Error('M8_TLS_EXACT_ORIGINAL_CREATE_REQUIRED');
  const original=certificates[0],sni=snis[0],certificate=original.body.cert;
  if(typeof certificate!=='string'||!certificate.startsWith('-----BEGIN CERTIFICATE-----')
    ||original.responseData.entity.cert!==certificate||f.certificate.cert!==certificate
    ||sni.body.name!==f.sni.name||sni.body.certificate?.id!==f.certificate.id
    ||sni.responseData.entity.certificate?.id!==f.certificate.id)throw Error('M8_TLS_ORIGINAL_TRUST_BODY_MISMATCH');
  return{certificate,servername:f.sni.name,publicCaSha256:sha256(certificate),certificateId:f.certificate.id,sniId:f.sni.id,
    originalCertificateRequestId:original.requestId,originalCertificateBodySha256:original.bodySha256,originalSniRequestId:sni.requestId};
}
/** Direct proxy is restricted to published localhost proxy ports, never Admin. */
export async function proxyRequest(h, area, path, { method = 'GET', headers = {}, body, expected, consumerId, tls = false } = {}) {
  if (!['GET', 'POST'].includes(method) || !path.startsWith(`/m8/${h.state.testTag}/`) || /[?#\\]/.test(path)) throw Error('M8_PROXY_FIXTURE_PATH_REQUIRED');
  if (method === 'POST') h.assertWritable();
  const port = tls && area.cid === h.state.scopes.direct.cid ? 8443 : !tls && area.cid === h.state.scopes.direct.cid ? 8000 : !tls && area.cid === h.state.scopes.approval.cid ? 9000 : null;
  if (!port) throw Error('M8_PROXY_CANONICAL_CLUSTER_REQUIRED');
  const trust=tls?resolveM8TlsTrust(h.state,area):undefined;
  const frozenHeaders = Object.freeze({ ...headers }), serialized = body === undefined ? undefined : JSON.stringify(body);
  h.remember(body); for (const [name, value] of Object.entries(frozenHeaders)) if (/^(authorization|apikey)$/i.test(name) && typeof value === 'string' && value.length > 8) h.state.secrets.push(value);
  const intent = { key: randomUUID(), cid: area.cid, wid: area.wid, method, path, port, headers: frozenHeaders,
    body: serialized === undefined ? null : JSON.parse(serialized), bodySha256: sha256(serialized ?? 'null'), tls,
    ...(trust?Object.fromEntries(Object.entries(trust).filter(([key])=>key!=='certificate')):{}),state: 'prepared', at: new Date().toISOString() };
  h.state.proxyChecks.push(intent); h.save();
  let response, bytes;
  try {
    if (tls) {
      const received=await new Promise((resolve,reject)=>{
        const req=httpsRequest({hostname:'127.0.0.1',port,method,path,servername:trust.servername,ca:trust.certificate,rejectUnauthorized:true,headers:frozenHeaders,signal:AbortSignal.timeout(15000)},res=>{
          const chunks=[],authorized=res.socket?.authorized===true;let count=0;res.on('data',chunk=>{count+=chunk.length;if(count>2*1024*1024){res.destroy();reject(Error('M8_PROXY_RESPONSE_LIMIT'));}else chunks.push(chunk);});
          res.once('error',reject);res.once('end',()=>resolve({status:res.statusCode,bytes:Buffer.concat(chunks),authorized}));
        });req.once('error',reject);req.end(serialized);
      });
      if(received.authorized!==true)throw Error('M8_TLS_CERTIFICATE_NOT_AUTHORIZED');response={status:received.status};bytes=received.bytes;intent.tlsAuthorized=true;
    } else {response = await fetch(`http://127.0.0.1:${port}${path}`, { method, redirect: 'manual', signal: AbortSignal.timeout(15000), headers: frozenHeaders, ...(serialized === undefined ? {} : { body: serialized }) }); bytes = Buffer.from(await response.arrayBuffer());}
  }
  catch { intent.state = 'response_unknown'; h.save({ phase: 'stopped-proxy-unknown' }); throw Error('M8_PROXY_RESPONSE_UNKNOWN_ORIGINAL_RETAINED'); }
  let payload = null; try { payload = JSON.parse(bytes.toString()); } catch { /* no raw diagnostic */ }
  h.remember(payload, true); Object.assign(intent, { state: 'response_observed', status: response.status, responseSha256: sha256(bytes), responseData: payload }); h.save();
  if (expected !== undefined) h.check(response.status === expected, 'real proxy response has expected status', { cid: area.cid, path, status: response.status });
  if (consumerId) h.check(payload?.upstream === 'kongos-test' && payload.consumerId === consumerId, 'real upstream identifies the restored authenticated Consumer', { consumerId });
  return { status: response.status, payload };
}
export async function waitProxy(h, area, path, options) {
  // GETs can be observed repeatedly during normal Kong DB propagation. OAuth
  // token POST is never polled/replayed and is always a separate durable intent.
  if (options.method === 'POST') return proxyRequest(h, area, path, options);
  const value = await h.poll(() => proxyRequest(h, area, path, { ...options, expected: undefined, consumerId: undefined }), r => r.status === options.expected, 'real proxy observes eventual configuration propagation', 20000);
  if (options.consumerId) h.check(value.payload?.consumerId === options.consumerId && value.payload.upstream === 'kongos-test', 'actual authenticated upstream Consumer is exact', { consumerId: options.consumerId }); return value;
}
export function jwtAuthorization(input) {
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'), payload = Buffer.from(JSON.stringify({ iss: input.key, exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url');
  return `Bearer ${head}.${payload}.${createHmac('sha256', input.secret).update(`${head}.${payload}`).digest('base64url')}`;
}
export function hmacAuthorization(input, date) {
  return `hmac username="${input.username}", algorithm="hmac-sha256", headers="date", signature="${createHmac('sha256', input.secret).update(`date: ${date}`).digest('base64')}"`;
}
export async function createNativeFixture(h, actor, area) {
  const tag = h.state.testTag, secret = family => `${family}-${randomUUID()}-${randomUUID()}`;
  const dir = mkdtempSync(join(tmpdir(), 'kongos-m8-pem-')); chmodSync(dir, 0o700); h.state.pemDirectory = dir; h.save();
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '30', '-subj', `/CN=${tag}.invalid`, '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: ['ignore', 'pipe', 'pipe'] });
  chmodSync(join(dir, 'key.pem'), 0o600); const key = readFileSync(join(dir, 'key.pem'), 'utf8'), cert = readFileSync(join(dir, 'cert.pem'), 'utf8'); h.remember({ key }); h.save();
  const certificate = await nativeCreate(h, actor, area, 'certificates', { cert, key, tags: [tag] });
  const ca = await nativeCreate(h, actor, area, 'ca_certificates', { cert, tags: [tag] });
  const sni = await nativeCreate(h, actor, area, 'snis', { name: `${tag}.invalid`, certificate: { id: certificate.id }, tags: [tag] });
  const upstream = await nativeCreate(h, actor, area, 'upstreams', { name: `${tag}.upstream`, tags: [tag] });
  const target = entity(h.data(await h.request(actor, route(area, `upstreams/${upstream.id}/targets`), 'POST', { target: 'echo-upstream:8081', weight: 100, tags: [tag] })));
  h.state.fixtures.push({ ...area, type: 'targets', id: target.id, parentId: upstream.id, name: target.target }); h.save();
  const service = await nativeCreate(h, actor, area, 'services', { name: `${tag}-service`, host: 'echo-upstream', port: 8081, protocol: 'http', retries: 0, connect_timeout: 3000, read_timeout: 3000, write_timeout: 3000, tags: [tag] });
  const consumer = await nativeCreate(h, actor, area, 'consumers', { username: `${tag}-consumer`, tags: [tag] });
  const inputs = { 'key-auth': { key: secret('m8-key') }, 'basic-auth': { username: `${tag}-basic`, password: secret('m8-basic') },
    jwt: { key: secret('m8-jwt-issuer'), secret: secret('m8-jwt'), algorithm: 'HS256' },
    oauth2: { name: `${tag}-oauth`, client_id: `${tag}-client`, client_secret: secret('m8-oauth'), redirect_uris: ['https://example.invalid/callback'] },
    'hmac-auth': { username: `${tag}-hmac`, secret: secret('m8-hmac') }, acls: { group: `${tag}-acl` } };
  const credentials = {}, routes = {}, plugins = {}; const provisionKey = secret('m8-provision'); h.remember({ key: provisionKey }); h.remember(inputs); h.save();
  for (const kind of CREDENTIAL_KINDS) {
    const credential = entity(h.data(await h.request(actor, route(area, `consumers/${consumer.id}/credentials/${kind}`), 'POST', { ...inputs[kind], tags: [tag] })));
    h.check(typeof credential.id === 'string', 'fresh credential gets original exact native identity', { kind }); credentials[kind] = credential;
    h.state.fixtures.push({ ...area, type: 'credentials', credentialKind: kind, parentId: consumer.id, id: credential.id, name: credential.username ?? credential.name ?? credential.id }); h.save();
    const path = `/m8/${tag}/${kind}`, r = await nativeCreate(h, actor, area, 'routes', { name: `${tag}-${kind}-route`, service: { id: service.id }, protocols: ['http'], paths: [path], strip_path: true, tags: [tag] }); routes[kind] = { ...r, proxyPath: path };
    const name = kind === 'acls' ? 'acl' : kind, config = kind === 'key-auth' ? { key_names: ['apikey'], hide_credentials: true } : kind === 'basic-auth' ? { hide_credentials: true }
      : kind === 'oauth2' ? { provision_key: provisionKey, enable_client_credentials: true, accept_http_if_already_terminated: true }
      : kind === 'hmac-auth' ? { enforce_headers: ['date'] } : kind === 'acls' ? { whitelist: [inputs.acls.group], hide_groups_header: true } : {};
    plugins[kind] = await nativeCreate(h, actor, area, 'plugins', { name, route: { id: r.id }, config, tags: [tag] });
    if (kind === 'acls') await nativeCreate(h, actor, area, 'plugins', { name: 'key-auth', route: { id: r.id }, config: { hide_credentials: true }, tags: [tag] });
  }
  const fixture = { area, certificate, ca, sni, upstream, target, service, consumer, credentials, inputs, routes, plugins, provisionKey };
  h.state.nativeFixture = fixture; h.save(); return fixture;
}
export async function sixCredentialProxyAcceptance(h, fixture, stage) {
  const { area, consumer, inputs, routes } = fixture; const facts = [];
  for (const kind of CREDENTIAL_KINDS) {
    const path = routes[kind].proxyPath + '/echo'; let headers;
    if (kind === 'key-auth' || kind === 'acls') headers = { apikey: inputs['key-auth'].key };
    else if (kind === 'basic-auth') headers = { Authorization: `Basic ${Buffer.from(`${inputs[kind].username}:${inputs[kind].password}`).toString('base64')}` };
    else if (kind === 'jwt') headers = { Authorization: jwtAuthorization(inputs.jwt) };
    else if (kind === 'hmac-auth') { const date = new Date().toUTCString(); headers = { Date: date, Authorization: hmacAuthorization(inputs[kind], date) }; }
    else {
      const token = await proxyRequest(h, area, routes.oauth2.proxyPath + '/oauth2/token', { method: 'POST', tls: h.state.oauthTlsReady===true, headers: { 'Content-Type': 'application/json', ...(h.state.oauthTlsReady===true?{}:{'X-Forwarded-Proto': 'https'}) }, body: { grant_type: 'client_credentials', client_id: inputs.oauth2.client_id, client_secret: inputs.oauth2.client_secret }, expected: 200 });
      h.check(typeof token.payload?.access_token === 'string' && token.payload.access_token.length >= 16, 'real OAuth2 client credentials flow returns a token'); headers = { Authorization: `Bearer ${token.payload.access_token}` };
    }
    await waitProxy(h, area, path, { headers, expected: 200, consumerId: consumer.id, tls: kind==='oauth2'&&h.state.oauthTlsReady===true }); facts.push({ kind, passed: true, originalConsumer: consumer.id });
  }
  h.public ??= {}; h.public.credentialProxyStages ??= []; h.public.credentialProxyStages.push({ stage, facts }); h.save();
}
export async function recycleAndRestore(h, actor, area, type, object) {
  const name = object.name ?? object.username ?? object.id;
  const result = h.data(await h.request(actor, route(area, `entities/${type}/${object.id}`), 'DELETE', { confirmed: true, confirm_name: name }));
  await h.request(actor, route(area, `entities/${type}/${object.id}`), 'GET', undefined, { expected: [404] });
  const page = h.data(await h.request(actor, scope(area.cid, area.wid, 'recycle-bin', { size: 100, search: name })));
  const entries = page.items.filter(e => e.original_id === object.id && !['restored', 'purged'].includes(e.state)); h.check(entries.length === 1, 'deleted root has one exact scoped soft-recycle entry', { type });
  const entry = entries[0]; h.state.recycleEntries ??= []; h.state.recycleEntries.push({ ...area, id: entry.id, originalId: object.id, type, name: entry.root_name, state: entry.state }); h.save();
  const restored = h.data(await h.request(actor, route(area, `recycle-bin/${entry.id}/restore`), 'POST', { confirmed: true, confirm_name: entry.root_name }));
  h.check(restored.state === 'restored', 'original object graph reaches fully restored state', { type });
  const current = await nativeRead(h, actor, area, type, object.id); h.check(current.id === object.id, 'restored root preserves original native UUID', { type }); return { entry, restored, current, deletedResult: result };
}
