import {execFileSync} from 'node:child_process';

const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
const roles=['owner','administrator'];

// This helper consumes an already-authorized immutable journal checkpoint. It
// never opens a reference file, sends a login/refresh, or persists recovered RAM.
export function manualSessionRecoveryContext(input){
 if(!exact(input,['candidates','expected'])||!Array.isArray(input.candidates)||input.candidates.length>4096||input.candidates.some(v=>typeof v!=='string'||!v.length||v.length>16384)||!exact(input.expected,roles))throw Error('Manual session recovery input invalid');
 for(const role of roles){const e=input.expected[role],portal=role==='owner',keys=['actorId','loginRequestId','startedAt','responseObservedAt',...(portal?['clusterId','workspaceId']:[])];
  if(!exact(e,keys)||!uuid(e.actorId)||!uuid(e.loginRequestId)||portal&&(!uuid(e.clusterId)||!uuid(e.workspaceId)))throw Error('Manual session identity invalid');
  const start=Date.parse(e.startedAt),end=Date.parse(e.responseObservedAt);
  if(typeof e.startedAt!=='string'||typeof e.responseObservedAt!=='string'||!Number.isFinite(start)||!Number.isFinite(end)||end<start||end-start>60000||new Date(start).toISOString()!==e.startedAt||new Date(end).toISOString()!==e.responseObservedAt)throw Error('Manual session original login window invalid');
 }
 if(input.expected.owner.actorId===input.expected.administrator.actorId||input.expected.owner.loginRequestId===input.expected.administrator.loginRequestId||Buffer.byteLength(JSON.stringify(input),'utf8')>4*1024*1024)throw Error('Manual session recovery input ambiguous or over budget');
 return {candidates:[...input.candidates],expected:{owner:{...input.expected.owner},administrator:{...input.expected.administrator}}};
}

// Select every eligible original-window session rather than trusting a candidate
// SID. A second same-window SID or repeated exact login audit is ambiguous.
export const MANUAL_PORTAL_SESSION_SQL=`SELECT s.id,s.refresh_token_hash,s.csrf_token_hash,s.credential_epoch,
 (SELECT count(*)::int FROM audit_events a WHERE a.request_id=$4 AND a.action='portal.login' AND a.result='success'
 AND a.actor_id IS NULL AND a.actor_type='developer' AND a.entity_type='portal_developers' AND a.entity_id=d.id::text
 AND a.cluster_id=s.cluster_id AND a.workspace_id=s.workspace_id
 AND a.occurred_at BETWEEN $5::timestamptz-interval '2 seconds' AND $6::timestamptz+interval '2 seconds'
 AND a.occurred_at BETWEEN s.created_at-interval '2 seconds' AND s.created_at+interval '5 seconds') AS login_count
 FROM portal_sessions s JOIN portal_developers d ON d.cluster_id=s.cluster_id AND d.workspace_id=s.workspace_id AND d.id=s.developer_id
 JOIN portal_settings p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id
 JOIN workspaces w ON w.cluster_id=s.cluster_id AND w.id=s.workspace_id JOIN clusters c ON c.id=s.cluster_id
 WHERE s.developer_id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()
 AND s.created_at BETWEEN $5::timestamptz-interval '2 seconds' AND $6::timestamptz+interval '2 seconds'
 AND d.status='active' AND d.deleted_at IS NULL AND d.credential_epoch=s.credential_epoch
 AND p.status='active' AND p.published=true AND p.deleted_at IS NULL AND w.status='active' AND w.deleted_at IS NULL
 AND c.status<>'disabled' AND c.deleted_at IS NULL LIMIT 11`;

export const MANUAL_CONSOLE_SESSION_SQL=`SELECT s.id,s.refresh_token_hash,s.csrf_token_hash,s.credential_epoch,
 (SELECT count(*)::int FROM audit_events a WHERE a.request_id=$2 AND a.action='login' AND a.result='success'
 AND a.actor_id=u.id AND a.actor_type='user' AND a.entity_type='authentication' AND a.cluster_id IS NULL AND a.workspace_id IS NULL
 AND a.occurred_at BETWEEN $3::timestamptz-interval '2 seconds' AND $4::timestamptz+interval '2 seconds'
 AND a.occurred_at BETWEEN s.created_at-interval '2 seconds' AND s.created_at+interval '5 seconds') AS login_count
 FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.user_id=$1 AND s.revoked_at IS NULL AND s.expires_at>now()
 AND s.created_at BETWEEN $3::timestamptz-interval '2 seconds' AND $4::timestamptz+interval '2 seconds'
 AND u.status='active' AND u.deleted_at IS NULL AND s.credential_epoch=u.credential_epoch LIMIT 11`;

// Both identities are read in one statement snapshot under BEGIN READ ONLY.
export const MANUAL_PAIR_SESSION_SQL=`SELECT 'owner' AS role,to_jsonb(v) AS session FROM (${MANUAL_PORTAL_SESSION_SQL}) v
 UNION ALL SELECT 'administrator' AS role,to_jsonb(v) AS session FROM (${MANUAL_CONSOLE_SESSION_SQL.replace(/\$(\d+)/g,(_m,n)=>'$'+(Number(n)+6))}) v`;

function readerRuntime(sql){
 const pg=require('pg'),jwt=require('jsonwebtoken'),{createHash,timingSafeEqual}=require('node:crypto');
 let input='',overBudget=false;
 process.stdin.on('data',v=>{if(overBudget)return;input+=v;if(Buffer.byteLength(input,'utf8')>4*1024*1024){overBudget=true;input='';}});
 process.stdin.on('end',async()=>{let pool,client;try{
  if(overBudget)throw Error();const q=JSON.parse(input),t=q.candidates,e=q.expected;
  const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
  const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
  if(!exact(q,['candidates','expected'])||!Array.isArray(t)||t.length>4096||t.some(v=>typeof v!=='string'||!v.length||v.length>16384)||!exact(e,['owner','administrator']))throw Error();
  const matches={},start={};
  for(const role of ['owner','administrator']){
   const x=e[role],portal=role==='owner';if(!exact(x,['actorId','loginRequestId','startedAt','responseObservedAt',...(portal?['clusterId','workspaceId']:[])])||!uuid(x.actorId)||!uuid(x.loginRequestId)||portal&&(!uuid(x.clusterId)||!uuid(x.workspaceId)))throw Error();
   const a=Date.parse(x.startedAt),b=Date.parse(x.responseObservedAt);if(typeof x.startedAt!=='string'||typeof x.responseObservedAt!=='string'||!Number.isFinite(a)||!Number.isFinite(b)||b<a||b-a>60000||new Date(a).toISOString()!==x.startedAt||new Date(b).toISOString()!==x.responseObservedAt)throw Error();start[role]={a,b};
   const secret=process.env[portal?'PORTAL_SECRET':'APP_SECRET'];if(!secret||secret.length<32)throw Error();
   matches[role]=[];
   for(let i=0;i<t.length;i++)try{
    const c=jwt.verify(t[i],secret,{algorithms:['HS256'],issuer:portal?'kongos-portal':'kongos-console',audience:portal?'kongos-portal':'kongos-api',ignoreExpiration:true});
    if(typeof c==='object'&&c.sub===x.actorId&&uuid(c.sid)&&Number.isSafeInteger(c.iat)&&Number.isSafeInteger(c.exp)&&c.exp===c.iat+900&&c.iat*1000>=a-2000&&c.iat*1000<=b+2000&&
      (portal?c.kind==='portal_developer'&&c.cid===x.clusterId&&c.wid===x.workspaceId&&Number.isSafeInteger(c.credential_epoch)&&c.credential_epoch>0:!('kind'in c)&&!('cid'in c)&&!('wid'in c)))matches[role].push({i,c});
   }catch{}
   if(matches[role].length!==1)throw Error();
  }
  if(e.owner.actorId===e.administrator.actorId||e.owner.loginRequestId===e.administrator.loginRequestId)throw Error();
  pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});client=await pool.connect();await client.query('BEGIN READ ONLY');
  const p=e.owner,c=e.administrator,rows=(await client.query(sql,[p.actorId,p.clusterId,p.workspaceId,p.loginRequestId,p.startedAt,p.responseObservedAt,c.actorId,c.loginRequestId,c.startedAt,c.responseObservedAt])).rows;
  const hash=s=>createHash('sha256').update(s,'utf8').digest('hex'),equal=(s,h)=>typeof h==='string'&&/^[a-f\d]{64}$/.test(h)&&timingSafeEqual(Buffer.from(hash(s),'hex'),Buffer.from(h,'hex')),proof={};
  for(const role of ['owner','administrator']){
   const eligible=rows.filter(v=>v.role===role);if(eligible.length!==1||eligible[0].session?.login_count!==1)throw Error();
   const row=eligible[0].session,access=matches[role][0];if(row.id!==access.c.sid||!Number.isSafeInteger(Number(row.credential_epoch))||Number(row.credential_epoch)<1||role==='owner'&&Number(row.credential_epoch)!==access.c.credential_epoch)throw Error();
   const refresh=[],csrf=[];
   for(let i=0;i<t.length;i++){const parts=t[i].split('.');if(parts.length===2&&parts[0]===row.id&&/^[A-Za-z0-9_-]{43,128}$/.test(parts[1])&&equal(parts[1],row.refresh_token_hash))refresh.push(i);if(/^[A-Za-z0-9_-]{43,128}$/.test(t[i])&&equal(t[i],row.csrf_token_hash))csrf.push(i);}
   if(refresh.length!==1||csrf.length!==1||new Set([access.i,refresh[0],csrf[0]]).size!==3)throw Error();
   proof[role]={accessIndex:access.i,refreshIndex:refresh[0],csrfIndex:csrf[0],sessionId:row.id,issuedAt:access.c.iat,accessExpired:access.c.exp<=Date.now()/1000,originalLoginAudited:true,currentSessionVerified:true,refreshVerified:true,csrfVerified:true};
  }
  if(new Set(Object.values(proof).flatMap(v=>[v.accessIndex,v.refreshIndex,v.csrfIndex])).size!==6||proof.owner.sessionId===proof.administrator.sessionId)throw Error();
  await client.query('ROLLBACK');process.stdout.write(JSON.stringify(proof));
 }catch{if(client)await client.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{client?.release();await pool?.end();}});
}
export const MANUAL_SESSION_READER_PROGRAM=`(${readerRuntime.toString()})(${JSON.stringify(MANUAL_PAIR_SESSION_SQL)});`;

export function readOriginalManualSessionCookies(input,execute=execFileSync){
 const context=manualSessionRecoveryContext(input);
 try{return JSON.parse(execute('docker',['compose','exec','-T','console-api','node','-e',MANUAL_SESSION_READER_PROGRAM],{input:JSON.stringify(context),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:16384}));}
 catch{throw Error('Original manual session recovery failed; private diagnostics withheld');}
}
export function originalManualCookieJar(input,proof,role){
 const context=manualSessionRecoveryContext(input),p=proof?.[role],e=context.expected[role];
 if(!roles.includes(role)||!exact(p,['accessIndex','refreshIndex','csrfIndex','sessionId','issuedAt','accessExpired','originalLoginAudited','currentSessionVerified','refreshVerified','csrfVerified'])||!uuid(p.sessionId)||!Number.isSafeInteger(p.issuedAt)||typeof p.accessExpired!=='boolean'||['originalLoginAudited','currentSessionVerified','refreshVerified','csrfVerified'].some(k=>p[k]!==true))throw Error('Original manual session proof invalid');
 const indices=[p.accessIndex,p.refreshIndex,p.csrfIndex];if(indices.some(i=>!Number.isInteger(i)||i<0||i>=context.candidates.length)||new Set(indices).size!==3)throw Error('Original manual session proof ambiguous');
 const values=indices.map(i=>context.candidates[i]);let c;try{c=JSON.parse(Buffer.from(values[0].split('.')[1],'base64url'));}catch{throw Error('Original manual access identity invalid');}
 const portal=role==='owner';
 if(c.sid!==p.sessionId||c.sub!==e.actorId||c.iat!==p.issuedAt||c.exp!==c.iat+900||c.iat*1000<Date.parse(e.startedAt)-2000||c.iat*1000>Date.parse(e.responseObservedAt)+2000||c.iss!==(portal?'kongos-portal':'kongos-console')||c.aud!==(portal?'kongos-portal':'kongos-api')||portal&&(c.kind!=='portal_developer'||c.cid!==e.clusterId||c.wid!==e.workspaceId)||values[1].split('.')[0]!==p.sessionId)throw Error('Original manual session identity changed');
 const names=portal?['kongos_portal_access','kongos_portal_refresh','kongos_portal_csrf']:['kongos_access','kongos_refresh','kongos_csrf'];
 // Session cookies deliberately have no browser expiry; an expired signed
 // access token remains expired and must take the normal sameSID refresh path.
 return names.map((name,i)=>({name,value:values[i],domain:'127.0.0.1',path:portal?'/api/v1/portal':i===1?'/api/v1/auth':'/api',httpOnly:true,secure:false,sameSite:'Strict'}));
}
