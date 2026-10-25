import { hostname, userInfo } from 'node:os';
import { DbService } from './db.service';
import { SecretService } from './secret.service';
import { AuditService } from '../modules/audit/audit.service';
import { AuditOutboxWriter } from '../modules/event-core/audit-outbox-writer.service';

/**
 * Break-glass for the single-approver deadlock (approval mode enabled while only
 * one human can approve, so requester!=approver can never be satisfied).
 *
 * Host/DB-only: there is deliberately NO HTTP route. It is run inside the API
 * container (`docker compose exec -T console-api node dist/infrastructure/approval-break-glass.js`)
 * with a JSON command on bounded stdin. It never switches a cluster to direct mode
 * and never approves anything: it only binds the protected built-in `approver`
 * role (SQL046) to an existing active user, and only while fewer than two
 * eligible approvers exist. Every grant is written to the hash-chained audit log.
 */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export class BreakGlassError extends Error{constructor(readonly code:string){super(code);}}

export async function eligibleApprovers(db:DbService):Promise<number>{
  const row=await db.one<{n:string}>(`SELECT count(DISTINCT u.id) AS n FROM users u WHERE u.status='active' AND (u.super_admin
    OR EXISTS(SELECT 1 FROM iam_effective_grants g WHERE g.user_id=u.id AND g.module='workflows' AND g.action='approve'))`);
  return Number(row?.n??0);
}

export async function runBreakGlass(db:DbService,audit:Pick<AuditService,'append'>,input:any,origin:{host:string;osUser:string}):Promise<unknown>{
  if(!input||typeof input!=='object'||Array.isArray(input))throw new BreakGlassError('BREAK_GLASS_INVALID_COMMAND');
  if(input.action==='status'){
    if(Object.keys(input).some(k=>k!=='action'))throw new BreakGlassError('BREAK_GLASS_INVALID_FIELDS');
    const approvalClusters=await db.query<{id:string;name:string}>("SELECT id,name FROM clusters WHERE execution_mode='approval' AND deleted_at IS NULL ORDER BY name");
    const n=await eligibleApprovers(db);
    return {eligibleApprovers:n,approvalClusters,deadlockRisk:n<2};
  }
  if(input.action!=='grant-approver')throw new BreakGlassError('BREAK_GLASS_INVALID_COMMAND');
  const allowed=['action','userId','operator','reason','ticket'];
  if(Object.keys(input).some(k=>!allowed.includes(k)))throw new BreakGlassError('BREAK_GLASS_INVALID_FIELDS');
  const {userId,operator,reason,ticket}=input;
  if(typeof userId!=='string'||!UUID.test(userId))throw new BreakGlassError('BREAK_GLASS_INVALID_USER');
  if(typeof operator!=='string'||!/^\S.{1,127}$/.test(operator))throw new BreakGlassError('BREAK_GLASS_OPERATOR_REQUIRED');
  if(typeof reason!=='string'||reason.trim().length<20||reason.length>1000)throw new BreakGlassError('BREAK_GLASS_REASON_REQUIRED');
  if(typeof ticket!=='string'||!/^[\w.:#/-]{3,128}$/.test(ticket))throw new BreakGlassError('BREAK_GLASS_TICKET_REQUIRED');
  return db.transaction(async tx=>{
    // Serialize with all IAM writers so the deadlock precondition cannot race.
    await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR UPDATE');
    const before=await eligibleApprovers(tx);
    if(before>=2)throw new BreakGlassError('BREAK_GLASS_NOT_DEADLOCKED');
    const user=await tx.one<{id:string;status:string}>('SELECT id,status FROM users WHERE id=$1 FOR UPDATE',[userId]);
    if(!user||user.status!=='active')throw new BreakGlassError('BREAK_GLASS_USER_NOT_ACTIVE');
    const role=await tx.one<{id:string}>("SELECT id FROM roles WHERE builtin_kind='approver' AND status='active' AND cluster_id IS NULL AND workspace_id IS NULL");
    if(!role)throw new BreakGlassError('BREAK_GLASS_APPROVER_ROLE_MISSING');
    if(await tx.one("SELECT id FROM user_role_bindings WHERE user_id=$1 AND role_id=$2 AND cluster_id IS NULL AND workspace_id IS NULL AND status='active'",[userId,role.id]))
      throw new BreakGlassError('BREAK_GLASS_ALREADY_BOUND');
    const binding=await tx.one<{id:string}>('INSERT INTO user_role_bindings(user_id,role_id,granted_by) VALUES($1,$2,NULL) RETURNING id',[userId,role.id]);
    await tx.exec('UPDATE users SET permissions_epoch=permissions_epoch+1,revision=revision+1,updated_at=now() WHERE id=$1',[userId]);
    const after=await eligibleApprovers(tx);
    await audit.append({actorId:null,actorType:'system',entityType:'user_role_binding',entityId:binding!.id,action:'break_glass_grant_approver',result:'success',
      after:{user_id:userId,role:'approver',operator,reason,ticket,host:origin.host,os_user:origin.osUser,eligible_approvers_before:before,eligible_approvers_after:after},
      requestId:'approval-break-glass-cli'},tx);
    return {bindingId:binding!.id,eligibleApproversBefore:before,eligibleApproversAfter:after};
  });
}

async function main():Promise<void>{
  let bytes=0;const chunks:Buffer[]=[];
  for await(const chunk of process.stdin){const buffer=Buffer.from(chunk);bytes+=buffer.length;if(bytes>8192)throw new BreakGlassError('BREAK_GLASS_STDIN_BUDGET');chunks.push(buffer);}
  if(process.argv.length!==2)throw new BreakGlassError('BREAK_GLASS_INVALID_COMMAND');
  const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const db=new DbService();
  try{
    const secrets=new SecretService(),audit=new AuditService(db,secrets,new AuditOutboxWriter(db,secrets));
    const result=await runBreakGlass(db,audit,input,{host:hostname(),osUser:userInfo().username});
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }finally{await db.onModuleDestroy();}
}
if(require.main===module)main().catch(error=>{process.stderr.write(`${error instanceof BreakGlassError?error.code:'BREAK_GLASS_FAILED'}\n`);process.exitCode=1;});
