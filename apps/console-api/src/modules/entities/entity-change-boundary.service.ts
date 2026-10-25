import {ConflictException, ForbiddenException, Inject, Injectable} from '@nestjs/common';
import {isIP} from 'node:net';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {assertManagedCollectorDestination, assertPluginDestinationSafety, assertPluginExecutionPrivilege, assertProxyDestination, assertTargetDestination} from '../../infrastructure/kong/destination-policy';
import {workspaceTag} from '../../infrastructure/kong/tags';
import {AuthorizationService} from '../authorization/authorization.service';
import {validGrant,grantMatchesEntity} from '../authorization/grant-policy';
import {WorkspaceResolverService, type WorkspaceRow} from '../workspaces/workspace-resolver.service';
import {MetricsCredentialsService} from '../metrics/metrics-credentials.service';
import {PORTAL_AUTH_BOUNDARY, type PortalAuthBoundaryPolicy} from '../workflows/approved-execution.types';
import {assertFrozenChangeGrants, frozenChangePermits, type FrozenChangeSubject, type FrozenChangeObject} from './entity-change-subject-policy';
import {entityReferenceId} from './entity-reference';
import {CREDENTIAL_KINDS} from './entities.types';
import type {EntityChangePreparationBoundary, PreparedEntityChange} from './entity-change.types';
import type {EntityChangeIntentEnvelope} from '../workflows/entity-change-intent.types';
import type {EntityActor} from './entities.types';
import type {EntityRecycleCurrentWitnessHandle, EntityRecycleCurrentWitnessReader} from '../recycle-bin/entity-recycle-current-witness.types';
import type {EntityScheduledNamespaceCheckpoint, EntityScheduledNamespaceProof} from '../workflows/entity-scheduled-namespace.types';

const deny = (code: string) => new ForbiddenException({code});
/** Fixed zero-write preparation/subject policy. It cannot mint an actor,
 * approval, operation, claim, metrics fence or native execution capability. */
@Injectable()
export class EntityChangeBoundaryService {
  private recycleCurrent?:Readonly<EntityRecycleCurrentWitnessReader>;
  installCurrentRecycleWitnessReader(reader:EntityRecycleCurrentWitnessReader):void {
    if(this.recycleCurrent||!reader||typeof reader.resolve!=='function'||Object.keys(reader).some(key=>key!=='resolve'))throw deny('ENTITY_RECYCLE_CURRENT_READER_INVALID');
    this.recycleCurrent=Object.freeze({resolve:reader.resolve.bind(reader)});
  }
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly context: KongExecutionContextService,
    private readonly authz: AuthorizationService, private readonly workspaces: WorkspaceResolverService, private readonly kong: KongService,
    private readonly metricsCredentials: MetricsCredentialsService, @Inject(PORTAL_AUTH_BOUNDARY) private readonly portal: PortalAuthBoundaryPolicy) {}

  resolveCurrentRecycleWitness(handle:EntityRecycleCurrentWitnessHandle){
    if(!this.recycleCurrent)throw deny('ENTITY_RECYCLE_CURRENT_READER_REQUIRED');
    return this.recycleCurrent.resolve(handle);
  }
  /** No SID exemption is inferred from a DTO, actor or scheduler flag. The
   * actual Context authenticates its original private ancestor on every call;
   * these additional current SQL checks never manufacture native authority. */
  private async scheduledScope(checkpoint: EntityScheduledNamespaceCheckpoint, actor: EntityActor, clusterId: string, workspaceId: string,
    tx: DbService, transportScope?: string): Promise<Readonly<EntityScheduledNamespaceProof>> {
    if (typeof this.context.verifyEntityScheduledNamespace !== 'function') throw deny('ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED');
    const proof = await this.context.verifyEntityScheduledNamespace(checkpoint), frame = this.context.current();
    if (!proof || proof.version !== 1 || proof.origin !== 'scheduled-entity' || proof.sessionId !== null || frame.sessionId != null
      || proof.actor.id !== actor.user.id || frame.actor?.id !== proof.actor.id || actor.workspaceId !== workspaceId
      || frame.clusterId !== clusterId || frame.workspaceId !== workspaceId || proof.clusterId !== clusterId || proof.workspaceId !== workspaceId
      || proof.claim.ownerId !== proof.actor.id || proof.claim.clusterId !== clusterId || proof.claim.workspaceId !== workspaceId
      || proof.claim.ownerCredentialEpoch !== proof.credentialEpoch || !Number.isFinite(Date.parse(proof.expiresAt)) || Date.parse(proof.expiresAt) <= Date.now()
      || transportScope !== undefined && proof.transportScope !== transportScope) throw deny('ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED');
    const owner = await tx.one<any>("SELECT id,credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [proof.actor.id]);
    const cluster = await tx.one<any>('SELECT revision FROM clusters WHERE id=$1 AND deleted_at IS NULL', [clusterId]);
    const workspace = await this.workspaces.get(clusterId, workspaceId, false, tx);
    if (!owner || owner.id !== proof.actor.id || String(owner.credential_epoch) !== proof.credentialEpoch
      || !cluster || Number(cluster.revision) !== proof.clusterRevision || workspace.revision !== proof.workspaceRevision || workspace.status !== 'active'
      || await this.kong.transportScope(clusterId) !== proof.transportScope) throw deny('ENTITY_SCHEDULE_BOUNDARY_SCOPE_CHANGED');
    return proof;
  }
  private scheduledMaterial(material: Readonly<PreparedEntityChange>, proof: Readonly<EntityScheduledNamespaceProof>): void {
    const {changeDigest, ...payload} = material;
    if (material.requesterId !== proof.actor.id || material.clusterId !== proof.clusterId || material.workspaceId !== proof.workspaceId
      || changeDigest !== proof.intent.changeDigest || this.secrets.fingerprint(payload) !== changeDigest
      || material.scope.transportScope !== proof.transportScope || material.scope.clusterRevision !== proof.clusterRevision
      || material.scope.workspaceRevision !== proof.workspaceRevision) throw deny('ENTITY_SCHEDULE_BOUNDARY_MATERIAL_CHANGED');
  }

  private async membership(material: PreparedEntityChange, subject: FrozenChangeSubject, action: 'read' | 'write' | 'approve', tx = this.db): Promise<void> {
    const workspace = await this.workspaces.get(material.clusterId, material.workspaceId, false, tx);
    if (action !== 'read' && workspace.status !== 'active') throw deny('ENTITY_CHANGE_WORKSPACE_INACTIVE');
    const matches = (data: any, row: WorkspaceRow) => {
      const tags = data?.tags ?? [];
      if (!Array.isArray(tags) || tags.some(t => typeof t !== 'string')) return false;
      const reserved = tags.filter(t => t.startsWith('kos-ws-'));
      return row.is_default ? reserved.length === 0 || reserved.length === 1 && reserved[0] === workspaceTag('default')
        : reserved.length === 1 && reserved[0] === workspaceTag(row.code);
    };
    for (const graph of [subject.before, subject.after]) for (const node of graph.values()) {
      const inherited = node.type === 'targets' || CREDENTIAL_KINDS.includes(node.type as any);
      const parentType = node.type === 'targets' ? 'upstreams' : 'consumers';
      const parentId = entityReferenceId(node.type === 'targets' ? node.data.upstream : node.data.consumer);
      const owner = inherited ? graph.get(`${parentType}:${parentId}`) : node;
      if (!owner || !matches(owner.data, workspace)) throw deny('ENTITY_CHANGE_OBJECT_WORKSPACE_MISMATCH');
    }
  }
  async assertStoredSubject(input: Parameters<NonNullable<EntityChangePreparationBoundary['assertStoredSubject']>>[0], tx = this.db): Promise<void> {
    const {material, actor, action} = input, frame = this.context.current();
    const scheduled = !frame.sessionId ? await this.scheduledScope('capture', actor, material.clusterId, material.workspaceId, tx, material.scope.transportScope) : null;
    if ((!frame.sessionId && !scheduled) || frame.actor?.id !== actor.user.id || frame.clusterId !== material.clusterId || frame.workspaceId !== material.workspaceId
      || actor.workspaceId !== material.workspaceId) throw deny('ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED');
    if (scheduled) this.scheduledMaterial(material, scheduled);
    const snapshot = await this.authz.snapshot(actor.user, tx);
    if (snapshot.user.forcePasswordChange) throw deny('PASSWORD_CHANGE_REQUIRED');
    if (scheduled && (snapshot.user.id !== scheduled.actor.id || snapshot.user.superAdmin !== scheduled.actor.superAdmin || snapshot.version !== scheduled.permissionVersion))
      throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    const subject = assertFrozenChangeGrants(material, snapshot.grants, snapshot.user.superAdmin, action, material.requesterId === actor.user.id);
    await this.membership(material, subject, action, tx);
    if (await this.authz.permissionVersion(actor.user, tx) !== snapshot.version) throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    if (scheduled && await this.scheduledScope('capture', actor, material.clusterId, material.workspaceId, tx, material.scope.transportScope) !== scheduled)
      throw deny('ENTITY_SCHEDULE_BOUNDARY_SCOPE_CHANGED');
  }
  async assertIntentSubject(envelope: EntityChangeIntentEnvelope, userId: string, action: 'read' | 'write' | 'approve', tx = this.db): Promise<void> {
    const frame = this.context.current();
    if (!frame.actor || frame.actor.id !== userId || action === 'write' && userId !== envelope.requesterId) throw deny('ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED');
    const actor = {user: frame.actor, workspaceId: envelope.workspaceId, requestId: frame.requestId, ip: frame.ip};
    if (!frame.sessionId) {
      const scheduled = await this.scheduledScope('capture', actor, envelope.clusterId, envelope.workspaceId, tx, envelope.prepared.scope.transportScope);
      if (envelope.version !== 2 || envelope.requesterId !== scheduled.actor.id || envelope.credentialEpoch !== scheduled.credentialEpoch
        || envelope.intentId !== scheduled.intent.id || envelope.revision !== scheduled.intent.revision
        || envelope.packetManifestHmac !== scheduled.intent.packetManifestHmac || this.secrets.fingerprint(envelope) !== scheduled.intent.materialHmac)
        throw deny('ENTITY_SCHEDULE_BOUNDARY_MATERIAL_CHANGED');
      // Preserve the original scheduled namespace. runActor would construct a
      // different frame and must never be used to adopt a no-SID principal.
      await this.assertStoredSubject({material: envelope.prepared, actor, action, mode: 'historical'}, tx);
      return;
    }
    await this.context.runActor({actor: frame.actor, clusterId: envelope.clusterId, workspaceId: envelope.workspaceId, module: 'workflows', action, requestId: frame.requestId},
      () => this.assertStoredSubject({material: envelope.prepared, actor, action, mode: 'historical'}, tx));
  }
  /** Reviewer validation reads the actual user/grants. It does not adopt that
   * user's identity inside the executor's ALS or invent a session. */
  async assertReviewer(userId: string, material: PreparedEntityChange, tx = this.db): Promise<void> {
    const epoch = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const user = await tx.one<any>("SELECT id,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [userId]);
    if (!user || userId === material.requesterId) throw deny('ENTITY_CHANGE_REVIEWER_INACTIVE');
    const grants = (await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [userId])).filter(validGrant);
    const subject = assertFrozenChangeGrants(material, grants, user.super_admin === true, 'approve', false);
    await this.membership(material, subject, 'approve', tx);
    const after = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!epoch || !after || String(epoch.version) !== String(after.version)) throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
  }
  /** Current observations have their own opaque domain. They never replace
   * the approved historical subject and never adopt a reviewer's ALS identity. */
  async assertCurrentRecycleSubject(userId:string,material:PreparedEntityChange,action:'write'|'approve',handle:EntityRecycleCurrentWitnessHandle,tx=this.db):Promise<number>{
    const reader=this.recycleCurrent;if(!reader)throw deny('ENTITY_RECYCLE_CURRENT_READER_REQUIRED');
    const initial=reader.resolve(handle),d=initial.descriptor;
    if(d.source.clusterId!==material.clusterId||d.source.workspaceId!==material.workspaceId||d.source.executionActorId!==material.requesterId
      ||this.secrets.fingerprint(d.prepared)!==this.secrets.fingerprint(material)||action==='write'&&userId!==material.requesterId
      ||action==='approve'&&userId===material.requesterId)throw deny('ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID');
    const live=()=>{if(reader.resolve(handle)!==initial)throw deny('ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID');};
    const epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');live();
    const sql="SELECT id,super_admin,credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change";
    const user=await tx.one<any>(sql,[userId]);live();if(!user||user.id!==userId)throw deny('ENTITY_RECYCLE_CURRENT_PARTY_INACTIVE');
    const started=performance.now();
    const observed=await tx.query<any>(`SELECT g.*,
      CASE WHEN g.binding_source='user' THEN ub.id IS NOT NULL AND ub.status='active' AND(ub.expires_at IS NULL OR ub.expires_at>clock_timestamp())
        WHEN g.binding_source='team' THEN tb.id IS NOT NULL AND tb.status='active' AND tm.user_id IS NOT NULL AND t.status='active' AND(tb.expires_at IS NULL OR tb.expires_at>clock_timestamp()) ELSE false END AS binding_current,
      CASE WHEN g.binding_source='user' THEN extract(epoch FROM(ub.expires_at-clock_timestamp()))*1000
        WHEN g.binding_source='team' THEN extract(epoch FROM(tb.expires_at-clock_timestamp()))*1000 END AS binding_remaining_ms
      FROM iam_effective_grants g
      LEFT JOIN user_role_bindings ub ON g.binding_source='user' AND ub.id=g.binding_id AND ub.user_id=g.user_id AND ub.role_id=g.role_id
      LEFT JOIN team_role_bindings tb ON g.binding_source='team' AND tb.id=g.binding_id AND tb.role_id=g.role_id
      LEFT JOIN team_members tm ON tm.team_id=tb.team_id AND tm.user_id=g.user_id AND tm.status='active'
      LEFT JOIN teams t ON t.id=tb.team_id
      WHERE g.user_id=$1`,[userId]);live();
    const currentRows=observed.filter(row=>row.binding_current===true&&
      (row.binding_remaining_ms===null||Number.isFinite(Number(row.binding_remaining_ms))&&Number(row.binding_remaining_ms)>performance.now()-started));
    const bindingDeadline=Math.min(...currentRows.map(row=>row.binding_remaining_ms===null?Infinity:started+Number(row.binding_remaining_ms)));
    const grants=currentRows.filter(validGrant);
    const bindingsLive=()=>{live();if(performance.now()>=bindingDeadline)throw deny('ENTITY_RECYCLE_CURRENT_BINDING_EXPIRED');};
    // Both historical/proposed and current objects must independently pass
    // this party's fresh complete grants. No scopes from different users fuse.
    const historical=assertFrozenChangeGrants(material,grants,user.super_admin===true,action,action==='write');
    const assertSecret=(view:ReadonlyMap<string,FrozenChangeObject>,node:FrozenChangeObject)=>{
      if(user.super_admin===true||this.secrets.fingerprint(node.data)===this.secrets.fingerprint(this.secrets.redact(node.data)))return;
      const parent=entityReferenceId(node.data.consumer),entity=CREDENTIAL_KINDS.includes(node.type as any)&&!Array.isArray(node.data.tags)
        ?{...node.data,tags:view.get(`consumers:${parent}`)?.data.tags}:node.data;
      if(!grants.some(g=>grantMatchesEntity(g,'secrets','read',{clusterId:material.clusterId,workspaceId:material.workspaceId,entityType:node.type,entity})))throw deny('ENTITY_RECYCLE_CURRENT_SECRET_SCOPE_DENIED');
    };
    // Proposed/archive secrets are a separate approved-scope check, before
    // the first POST; absence never defers missing secret authority until a
    // credential has already been restored. These views are not witnesses.
    for(const view of [historical.before,historical.after])for(const node of view.values())assertSecret(view,node);
    const graph=new Map<string,FrozenChangeObject>();
    for(const node of initial.nodes){
      const archived=d.obligation.graph.nodes.find(original=>original.key===node.key);
      if(!archived||archived.id!==node.originalId||archived.type!==node.type||archived.affected!==node.affected)throw deny('ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID');
      let data=node.data;
      if(data.id!==node.originalId){
        const packet=d.packets.find(packet=>packet.nativeType===node.type&&packet.originalNativeId===node.originalId&&packet.nativeId===data.id);
        if(node.type!=='targets'||!packet||packet.method!=='POST'||packet.mutationAction!=='restore'||packet.parentId!==node.parentId
          ||packet.body?.target!==data.target)throw deny('ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID');
        // Scope uses the sealed logical original ID; actual observed bytes and
        // allocated history UUID stay untouched in the private witness.
        data={...data,id:node.originalId};
      }
      const key=`${node.type}:${node.originalId}`;if(graph.has(key))throw deny('ENTITY_RECYCLE_CURRENT_SUBJECT_INVALID');
      graph.set(key,{type:node.type,data});
    }
    await this.membership(material,{before:graph,after:graph},action,tx);bindingsLive();
    if(user.super_admin!==true)for(const node of initial.nodes){
      const value=graph.get(`${node.type}:${node.originalId}`)!;assertSecret(graph,value);
      const packet=d.packets.find(packet=>packet.nativeType===node.type&&(packet.originalNativeId??packet.nativeId)===node.originalId);
      const preserved=!packet&&d.obligation.kind==='recycle-restore'&&d.obligation.partialRestore?.presentNodes.some(value=>value.nodeKey===node.key);
      if(node.affected&&!preserved){
        if(!packet||!frozenChangePermits(grants,material,graph,value,'workflows',action)
          ||!frozenChangePermits(grants,material,graph,value,'native',action==='approve'?'read':packet.permissionAction))throw deny('ENTITY_CHANGE_SUBJECT_SCOPE_DENIED');
      }else{
        const prerequisite=material.prerequisites.find(p=>p.type===node.type&&p.nativeId===node.originalId&&!p.absent);
        const privateParent=prerequisite?.purpose==='private-parent'&&['consumers','upstreams'].includes(node.type)
          &&d.packets.some(packet=>packet.parentId===node.originalId);
        if(!privateParent&&!frozenChangePermits(grants,material,graph,value,'native','read'))throw deny('ENTITY_CHANGE_SUBJECT_SCOPE_DENIED');
      }
    }
    const afterUser=await tx.one<any>(sql,[userId]);bindingsLive();
    const after=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');bindingsLive();
    if(!epoch||!after||String(epoch.version)!==String(after.version)||!afterUser||this.secrets.fingerprint(user)!==this.secrets.fingerprint(afterUser))throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    return Math.min(bindingDeadline,initial.monotonicDeadline);
  }
  async assertPacket(input: Parameters<EntityChangePreparationBoundary['assertPacket']>[0]): Promise<void> {
    const {packet, actor, clusterId, workspaceId, transportScope} = input, frame = this.context.current();
    const scheduled = !frame.sessionId ? await this.scheduledScope('packet', actor, clusterId, workspaceId, this.db, transportScope) : null;
    if ((!frame.sessionId && !scheduled) || frame.actor?.id !== actor.user.id || frame.clusterId !== clusterId || frame.workspaceId !== workspaceId
      || actor.workspaceId !== workspaceId || await this.kong.transportScope(clusterId) !== transportScope) throw deny('ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED');
    if (this.secrets.fingerprint(packet.body ?? null) !== packet.bodyHmac || this.secrets.fingerprint(packet.before) !== packet.beforeHmac) throw deny('ENTITY_CHANGE_PACKET_INVALID');
    const snapshot = await this.authz.snapshot(actor.user), effective: any = {...(packet.before as any), ...packet.body};
    if (scheduled && (snapshot.user.forcePasswordChange || snapshot.user.id !== scheduled.actor.id
      || snapshot.user.superAdmin !== scheduled.actor.superAdmin || snapshot.version !== scheduled.permissionVersion)) throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    if (packet.method !== 'DELETE') {
      if (packet.nativeType === 'services') {
        let upstream: any;
        const path = `/upstreams/${encodeURIComponent(effective.host)}`;
        if (!isIP(String(effective.host).replace(/^\[|\]$/g, ''))) {
          try {upstream = await this.context.runInternalRead(clusterId, 'entity-preflight', () => this.kong.request(clusterId, 'GET', path), {paths: [path], maxCalls: 1, workspaceId});}
          catch (error: any) {if (typeof error?.getStatus !== 'function' || error.getStatus() !== 404) throw error;}
        }
        if (upstream?.id) {
          const targetPath = `/upstreams/${upstream.id}/targets`;
          await this.context.runInternalRead(clusterId, 'entity-preflight', async () => {
            let cursor: string | undefined;
            for (let page = 0; page < 5; page++) {
              const result = await this.kong.list(clusterId, targetPath, {size: 100}, cursor, 'entity-change-destination');
              for (const target of result.items) await assertTargetDestination(this.db, target.target);
              if (!result.nextCursor) return;
              cursor = result.nextCursor;
            }
            throw new ConflictException({code: 'DESTINATION_LOOKUP_LIMIT'});
          }, {paths: [targetPath], maxCalls: 8, maxPages: 5, maxRecords: 500, timeoutMs: 10_000, workspaceId});
        } else await assertProxyDestination(this.db, {host: effective.host, port: Number(effective.port ?? (['https', 'grpcs'].includes(effective.protocol) ? 443 : 80))});
      }
      if (packet.nativeType === 'targets' && !['mark_healthy', 'mark_unhealthy'].includes(packet.mutationAction)) await assertTargetDestination(this.db, effective.target);
      if (packet.nativeType === 'plugins') {
        if (input.action !== 'approve' && input.action !== 'read') assertPluginExecutionPrivilege(effective.name, effective.config, snapshot.user.superAdmin);
        const endpoint = effective.name === 'http-log' ? effective.config?.http_endpoint : undefined;
        let parsed: URL | undefined; try {if (endpoint) parsed = new URL(endpoint);} catch { /* ordinary destination check fails */ }
        if (parsed?.username || parsed?.password) {
          if (packet.mutationAction !== 'update' || (packet.before as any)?.config?.http_endpoint !== endpoint
            || input.action !== 'approve' && input.action !== 'read' && !snapshot.user.superAdmin) throw deny('MANAGED_METRICS_PROVISION_REQUIRED');
          if (!(await this.metricsCredentials.verifyManagedIngestUrl(clusterId, endpoint)).valid) throw deny('MANAGED_METRICS_TOKEN_INVALID');
          parsed.username = ''; parsed.password = '';
          await assertManagedCollectorDestination(this.db, clusterId, parsed.toString());
        } else await assertPluginDestinationSafety(this.db, effective.name, effective.config);
      }
    }
    if (!this.portal.assertPreparedChange) throw deny('ENTITY_CHANGE_PORTAL_PREPARATION_UNAVAILABLE');
    await this.portal.assertPreparedChange({clusterId, workspaceId, transportScope, method: packet.method, canonicalPath: packet.canonicalPath,
      nativeId: packet.nativeId, body: packet.body, before: packet.before, mutationAction: packet.mutationAction, parentId: packet.parentId, credentialKind: packet.credentialKind});
    if (await this.authz.permissionVersion(actor.user) !== snapshot.version) throw deny('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    if (scheduled && await this.scheduledScope('packet', actor, clusterId, workspaceId, this.db, transportScope) !== scheduled)
      throw deny('ENTITY_SCHEDULE_BOUNDARY_SCOPE_CHANGED');
  }
}
