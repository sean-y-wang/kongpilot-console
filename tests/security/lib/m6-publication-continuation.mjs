import { M6_C1, M6_C2, cookieMerge, entity, scope } from './m6-harness.mjs';

const cookieValue = (cookie, name) => cookie.split('; ').find(pair => pair.startsWith(`${name}=`))?.slice(name.length + 1);
export async function originalConsoleSession(h, session) {
  let result = await h.request(session, '/auth/me');
  if (result.status === 401) {
    const previous = { cookie: session.cookie, csrf: session.csrf, actorId: session.user.id };
    const oldSid = cookieValue(previous.cookie,'kongos_refresh')?.split('.')[0];
    h.check(/^[\da-f-]{36}$/.test(oldSid ?? ''), 'Continuation/Refresh', 'expired original access still has its original opaque refresh session');
    const csrf = h.ok(await h.request(session,'/auth/csrf'), 'Continuation/Refresh', 'current original refresh session supplies its valid CSRF');
    h.check(typeof csrf.csrfToken === 'string' && csrf.csrfToken.length >= 16, 'Continuation/Refresh', 'original-session CSRF bootstrap is complete');
    session.csrf = csrf.csrfToken;
    h.saveReference({ originalSessionRefreshes: [...(h.referenceData.originalSessionRefreshes ?? []), { actorId:session.user.id, sessionId:oldSid, previousCookie:previous.cookie, previousCsrf:previous.csrf, phase:'before-single-refresh', startedAt:new Date().toISOString() }] });
    // Never retry this POST. Unknown refresh ACKs stop the whole continuation.
    const refreshed = await h.request(session,'/auth/refresh','POST');
    const value = h.ok(refreshed,'Continuation/Refresh','one standard refresh renews the original session');
    const nextCookie = cookieMerge(session.cookie,refreshed.response.headers.getSetCookie());
    const nextSid = cookieValue(nextCookie,'kongos_refresh')?.split('.')[0];
    const access = cookieValue(nextCookie,'kongos_access');
    let jwtSid; try { jwtSid = JSON.parse(Buffer.from(access.split('.')[1],'base64url').toString()).sid; } catch { jwtSid = undefined; }
    h.check(value.user?.id === previous.actorId && nextSid === oldSid && jwtSid === oldSid, 'Continuation/Refresh', 'refreshed cookies preserve the exact original actor and server session UUID');
    session.cookie=nextCookie; session.user=value.user; h.rememberCookies(nextCookie); h.saveReference();
    result = await h.request(session,'/auth/me');
  }
  const me=h.ok(result,'Continuation/Actor','current original session is authorized after optional renewal');
  h.check((me.user?.id??me.id)===session.user.id,'Continuation/Actor','current DB-authorized session retains its exact original user UUID');
  return session;
}

/** This guard is intentionally specific to the first observed, locally blocked
 * publication request. It is not a general permission to retry failed writes. */
export function publicationContinuationCheckpoint(reference, proof) {
  const primary = reference.fixtures?.[0], secondary = reference.fixtures?.[1], otherFixture = reference.fixtures?.[2];
  const first = primary?.publications?.[0], attempt = reference.writeAttempts?.find(row => row.key === proof?.originalKey);
  const attempts = reference.writeAttempts?.filter(row => row.key === proof?.originalKey) ?? [];
  const counts = proof?.ledgerCounts;
  const body = attempt?.body;
  const valid = reference.phase === 'bootstrap' && reference.liveStartedAt &&
    primary?.cluster?.id === M6_C1 && secondary?.cluster?.id === M6_C2 && otherFixture?.workspace?.id &&
    reference.consoleAdministrator?.user?.id && attempt?.actorId === reference.consoleAdministrator.user.id &&
    reference.accounts?.['approver-only']?.session && reference.accounts?.['approver-c2']?.session &&
    primary.settings && secondary.settings && otherFixture.settings &&
    primary.services?.length === 3 && primary.routes?.length === 3 && primary.publications?.length === 2 &&
    secondary.services?.length === 1 && secondary.routes?.length === 1 && secondary.publications?.length === 1 &&
    !(reference.portalUsers?.length) && !(reference.grants?.length) && attempts.length === 1 &&
    attempt === reference.writeAttempts.at(-1) && attempt.state === 'response_observed' &&
    attempt.httpStatus === 403 && attempt.errorCode === 'KONG_ENDPOINT_FORBIDDEN' &&
    attempt.path === `/api/v1/clusters/${M6_C1}/portal/publications/${first?.id}/publish` &&
    attempt.clusterId === M6_C1 && attempt.workspaceId === primary.workspace.id &&
    new URLSearchParams(attempt.query).get('workspaceId') === primary.workspace.id &&
    Object.keys(body ?? {}).sort().join(',') === 'confirm_name,confirmed,revision' &&
    body.revision === 2 && body.confirmed === true && body.confirm_name === first.name &&
    proof.readOnly === true && proof.clusterId === M6_C1 && proof.workspaceId === primary.workspace.id &&
    proof.publicationId === first.id && proof.requestId === attempt.requestId &&
    proof.operationsStatus === 200 && proof.operationsKind === 'not_sent' && proof.operationsState === 'not_sent' &&
    proof.publicationStatus === 'draft' && proof.publicationRevision === 2 && proof.noUnknowns === true &&
    counts?.workflows === 0 && counts.iam_operations === 0 && counts.native_operations === 0 && counts.unresolved === 0;
  if (!valid) throw new Error('M6 publication continuation checkpoint is incomplete or changed');
  const legacy = primary.services.find(row => row.name.endsWith('-legacy'));
  const legacyRecord = reference.fixtureJournal?.find(row => row.type === 'plugins' && row.name === 'key-auth' && row.clusterId === M6_C1 && row.workspaceId === primary.workspace.id);
  if (!legacy?.id || !legacyRecord?.id) throw new Error('M6 publication continuation legacy identity is missing');
  return { admin: reference.consoleAdministrator, clusters: [primary.cluster, secondary.cluster], fixtures: reference.fixtures, primary, secondary, otherFixture, approver: reference.accounts['approver-only'], secondaryApprover: reference.accounts['approver-c2'], legacy, legacyRecord, first, attempt };
}

export async function guardPublicationContinuation(h, proof) {
  h.requireLive();
  const state = publicationContinuationCheckpoint(h.referenceData, proof);
  const read = async path => h.ok(await h.request(state.admin, path), 'Continuation/CurrentFacts', 'read-only current checkpoint proof');
  await originalConsoleSession(h,state.admin);
  await originalConsoleSession(h,state.approver.session);
  await originalConsoleSession(h,state.secondaryApprover.session);
  for (const fixture of state.fixtures) {
    const cid = fixture.cluster.id, wid = fixture.workspace.id;
    const ws = await read(`/clusters/${cid}/workspaces/${wid}`);
    h.check(ws.id === wid && ws.code === fixture.workspace.code && ws.status === 'active' && ws.revision === fixture.workspace.revision, 'Continuation/Scope', 'original workspace identity and revision are unchanged');
    const settings = (await read(scope(`/clusters/${cid}/portal/settings`, wid))).settings;
    h.check(settings?.id === fixture.settings.id && settings.slug === fixture.slug && settings.published === true && settings.revision === fixture.settings.revision, 'Continuation/Settings', 'published tenant settings match the original actual object');
    for (const type of ['services', 'routes']) for (const saved of fixture[type]) {
      const actual = entity(await read(scope(`/clusters/${cid}/entities/${type}/${saved.id}`, wid)));
      h.check(actual.id === saved.id && actual.name === saved.name && (type === 'services' ? actual.host === saved.host && actual.port === saved.port && actual.protocol === saved.protocol : actual.service?.id === saved.service?.id && JSON.stringify(actual.paths) === JSON.stringify(saved.paths)), 'Continuation/NativeFacts', 'saved native Service/Route identity and configuration remain unchanged');
    }
    for (const publication of fixture.publications) {
      const actual = entity(await read(scope(`/clusters/${cid}/portal/publications/${publication.id}`, wid)));
      h.check(actual.id === publication.id && actual.status === 'draft' && actual.revision === publication.revision && actual.serviceId === publication.serviceId, 'Continuation/Publication', 'saved draft publication has not changed or executed');
    }
  }
  const plugin = entity(await read(scope(`/clusters/${M6_C1}/entities/plugins/${state.legacyRecord.id}`, state.primary.workspace)));
  h.check(plugin.id === state.legacyRecord.id && plugin.name === 'key-auth' && plugin.enabled === true && plugin.service?.id === state.legacy.id && !plugin.route && !plugin.consumer && !plugin.config?.anonymous, 'Continuation/Legacy', 'original legacy key-auth binding remains exact and enabled');
  const receipt = await read(scope(`/clusters/${M6_C1}/portal/operations/by-key/${state.attempt.key}`, state.primary.workspace));
  h.check(receipt.kind === 'not_sent' && receipt.state === 'not_sent', 'Continuation/Receipt', 'original key still has no sent workflow or metadata receipt');
  const counts = h.consoleRead(`SELECT (SELECT count(*)::int FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND idempotency_key=$3) AS workflows,(SELECT count(*)::int FROM iam_operations WHERE cluster_id=$1 AND workspace_id=$2 AND idempotency_key=$3) AS iam_operations,(SELECT count(*)::int FROM mutation_operations WHERE cluster_id=$1 AND request_id=$4) AS native_operations,(SELECT count(*)::int FROM mutation_operations WHERE cluster_id IN($1,$5) AND state IN('running','uncertain')) AS unresolved`, [M6_C1,state.primary.workspace.id,state.attempt.key,state.attempt.requestId,M6_C2])[0];
  h.check(counts?.workflows === 0 && counts.iam_operations === 0 && counts.native_operations === 0 && counts.unresolved === 0, 'Continuation/Ledger', 'fresh independent Console database proof confirms no original execution and no unresolved mutation');
  h.saveReference({ continuation: { phase: 'publication-known-not-sent', guardedAt: new Date().toISOString(), originalKey: state.attempt.key, originalRequestId: state.attempt.requestId } });
  return { ...state, legacyKeyAuth: plugin };
}
