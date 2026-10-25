import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { entity, scope } from './m7-harness.mjs';
import { auditPatchMatches } from './m7-audit-acceptance.mjs';

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const fullPageFields = ['id', 'cluster_id', 'workspace_id', 'slug', 'title', 'current_revision', 'published_revision', 'workflow_id', 'state', 'revision', 'created_by', 'updated_by', 'created_at', 'updated_at', 'deleted_at', 'retention_until'];
const privateAuditFields = ['sequence', 'eventHash', 'event_hash', 'prev_hash', 'prevHash', 'chainScope', 'chain_scope', 'sourceScope', 'sourceScopeHmac', 'history_scope', 'history_scope_hmac'];

// Passive helper only. The sole Security runner supplies the existing M7
// harness/sessions, which journals original keys and stops unknown writes.
// Markdown revisions are read through the page BFF. Terminal audits contain
// actual portal_content rows: title/current_revision attest their transition,
// rather than claiming that the separate markdown table is in that row.
export async function portalTerminalAuditAcceptance(h, actors) {
  const { admin, direct: area } = actors;
  h.check(uuid.test(area?.cid) && uuid.test(area?.wid) && uuid.test(admin?.user?.id), 'Portal terminal helper uses this runner named admin and exact fresh C1 workspace');
  const slug = `${h.state.testTag}-portal-audit-${randomUUID().slice(0, 8)}`;
  const title = `${h.state.testTag} Portal audit before`, markdown = '# M7 portal audit before\n\nFresh unpublished acceptance content.\n';
  const collection = scope(area.cid, area.wid, 'portal/pages');
  const create = await h.request(admin, collection, 'POST', { slug, title, markdown });
  const created = h.data(create), page = entity(created);
  h.check(uuid.test(page?.id) && page.slug === slug && page.title === title && page.state === 'draft' && page.documentRevision === null && Number.isSafeInteger(page.revision), 'fresh Portal page create returns an unpublished exact native-free metadata subject', { pageId: page.id });
  const fixture = { type: 'portal_pages', id: page.id, name: page.title, slug, revision: page.revision, ...area };
  h.state.fixtures.push(fixture); h.save();
  h.check(uuid.test(created.workflowId) && created.receipt?.state === 'succeeded', 'fresh Portal draft create has its actual completed metadata workflow receipt', { workflowId: created.workflowId });
  const workflow = h.data(await h.request(admin, scope(area.cid, area.wid, `workflows/${created.workflowId}`)));
  h.check(workflow.entity?.id === created.workflowId && workflow.entity.kind === 'portal-metadata' && workflow.entity.executionMode === 'direct' && workflow.entity.approvalRequired === false && workflow.entity.state === 'succeeded' && workflow.steps?.length === 1 && workflow.steps.every(step => step.kind === 'metadata' && step.state === 'succeeded' && !step.operationId && !step.recycleEntryId), 'actual Portal create workflow contains one completed metadata step and zero native steps');

  const path = scope(area.cid, area.wid, `portal/pages/${page.id}`);
  const before = h.data(await h.request(admin, path));
  h.check(isDeepStrictEqual(before.entity, page) && before.markdown === markdown, 'fresh Portal page before readback includes original title slug revision and exact Markdown');
  const nextTitle = `${h.state.testTag} Portal audit after`, nextMarkdown = '# M7 portal audit after\n\nUpdated unpublished acceptance content.\n';
  const patch = await h.request(admin, path, 'PATCH', { revision: before.entity.revision, slug: before.entity.slug, title: nextTitle, markdown: nextMarkdown });
  const changed = entity(h.data(patch));
  Object.assign(fixture, { name: changed.title, revision: changed.revision }); h.save();
  const after = h.data(await h.request(admin, path));
  h.check(uuid.test(patch.requestId) && isDeepStrictEqual(after.entity, changed) && changed.id === page.id && changed.slug === slug && changed.title === nextTitle && changed.revision === before.entity.revision + 1 && changed.state === 'draft' && changed.documentRevision === null && after.markdown === nextMarkdown && before.markdown !== after.markdown, 'Portal PATCH uses current CAS and preserves draft state while fresh readback proves new title and Markdown', { pageId: page.id, requestId: patch.requestId });

  const rows = []; let cursor;
  for (let index = 0; index < 12; index++) {
    const result = h.data(await h.request(admin, scope(area.cid, area.wid, 'audit', { requestId: patch.requestId, entityType: 'portal_content', entityId: page.id, result: 'success', size: 100, cursor })));
    h.check(Array.isArray(result?.items) && result.total === null && result.size === 100 && result.items.length <= 100, 'Portal exact original request audit query uses bounded server cursor');
    rows.push(...result.items);
    if (!result.nextCursor) break;
    h.check(index < 11 && typeof result.nextCursor === 'string', 'Portal precise audit query reaches actual EOF within bounded pages'); cursor = result.nextCursor;
  }
  h.check(rows.length === 2 && rows.filter(row => row.action === 'portal.page.draft').length === 1 && rows.filter(row => row.action === 'iam.write').length === 1, 'Portal direct metadata PATCH has exactly one business terminal and one IAM terminal', { pageId: page.id, count: rows.length });
  for (const row of rows) {
    h.check(uuid.test(row.id) && privateAuditFields.every(field => !Object.hasOwn(row, field)) && row.actorId === admin.user.id && row.actorType === 'user' && row.clusterId === area.cid && row.workspaceId === area.wid && row.entityType === 'portal_content' && row.entityId === page.id && row.result === 'success' && row.requestId === patch.requestId && row.workflowId === null && row.scopeQuality === 'verified' && Boolean(row.sourceIp), 'Portal terminal binds actual actor source IP request subject and immutable scope', { auditId: row.id, action: row.action });
    h.check(fullPageFields.every(field => Object.hasOwn(row.before ?? {}, field) && Object.hasOwn(row.after ?? {}, field)), 'Portal terminal retains complete actual locked before and fresh SQL readback fields', { auditId: row.id });
    for (const [record, readback] of [[row.before, before.entity], [row.after, after.entity]]) {
      h.check(record.id === page.id && record.cluster_id === area.cid && record.workspace_id === area.wid && record.slug === slug && record.title === readback.title && record.revision === readback.revision && record.state === readback.state && record.published_revision === readback.documentRevision && record.created_by === admin.user.id && record.updated_by === admin.user.id && record.deleted_at === null && record.retention_until === null && Number.isSafeInteger(record.current_revision) && record.current_revision > 0 && Number.isFinite(Date.parse(record.created_at)) && Number.isFinite(Date.parse(record.updated_at)), 'Portal full audited row agrees with independently fetched public page state', { auditId: row.id });
    }
    h.check(row.after.current_revision === row.before.current_revision + 1 && row.after.created_at === row.before.created_at && row.after.workflow_id === row.before.workflow_id && Date.parse(row.after.updated_at) >= Date.parse(row.before.updated_at), 'Portal audit preserves immutable row fields and records the actual content revision increment', { auditId: row.id });
    h.check(auditPatchMatches(row) && ['/title', '/revision', '/current_revision'].every(path => row.jsonPatch.some(operation => operation.path === path)), 'independent RFC6902 verification proves full Portal terminal patch with title and both revision changes', { auditId: row.id });
    h.check(!h.state.secrets.filter(value => value.length >= 8).some(value => JSON.stringify(row).includes(value)), 'Portal terminal audit exposes no captured credential');
    const detail = h.data(await h.request(admin, scope(area.cid, area.wid, `audit/${row.id}`)));
    h.check(isDeepStrictEqual(detail, row), 'Portal terminal audit detail equals exact request list result', { auditId: row.id });
  }
  h.check(isDeepStrictEqual(rows[0].before, rows[1].before) && isDeepStrictEqual(rows[0].after, rows[1].after) && isDeepStrictEqual(rows[0].jsonPatch, rows[1].jsonPatch), 'Portal business and IAM terminal share the same full actual SQL transition');

  // Complete this isolated fixture now. A rejected/unknown request propagates
  // without retry, new key, publish, restore or independent cleanup process.
  const archive = entity(h.data(await h.request(admin, path, 'DELETE', { revision: after.entity.revision, confirmed: true, confirm_name: after.entity.title })));
  h.check(archive.id === page.id && archive.state === 'deleted' && archive.documentRevision === null && archive.revision === after.entity.revision + 1, 'isolated unpublished Portal page is soft archived using actual current revision and typed title');
  const archived = h.data(await h.request(admin, path));
  h.check(isDeepStrictEqual(archived.entity, archive), 'Portal page soft archive is independently read back');
  Object.assign(fixture, { revision: archive.revision, archived: true }); h.save();
  const result = { pageId: page.id, workflowId: created.workflowId, requestId: patch.requestId, auditEventIds: rows.map(row => row.id), terminalAudits: rows.length, archived: true, published: false, nativeSteps: 0, fullBeforeAfterVerified: true, independentPatchVerified: true };
  h.public ??= {}; h.public.portalTerminalAudit = result;
  return result;
}
