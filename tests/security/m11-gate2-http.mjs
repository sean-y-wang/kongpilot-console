import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {ReleaseHarness, releasePassword, releaseScope} from './lib/release-harness.mjs';
assert.equal(process.env.RELEASE_LAB_M11_GATE2_READY, 'true');
const h = new ReleaseHarness('M11', {resume: true});
h.reportPath = resolve('artifacts/M11/gate2-http-verification.json');
try {
  const admin = h.state.sessions.admin, cid = h.state.cid, wid = h.state.wid;
  const g = h.state.gate2 ??= {intents: {}, fixtures: {}}; h.save();
  const scope = suffix => releaseScope(cid, wid, suffix);
  const stage = process.argv[2] ?? 'prepare-core';
  if (stage === 'prepare-core') {
    const record = g.intents.create ??= {body: {change: {kind: 'entity', action: 'create', entityType: 'services',
      body: {name: `${h.state.tag}-durable-service`, protocol: 'http', host: 'echo', port: 8080, retries: 0,
        connect_timeout: 3000, read_timeout: 3000, write_timeout: 3000, tags: ['owner:m11-acceptance']}}}}; h.save();
    const result = (await h.once('m11-gate2-core-prepare', admin, scope('entity-changes/prepare'), 'POST', record.body)).data;
    record.id = result.id; record.receipt = result; h.save();
    assert.equal(result.review.impact.nativePackets, 1); assert.equal(result.nativeExecutionAvailable, false);
    assert.equal(Date.parse(result.expiresAt) - Date.parse(result.issuedAt), 24 * 3600000);
    const get = (await h.request(admin, scope(`entity-changes/${result.id}`))).data;
    assert.equal(get.materialHmac, result.materialHmac); assert.equal(get.workflowId, null);
    const nativeId = result.review.changes[0].nativeId;
    const absent = await h.request(admin, scope(`entities/services/${nativeId}`), 'GET', undefined, {expected: [404]});
    assert.equal(absent.status, 404);
    h.check(true, 'real create preparation persists a 24-hour immutable intent and allocates an ID without creating a Kong service', {intentId: result.id, nativeId});
  } else if (stage === 'submit-fresh-session') {
    const record = g.intents.create;
    const fresh = h.state.sessions['gate2-fresh-admin'] ?? await h.login('gate2-fresh-admin', admin.username, admin.password);
    assert.notEqual(fresh.sid, admin.sid); assert.equal(fresh.user.id, admin.user.id);
    record.submitBody ??= {revision: record.receipt.revision, materialHmac: record.receipt.materialHmac, confirmed: true, confirm_name: 'native-change'}; h.save();
    const result = (await h.once('m11-gate2-core-submit', fresh, scope(`entity-changes/${record.id}/submit`), 'POST', record.submitBody)).data;
    record.workflowId = result.workflowId; h.save(); assert(result.submissionCompleted);
    const view = (await h.request(fresh, scope(`workflows/${result.workflowId}`))).data.entity;
    assert.equal(view.kind, 'native-change'); assert.equal(view.capabilities.execute, false);
    const intent = (await h.request(fresh, scope(`entity-changes/${record.id}`))).data;
    assert.equal(intent.materialHmac, record.receipt.materialHmac); assert.equal(intent.expiresAt, record.receipt.expiresAt);
    assert.equal(intent.review.changes[0].nativeId, record.receipt.review.changes[0].nativeId);
    await h.once('m11-gate2-execution-closed', fresh, scope(`workflows/${result.workflowId}/execute`), 'POST',
      {revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: 'native-change'}, {expected: [409]});
    await h.request(fresh, scope(`entities/services/${record.receipt.review.changes[0].nativeId}`), 'GET', undefined, {expected: [404]});
    h.check(true, 'genuine new HTTP session submits the unchanged durable intent; ID, HMAC and deadline remain identical and native execution stays closed', {intentId: record.id, workflowId: result.workflowId});
  } else if (stage === 'native-fixtures') {
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data; assert.equal(cluster.execution_mode, 'direct');
    const tags = ['team:m11-acceptance', 'owner:m11-acceptance'];
    g.fixtures.service = (await h.once('m11-gate2-fixture-service', admin, scope('entities/services'), 'POST',
      {name: `${h.state.tag}-existing`, protocol: 'http', host: 'echo', port: 8080, tags})).data.entity; h.save();
    g.fixtures.route = (await h.once('m11-gate2-fixture-route', admin, scope('entities/routes'), 'POST',
      {name: `${h.state.tag}-existing-route`, service: {id: g.fixtures.service.id}, protocols: ['http'], hosts: [`${h.state.tag}.invalid`], paths: [`/${h.state.tag}`], tags})).data.entity; h.save();
    g.fixtures.consumer = (await h.once('m11-gate2-fixture-consumer', admin, scope('entities/consumers'), 'POST',
      {username: `${h.state.tag}-existing-consumer`, tags})).data.entity; h.save();
    g.fixtures.key ??= randomBytes(24).toString('hex'); h.save();
    g.fixtures.credential = (await h.once('m11-gate2-fixture-credential', admin, scope(`consumers/${g.fixtures.consumer.id}/credentials/key-auth`), 'POST',
      {key: g.fixtures.key, tags})).data.entity; h.save();
    g.fixtures.upstream = (await h.once('m11-gate2-fixture-upstream', admin, scope('entities/upstreams'), 'POST',
      {name: `${h.state.tag}-existing-upstream`, tags})).data.entity; h.save();
    g.fixtures.target = (await h.once('m11-gate2-fixture-target', admin, scope(`upstreams/${g.fixtures.upstream.id}/targets`), 'POST',
      {target: 'echo:8080', weight: 100, tags})).data.entity; h.save();
    h.check(true, 'explicit isolated native fixtures were created in direct mode for preparation tests; these are separate from intent execution', {fixtureNativeWrites: 6});
  } else if (stage === 'scoped-accounts') {
    const oldRole = (await h.request(admin, `/iam/roles/${h.state.gate1.roleId}`)).data;
    g.reviewerPermissionsBody ??= {revision: oldRole.revision, permissions: [
      ...['workflows', 'lint'].flatMap(module => ['read', 'approve'].map(action => ({module, action, scope_type: 'workspace', scope_values: [wid], cluster_id: cid, workspace_id: wid}))),
      ...['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'].map(module => ({module, action: 'read', scope_type: 'workspace', scope_values: [wid], cluster_id: cid, workspace_id: wid}))
    ]}; h.save();
    await h.once('m11-gate2-reviewer-read-scopes', admin, `/iam/roles/${oldRole.id}/permissions`, 'PUT', g.reviewerPermissionsBody);
    g.accounts ??= {}; h.save();
    for (const [label, type, values] of [['tag-writer', 'tag_group', ['team:m11-acceptance']], ['credential-writer', 'entity', [{entity_type: 'key-auth', entity_id: g.fixtures.credential.id}]]]) {
      const account = g.accounts[label] ??= {username: `${h.state.tag}-${label}`, initialPassword: releasePassword(), password: releasePassword()}; h.save();
      const user = (await h.once(`m11-gate2-${label}-user`, admin, '/iam/users', 'POST', {username: account.username, password: account.initialPassword})).data;
      account.id = user.id; h.save();
      if (!h.state.sessions[label]) {
        const initial = h.state.sessions[`${label}-initial`] ?? await h.login(`${label}-initial`, account.username, account.initialPassword);
        await h.once(`m11-gate2-${label}-password`, initial, '/auth/me/password', 'POST',
          {revision: initial.user.revision, current_password: account.initialPassword, new_password: account.password, confirmed: true});
        await h.login(label, account.username, account.password);
      }
      const role = (await h.once(`m11-gate2-${label}-role`, admin, '/iam/roles', 'POST', {code: `${h.state.tag}-${label}`, name: `M11 ${label}`, cluster_id: cid, workspace_id: wid})).data;
      account.roleId = role.id; h.save();
      const modules = label === 'tag-writer' ? ['services', 'routes', 'workflows'] : ['consumers', 'workflows'];
      await h.once(`m11-gate2-${label}-permissions`, admin, `/iam/roles/${role.id}/permissions`, 'PUT',
        {revision: role.revision, permissions: modules.flatMap(module => ['read', 'write'].map(action => ({module, action, scope_type: type, scope_values: values, cluster_id: cid, workspace_id: wid})))});
      await h.once(`m11-gate2-${label}-bind`, admin, `/iam/users/${user.id}/role-bindings`, 'POST', {role_id: role.id, cluster_id: cid, workspace_id: wid});
      assert.equal(h.state.sessions[label].user.superAdmin, false);
    }
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data;
    g.approvalModeBody ??= {revision: cluster.revision, execution_mode: 'approval'}; h.save();
    await h.once('m11-gate2-approval-mode', admin, `/clusters/${cid}`, 'PATCH', g.approvalModeBody);
    h.check(true, 'real tag-group and credential-ID-only accounts are bound without superadmin or public parent permissions');
  } else if (stage === 'prepare-scoped') {
    const cases = [
      ['tag-update', h.state.sessions['tag-writer'], {kind: 'entity', action: 'update', entityType: 'services', entityId: g.fixtures.service.id, body: {read_timeout: 3100}}],
      ['credential-update', h.state.sessions['credential-writer'], {kind: 'credential', action: 'update', consumerId: g.fixtures.consumer.id, credentialKind: 'key-auth', credentialId: g.fixtures.credential.id,
        body: {key: g.newKey ??= randomBytes(24).toString('hex')}}],
      ['service-delete', admin, {kind: 'recycle', action: 'delete', entityType: 'services', entityId: g.fixtures.service.id, confirmed: true, confirm_name: g.fixtures.service.name}]
    ]; h.save();
    for (const [label, user, change] of cases) {
      const record = g.intents[label] ??= {body: {change}}; h.save();
      const result = (await h.once(`m11-gate2-${label}-prepare`, user, scope('entity-changes/prepare'), 'POST', record.body)).data;
      record.id = result.id; record.receipt = result; h.save();
      assert.equal(result.executionMode, 'approval'); assert.equal(result.nativeExecutionAvailable, false);
      const get = (await h.request(user, scope(`entity-changes/${result.id}`))).data;
      assert.equal(get.materialHmac, result.materialHmac);
      h.check(true, `${label}: actual scoped preparation and historical review succeed without executing the planned packets`, {intentId: result.id, plannedPackets: result.review.impact.nativePackets});
    }
    await h.request(h.state.sessions['credential-writer'], scope(`entities/consumers/${g.fixtures.consumer.id}`), 'GET', undefined, {expected: [403]});
    const readonly = await h.once('m11-gate2-approve-only-prepare-denied', h.state.sessions.a, scope('entity-changes/prepare'), 'POST',
      {change: cases[0][2]}, {expected: [403]}); assert.equal(readonly.status, 403);
    h.check(true, 'credential whitelist gives no public parent read and approval-only users cannot prepare writes');
  } else if (stage === 'submit-and-approve-scoped') {
    const cases = [['tag-update', h.state.sessions['tag-writer']], ['credential-update', h.state.sessions['credential-writer']], ['service-delete', admin]];
    const originalService = (await h.request(admin, scope(`entities/services/${g.fixtures.service.id}`))).data.entity;
    const originalRoute = (await h.request(admin, scope(`entities/routes/${g.fixtures.route.id}`))).data.entity;
    for (const [label, user] of cases) {
      const record = g.intents[label];
      record.submitBody ??= {revision: record.receipt.revision, materialHmac: record.receipt.materialHmac, confirmed: true, confirm_name: 'native-change'}; h.save();
      const result = (await h.once(`m11-gate2-${label}-submit`, user, scope(`entity-changes/${record.id}/submit`), 'POST', record.submitBody)).data;
      record.workflowId = result.workflowId; h.save(); assert(result.submissionCompleted);
      const view = (await h.request(user, scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(view.state, 'pending'); assert.equal(view.approvalRequired, true); assert.equal(view.capabilities.execute, false);
      record.approveBody ??= {revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: 'native-change', execute: false}; h.save();
      await h.once(`m11-gate2-${label}-approve`, h.state.sessions.a, scope(`workflows/${record.workflowId}/approve`), 'POST', record.approveBody);
      const approved = (await h.request(user, scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, false);
      await h.once(`m11-gate2-${label}-execute-closed`, user, scope(`workflows/${record.workflowId}/execute`), 'POST',
        {revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change'}, {expected: [409]});
      const intent = (await h.request(user, scope(`entity-changes/${record.id}`))).data;
      assert.equal(intent.materialHmac, record.receipt.materialHmac); assert.equal(intent.expiresAt, record.receipt.expiresAt);
      h.check(true, `${label}: real scoped submission and independent approval preserve the intent while native execution remains closed`, {intentId: record.id, workflowId: record.workflowId});
    }
    const serviceAfter = (await h.request(admin, scope(`entities/services/${g.fixtures.service.id}`))).data.entity;
    const routeAfter = (await h.request(admin, scope(`entities/routes/${g.fixtures.route.id}`))).data.entity;
    assert.deepEqual(serviceAfter, originalService); assert.deepEqual(routeAfter, originalRoute);
    h.check(true, 'service and dependent route remain unchanged after real approval and rejected execution requests');
  } else if (stage === 'restore-fixture') {
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data;
    g.restoreFixtureModeBody ??= {revision: cluster.revision, execution_mode: 'direct'}; h.save();
    await h.once('m11-gate2-restore-fixture-direct-mode', admin, `/clusters/${cid}`, 'PATCH', g.restoreFixtureModeBody);
    const deletion = (await h.once('m11-gate2-restore-fixture-archive-delete', admin, scope(`entities/upstreams/${g.fixtures.upstream.id}`), 'DELETE',
      {confirmed: true, confirm_name: g.fixtures.upstream.name})).data;
    g.restoreFixtureReceipt = deletion; h.save();
    const entryId = deletion.entryId ?? deletion.recycleEntryId ?? deletion.entry?.id;
    assert(entryId, 'The actual native delete must return its persisted recycle entry');
    g.restoreEntryId = entryId; h.save();
    await h.request(admin, scope(`entities/upstreams/${g.fixtures.upstream.id}`), 'GET', undefined, {expected: [404]});
    const direct = (await h.request(admin, `/clusters/${cid}`)).data;
    g.restorePrepareModeBody ??= {revision: direct.revision, execution_mode: 'approval'}; h.save();
    await h.once('m11-gate2-restore-prepare-approval-mode', admin, `/clusters/${cid}`, 'PATCH', g.restorePrepareModeBody);
    h.check(true, 'the isolated upstream/target fixture was actually archived and deleted through the existing direct-mode recycle workflow', {entryId, intentExecution: false});
  } else if (stage === 'prepare-restore') {
    const record = g.intents.restore ??= {body: {change: {kind: 'recycle', action: 'restore', entryId: g.restoreEntryId,
      confirmed: true, confirm_name: g.fixtures.upstream.name}}}; h.save();
    const result = (await h.once('m11-gate2-restore-prepare', admin, scope('entity-changes/prepare'), 'POST', record.body)).data;
    record.id = result.id; record.receipt = result; h.save();
    assert.equal(result.executionMode, 'approval'); assert.equal(result.nativeExecutionAvailable, false);
    assert.equal(result.review.impact.nativePackets, 2);
    const get = (await h.request(admin, scope(`entity-changes/${result.id}`))).data;
    assert.equal(get.materialHmac, result.materialHmac);
    await h.request(admin, scope(`entities/upstreams/${g.fixtures.upstream.id}`), 'GET', undefined, {expected: [404]});
    h.check(true, 'real restore preparation seals the persisted upstream and target graph without recreating either native object', {intentId: result.id, entryId: g.restoreEntryId, plannedPackets: 2});
  } else if (stage === 'restore-submit-and-scope-denials') {
    const record = g.intents.restore;
    record.submitBody ??= {revision: record.receipt.revision, materialHmac: record.receipt.materialHmac, confirmed: true, confirm_name: 'native-change'}; h.save();
    const submitted = (await h.once('m11-gate2-restore-submit', admin, scope(`entity-changes/${record.id}/submit`), 'POST', record.submitBody)).data;
    record.workflowId = submitted.workflowId; h.save();
    const view = (await h.request(admin, scope(`workflows/${record.workflowId}`))).data.entity;
    record.approveBody ??= {revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: 'native-change', execute: false}; h.save();
    await h.once('m11-gate2-restore-approve', h.state.sessions.a, scope(`workflows/${record.workflowId}/approve`), 'POST', record.approveBody);
    const approved = (await h.request(admin, scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(approved.state, 'approved'); assert.equal(approved.capabilities.execute, false);
    await h.once('m11-gate2-restore-execute-closed', admin, scope(`workflows/${record.workflowId}/execute`), 'POST',
      {revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change'}, {expected: [409]});
    await h.request(admin, scope(`entities/upstreams/${g.fixtures.upstream.id}`), 'GET', undefined, {expected: [404]});
    h.check(true, 'persisted upstream/target restore reaches independent approval and still cannot create native objects before the execution adapter is enabled', {intentId: record.id, workflowId: record.workflowId});
    const m10 = JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m10-harness.json'));
    assert.equal(m10.targetCid, cid); assert.notEqual(m10.targetWid, wid);
    await h.once('m11-gate2-tag-removal-denied', h.state.sessions['tag-writer'], scope('entity-changes/prepare'), 'POST',
      {change: {kind: 'entity', action: 'update', entityType: 'services', entityId: g.fixtures.service.id, body: {tags: ['team:other', 'owner:m11-acceptance']}}}, {expected: [403]});
    await h.once('m11-gate2-foreign-workspace-service-denied', h.state.sessions['tag-writer'], scope('entity-changes/prepare'), 'POST',
      {change: {kind: 'entity', action: 'update', entityType: 'services', entityId: m10.fixtures.target.service.id, body: {read_timeout: 4100}}}, {expected: [403, 404]});
    await h.once('m11-gate2-foreign-credential-denied', h.state.sessions['credential-writer'], scope('entity-changes/prepare'), 'POST',
      {change: {kind: 'credential', action: 'update', consumerId: m10.fixtures.target.consumer.id, credentialKind: 'key-auth', credentialId: m10.fixtures.target.credential.id,
        body: {key: g.newKey}}}, {expected: [403, 404]});
    await h.request(h.state.sessions['tag-writer'], releaseScope(cid, m10.targetWid, `entity-changes/${g.intents['tag-update'].id}`), 'GET', undefined, {expected: [403, 404]});
    h.check(true, 'real tag removal, foreign workspace entity, foreign credential and intent scope attacks are denied using existing objects');
  } else if (stage === 'close-gate2') {
    for (const [label, user] of [['create', h.state.sessions['gate2-fresh-admin']], ['tag-update', h.state.sessions['tag-writer']],
      ['credential-update', h.state.sessions['credential-writer']], ['service-delete', admin], ['restore', admin]]) {
      const record = g.intents[label];
      const view = (await h.request(user, scope(`workflows/${record.workflowId}`))).data.entity;
      assert(['pending', 'approved'].includes(view.state));
      record.cancelBody ??= {revision: view.revision, confirmed: true, confirm_name: 'native-change'}; h.save();
      await h.once(`m11-gate2-${label}-cancel`, user, scope(`workflows/${record.workflowId}/cancel`), 'POST', record.cancelBody);
      const cancelled = (await h.request(user, scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(cancelled.state, 'cancelled');
    }
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data;
    g.closeModeBody ??= {revision: cluster.revision, execution_mode: 'direct'}; h.save();
    await h.once('m11-gate2-restore-original-direct-mode', admin, `/clusters/${cid}`, 'PATCH', g.closeModeBody);
    const result = (await h.once('m11-gate2-restore-own-fixture-direct', admin, scope(`recycle-bin/${g.restoreEntryId}/restore`), 'POST',
      {confirmed: true, confirm_name: g.fixtures.upstream.name})).data;
    g.restoreFixtureFinalReceipt = result; h.save();
    const upstream = (await h.request(admin, scope(`entities/upstreams/${g.fixtures.upstream.id}`))).data.entity;
    assert.equal(upstream.id, g.fixtures.upstream.id); assert.equal(upstream.name, g.fixtures.upstream.name);
    const targets = (await h.request(admin, scope(`upstreams/${g.fixtures.upstream.id}/targets`))).data;
    assert(targets.items.some(target => target.id === g.fixtures.target.id && target.target === g.fixtures.target.target && target.weight === g.fixtures.target.weight));
    await h.request(admin, scope(`entities/services/${g.intents.create.receipt.review.changes[0].nativeId}`), 'GET', undefined, {expected: [404]});
    h.check(true, 'all five Gate2 native-change workflows are cancelled without execution; original direct mode and own upstream/target fixture are restored through actual existing recycle execution', {cancelledWorkflows: 5, originalIdsRestored: true});
  } else throw Error('UNKNOWN_GATE2_STAGE');
  h.state.phase = `m11-gate2-${stage}-complete`; h.save(); h.report(true);
  console.log(JSON.stringify({passed: true, phase: h.state.phase, checks: h.state.checks.length, overallAcceptance: false}));
} catch (error) {
  h.state.phase = 'm11-gate2-stopped'; h.save(); h.report(false, 'M11_GATE2_HTTP_STOPPED');
  console.error(JSON.stringify({passed: false, message: String(error.message).slice(0, 500)})); process.exitCode = 1;
}
