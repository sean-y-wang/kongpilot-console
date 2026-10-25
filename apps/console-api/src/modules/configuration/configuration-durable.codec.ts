import { timingSafeEqual } from 'node:crypto';
import { canonicalJson, type SecretService } from '../../infrastructure/secret.service';
import { CONFIGURATION_DURABLE_DOMAIN, type DurableConfigurationEnvelope, type DurableConfigurationLocator, type DurableConfigurationSeal } from './configuration-durable.types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HMA = /^[0-9a-f]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const envelopeKeys = ['domain','envelopeVersion','issueId','clusterId','workspaceId','jobId','ownerId','authoringSessionId',
  'credentialEpoch','permissionVersion','issuedAt','admissionExpiresAt','expiresAt','policy','provenance','baseline','recipeHmac','schemaHmac','scopeHmac','plan'] as const;
const locatorKeys = ['domain','envelopeVersion','issueId','clusterId','workspaceId','jobId','planId','planRevision','planHash'] as const;
const invalid = () => new Error('DURABLE_CONFIGURATION_INVALID');
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== 'string' || !keys.includes(key))) throw invalid();
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}
function uuid(value: unknown): string { if (typeof value !== 'string' || !UUID.test(value)) throw invalid(); return value; }
function hma(value: unknown): string { if (typeof value !== 'string' || !HMA.test(value)) throw invalid(); return value; }
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) throw invalid();
  return value;
}
function timestamp(value: unknown): string {
  if (typeof value !== 'string' || !ISO.test(value)) throw invalid();
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) throw invalid();
  return value;
}
function permissionVersion(value: unknown, ownerId: string): string {
  if (typeof value !== 'string') throw invalid();
  const pieces = value.split(':');
  if (pieces.length !== 3 || pieces[0] !== ownerId || pieces.slice(1).some(piece => !/^[1-9]\d*$/.test(piece))) throw invalid();
  for (const piece of pieces.slice(1)) integer(Number(piece));
  return value;
}
function decodeLocator(value: unknown): DurableConfigurationLocator {
  const v = exact(value, locatorKeys);
  if (v.domain !== CONFIGURATION_DURABLE_DOMAIN || v.envelopeVersion !== 1) throw invalid();
  return Object.freeze({domain: CONFIGURATION_DURABLE_DOMAIN, envelopeVersion: 1, issueId: uuid(v.issueId), clusterId: uuid(v.clusterId),
    workspaceId: uuid(v.workspaceId), jobId: uuid(v.jobId), planId: uuid(v.planId), planRevision: integer(v.planRevision), planHash: hma(v.planHash)});
}
/** Pure decoding is not a capability, current SQL proof, SID proof or Native permit. */
export function decodeDurableConfigurationEnvelope(value: unknown, now = Date.now()): DurableConfigurationEnvelope {
  if (!Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) throw invalid();
  const v = exact(value, envelopeKeys);
  if (v.domain !== CONFIGURATION_DURABLE_DOMAIN || v.envelopeVersion !== 1) throw invalid();
  const policy = exact(v.policy, ['definitionId','version','hash','intentTtlHours']);
  const provenance = exact(v.provenance, ['jobId','planId','planRevision','planHash','kind']);
  const baseline = exact(v.baseline, ['snapshotId','version','manifestHmac']);
  const plan = exact(v.plan, ['planId','planRevision','planHash','stepsHmac','sourceManifestHmac','baselineManifestHmac']);
  if (provenance.kind !== 'import' && provenance.kind !== 'rollback') throw invalid();
  const ownerId = uuid(v.ownerId), issuedAt = timestamp(v.issuedAt), admissionExpiresAt = timestamp(v.admissionExpiresAt), expiresAt = timestamp(v.expiresAt);
  const intentTtlHours = integer(policy.intentTtlHours, 168);
  const issued = Date.parse(issuedAt), expires = Date.parse(expiresAt);
  if (expires <= issued || expires - issued > intentTtlHours * 3_600_000
    ||Date.parse(admissionExpiresAt)<=issued||Date.parse(admissionExpiresAt)>issued+300000||Date.parse(admissionExpiresAt)>expires) throw invalid();
  if (now < issued || now >= expires) throw new Error('DURABLE_CONFIGURATION_NOT_CURRENT');
  const decoded: DurableConfigurationEnvelope = {
    domain: CONFIGURATION_DURABLE_DOMAIN, envelopeVersion: 1, issueId: uuid(v.issueId), clusterId: uuid(v.clusterId),
    workspaceId: uuid(v.workspaceId), jobId: uuid(v.jobId), ownerId, authoringSessionId: uuid(v.authoringSessionId),
    credentialEpoch: integer(v.credentialEpoch), permissionVersion: permissionVersion(v.permissionVersion, ownerId), issuedAt, admissionExpiresAt, expiresAt,
    policy: Object.freeze({definitionId: uuid(policy.definitionId), version: integer(policy.version), hash: hma(policy.hash), intentTtlHours}),
    provenance: Object.freeze({jobId: uuid(provenance.jobId), planId: uuid(provenance.planId), planRevision: integer(provenance.planRevision),
      planHash: hma(provenance.planHash), kind: provenance.kind}),
    baseline: Object.freeze({snapshotId: uuid(baseline.snapshotId), version: integer(baseline.version), manifestHmac: hma(baseline.manifestHmac)}),
    recipeHmac: hma(v.recipeHmac), schemaHmac: hma(v.schemaHmac), scopeHmac: hma(v.scopeHmac),
    plan: Object.freeze({planId: uuid(plan.planId), planRevision: integer(plan.planRevision), planHash: hma(plan.planHash),
      stepsHmac: hma(plan.stepsHmac), sourceManifestHmac: hma(plan.sourceManifestHmac), baselineManifestHmac: hma(plan.baselineManifestHmac)}),
  };
  if (decoded.baseline.manifestHmac !== decoded.plan.baselineManifestHmac) throw invalid();
  return Object.freeze(decoded);
}
export function durableConfigurationLocator(envelope: DurableConfigurationEnvelope): DurableConfigurationLocator {
  return decodeLocator({domain: envelope.domain, envelopeVersion: envelope.envelopeVersion, issueId: envelope.issueId,
    clusterId: envelope.clusterId, workspaceId: envelope.workspaceId, jobId: envelope.jobId, planId: envelope.plan.planId,
    planRevision: envelope.plan.planRevision, planHash: envelope.plan.planHash});
}
/** The caller must supply the exact locator from its trusted SQL binding. */
export function durableConfigurationAad(locator: unknown): string {
  return `configuration-durable-envelope:v1:${canonicalJson(decodeLocator(locator))}`;
}
function sameLocator(envelope: DurableConfigurationEnvelope, locator: DurableConfigurationLocator): void {
  if (canonicalJson(durableConfigurationLocator(envelope)) !== canonicalJson(locator)) throw new Error('DURABLE_CONFIGURATION_BINDING_INVALID');
}
export class ConfigurationDurableCodec {
  constructor(private readonly secrets: SecretService) {}
  seal(value: unknown, expectedLocator: unknown, now = Date.now()): DurableConfigurationSeal {
    const envelope = decodeDurableConfigurationEnvelope(value, now), locator = decodeLocator(expectedLocator);
    sameLocator(envelope, locator);
    // Domain is part of the exact plaintext and the AEAD AAD. No legacy codec fallback.
    return Object.freeze({ciphertext: this.secrets.encrypt(envelope, durableConfigurationAad(locator)), materialHmac: this.secrets.fingerprint(envelope)});
  }
  open(value: unknown, expectedLocator: unknown, now = Date.now()): DurableConfigurationEnvelope {
    const seal = exact(value, ['ciphertext','materialHmac']), locator = decodeLocator(expectedLocator);
    const expectedHmac = hma(seal.materialHmac);
    if (typeof seal.ciphertext !== 'string' || seal.ciphertext.length > 131_072) throw invalid();
    let plaintext: unknown;
    try { plaintext = this.secrets.decrypt(seal.ciphertext, durableConfigurationAad(locator)); }
    catch { throw new Error('DURABLE_CONFIGURATION_SEAL_INVALID'); }
    const envelope = decodeDurableConfigurationEnvelope(plaintext, now);
    sameLocator(envelope, locator);
    const actualHmac = this.secrets.fingerprint(envelope);
    if (!timingSafeEqual(Buffer.from(actualHmac, 'hex'), Buffer.from(expectedHmac, 'hex'))) throw new Error('DURABLE_CONFIGURATION_SEAL_INVALID');
    return envelope;
  }
}
