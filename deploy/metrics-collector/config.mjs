import { readFileSync, statSync } from 'node:fs';
import { createHash, timingSafeEqual } from 'node:crypto';
import { CollectorError, isUuid } from './sanitize.mjs';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const DIGEST = /^[a-f0-9]{64}$/;
export const fingerprint = token => createHash('sha256').update(token, 'utf8').digest('hex');
export function matchesToken(token, digest) {
  if (typeof token !== 'string' || !TOKEN.test(token) || !DIGEST.test(digest || '')) return false;
  return timingSafeEqual(Buffer.from(fingerprint(token), 'hex'), Buffer.from(digest, 'hex'));
}
export function validateConfig(input) {
  const rows = Array.isArray(input) ? input : input?.clusters;
  if (!Array.isArray(rows) || rows.length > 32 || !rows.length) throw new CollectorError('COLLECTOR_CONFIGURATION_INVALID', 503);
  const seen = new Set();
  return rows.map(row => {
    if (!row || !isUuid(row.clusterId) || seen.has(row.clusterId) || !Number.isSafeInteger(row.generation) || row.generation < 1 || !TOKEN.test(row.catalogToken || '') || !DIGEST.test(row.ingestFingerprint || '') || !DIGEST.test(row.scrapeFingerprint || '') || row.ingestFingerprint === row.scrapeFingerprint || row.ingestFingerprint === fingerprint(row.catalogToken) || row.scrapeFingerprint === fingerprint(row.catalogToken)) throw new CollectorError('COLLECTOR_CONFIGURATION_INVALID', 503);
    seen.add(row.clusterId);
    return { clusterId: row.clusterId.toLowerCase(), generation: row.generation, catalogToken: row.catalogToken, ingestFingerprint: row.ingestFingerprint, scrapeFingerprint: row.scrapeFingerprint };
  });
}
export function readConfiguration(path = '/run/kongos-metrics/credentials.json') {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > 128 * 1024 || (stat.mode & 0o077) !== 0) throw new Error('invalid');
    return validateConfig(JSON.parse(readFileSync(path, 'utf8')));
  } catch { throw new CollectorError('COLLECTOR_CONFIGURATION_UNAVAILABLE', 503); }
}

export function authorization(request, type) {
  const count = request.rawHeaders.filter((_, index) => index % 2 === 0 && request.rawHeaders[index].toLowerCase() === 'authorization').length;
  if (count !== 1 || typeof request.headers.authorization !== 'string') return null;
  const value = request.headers.authorization;
  if (type === 'bearer') {
    const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(value);
    return match?.[1] || null;
  }
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) return null;
  const decoded = Buffer.from(match[1], 'base64').toString('utf8');
  if (Buffer.from(decoded, 'utf8').toString('base64') !== match[1]) return null;
  return /^kongos:([A-Za-z0-9_-]{43})$/.exec(decoded)?.[1] || null;
}
