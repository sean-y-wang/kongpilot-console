import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

export type ConnectionAuth = { type: 'none' | 'bearer' | 'basic' | 'header'; token?: string; username?: string; password?: string; header_name?: string; header_value?: string };

export function validateOutboundUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new BadRequestException({ code: 'INVALID_CONNECTION_URL', message: '连接地址必须是有效的 HTTP(S) URL' }); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || /%2f|%5c|%00/i.test(url.pathname) || url.hostname.endsWith('.')) {
    throw new BadRequestException({ code: 'INVALID_CONNECTION_URL', message: '连接地址不得包含用户信息、查询参数、片段或编码分隔符' });
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const rules = (process.env.OUTBOUND_ALLOWED_HOSTS || 'kong,prometheus,loki').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const allowed = rules.some(rule => rule === host || rule === `${host}:${url.port || (url.protocol === 'https:' ? '443' : '80')}` || (rule.startsWith('*.') && host.endsWith(rule.slice(1)) && host !== rule.slice(2)));
  if (!allowed) throw new ForbiddenException({ code: 'OUTBOUND_HOST_FORBIDDEN', message: '目标主机不在 OUTBOUND_ALLOWED_HOSTS 允许列表内' });
  return url;
}

export function authHeaders(auth?: ConnectionAuth | null): Record<string, string> {
  if (!auth || auth.type === 'none') return {};
  if (auth.type === 'bearer') return { Authorization: `Bearer ${auth.token}` };
  if (auth.type === 'basic') return { Authorization: `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}` };
  const name = auth.header_name || '';
  if (!/^[a-zA-Z0-9-]+$/.test(name) || /^(host|connection|content-length|transfer-encoding|cookie|accept|user-agent)$/i.test(name)) {
    throw new BadRequestException({ code: 'INVALID_AUTH_HEADER', message: '认证 Header 名称无效' });
  }
  return { [name]: auth.header_value || '' };
}

function prohibitedAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  // Reject mapped IPv6 entirely: its hexadecimal form can conceal link-local IPv4.
  return normalized.startsWith('::ffff:') || normalized === '0.0.0.0' || normalized === '::' || normalized.startsWith('169.254.') || normalized.startsWith('fe80:') || normalized.startsWith('ff') || /^22[4-9]\.|^23\d\./.test(normalized);
}

/** Resolve once and pin that address for this connection. Redirects are never followed. */
async function outboundRaw(base: string, path: string, method = 'GET', body?: unknown, query: Record<string, string | number> = {}, auth?: ConnectionAuth | null, timeoutMs = 5000, beforeSend?: () => void, prepareSend?: () => Promise<void>, maxResponseBytes = 8 * 1024 * 1024, accept = 'application/json'): Promise<{ status: number; body: string; bytes: number }> {
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 8 * 1024 * 1024) throw new BadRequestException({ code: 'INVALID_RESPONSE_BUDGET', message: '响应预算无效' });
  const baseUrl = validateOutboundUrl(base);
  const target = new URL(baseUrl.toString());
  target.pathname = `${baseUrl.pathname.replace(/\/$/, '')}${path}` || '/';
  Object.entries(query).forEach(([key, value]) => target.searchParams.set(key, String(value)));
  const host = target.hostname.replace(/^\[|\]$/g, '');
  let dnsTimer: NodeJS.Timeout | undefined;
  const resolved = isIP(host) ? [{ address: host, family: isIP(host) }] : await Promise.race([
    lookup(host, { all: true }),
    new Promise<never>((_resolve, reject) => { dnsTimer = setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEDOUT' })), timeoutMs); }),
  ]).finally(() => { if (dnsTimer) clearTimeout(dnsTimer); });
  if (!resolved.length || resolved.some(entry => prohibitedAddress(entry.address))) throw new ForbiddenException({ code: 'OUTBOUND_ADDRESS_FORBIDDEN', message: '目标地址不允许访问' });
  const pinned = resolved[0];
  const serialized = body === undefined ? undefined : JSON.stringify(body);
  const headers = { Accept: accept, 'User-Agent': 'KongPilot/0.1', ...authHeaders(auth), ...(serialized === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(serialized)) }) };
  // Writes can spend time resolving DNS. Revalidate durable execution and
  // current grants after that wait, then use the synchronous fence below.
  await prepareSend?.();
  return new Promise((resolve, reject) => {
    // DNS may have awaited beyond the outer mutation callback's lifetime.
    // Keep the trusted guard and the HTTP send in the same synchronous turn.
    beforeSend?.();
    // DNS has its own bounded resolution budget. Durable permission/graph
    // preparation is fenced by the caller's live execution context, not the
    // socket timer: no network request exists while that callback is awaited.
    // Start the unchanged network budget only after preparation and the final
    // synchronous guard both succeed; never retry or extend the outer lease.
    const deadline = Date.now() + timeoutMs;
    const request = (target.protocol === 'https:' ? httpsRequest : httpRequest)(target, { method, headers, lookup: ((_hostname: any, options: any, callback: any) => options?.all ? callback(null, [{ address: pinned.address, family: pinned.family }]) : callback(null, pinned.address, pinned.family)) as any }, response => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > maxResponseBytes) { request.destroy(Object.assign(new Error('Response exceeds size limit'), { code: 'RESPONSE_TOO_LARGE' })); return; }
        chunks.push(Buffer.from(chunk));
      });
      response.on('error', reject);
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: response.statusCode || 502, body: text, bytes: size });
      });
    });
    const timer = setTimeout(() => request.destroy(Object.assign(new Error('Upstream timeout'), { code: 'ETIMEDOUT' })), Math.max(1, deadline - Date.now()));
    request.on('close', () => clearTimeout(timer));
    request.on('error', reject);
    if (serialized !== undefined) request.write(serialized);
    request.end();
  });
}

export async function outboundJson(base: string, path: string, method = 'GET', body?: unknown, query: Record<string, string | number> = {}, auth?: ConnectionAuth | null, timeoutMs = 5000, beforeSend?: () => void, prepareSend?: () => Promise<void>, maxResponseBytes = 8 * 1024 * 1024): Promise<{ status: number; body: any; bytes: number; readonly jsonParsed:boolean }> {
  const result = await outboundRaw(base, path, method, body, query, auth, timeoutMs, beforeSend, prepareSend, maxResponseBytes);
  let parsed: any,jsonParsed=false;
  try { parsed = result.body.length ? JSON.parse(result.body) : null; jsonParsed=result.body.length>0; } catch { parsed = { message: '上游返回非 JSON 响应' }; }
  const response={ ...result, body: parsed };
  // Preserve the existing enumerable result for all consumers and logs. Only
  // the original transport response exposes this immutable parsing evidence.
  Object.defineProperty(response,'jsonParsed',{value:jsonParsed,writable:false,enumerable:false,configurable:false});
  return response as typeof response&{readonly jsonParsed:boolean};
}

/** Text is never interpreted as JSON; transport protection is identical. */
export async function outboundText(base: string, path: string, auth?: ConnectionAuth | null, timeoutMs = 5000, beforeSend?: () => void, maxResponseBytes = 2 * 1024 * 1024): Promise<{ status: number; body: string; bytes: number }> {
  return outboundRaw(base, path, 'GET', undefined, {}, auth, timeoutMs, beforeSend, undefined, maxResponseBytes, 'text/plain; version=0.0.4');
}
