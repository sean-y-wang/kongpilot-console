import { BadGatewayException } from '@nestjs/common';
import { createHash } from 'node:crypto';

/** Same registered Admin endpoint uses one physical transport budget and lock.
 * Arbitrary DNS aliases require an explicitly shared registered scope; DNS IPs
 * are not stable identities and reverse proxies can share IPs across clusters. */
export function transportScopeFor(adminUrl: string, registeredScope?: string | null): string {
  if (registeredScope != null) {
    if (!/^[a-f0-9]{64}$/.test(registeredScope)) throw new BadGatewayException({ code: 'INVALID_TRANSPORT_SCOPE', message: '集群物理连接作用域配置无效' });
    return registeredScope;
  }
  let url: URL;
  try { url = new URL(adminUrl); } catch { throw new BadGatewayException({ code: 'INVALID_ADMIN_ENDPOINT', message: '集群管理连接地址无效' }); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new BadGatewayException({ code: 'INVALID_ADMIN_ENDPOINT', message: '集群管理连接地址无效' });
  const path = url.pathname.replace(/\/+$/, '') || '/';
  return createHash('sha256').update(`${url.protocol}//${url.hostname.toLowerCase()}:${url.port || (url.protocol === 'https:' ? '443' : '80')}${path}`).digest('hex');
}
