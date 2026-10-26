export const entityTypes = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'] as const;
export type EntityType = typeof entityTypes[number];
export const entityLabels: Record<string, string> = { services: 'Services', routes: 'Routes', consumers: 'Consumers', plugins: 'Plugins', upstreams: 'Upstreams', certificates: 'Certificates', ca_certificates: 'CA Certificates', snis: 'SNIs' };
export const entityDescriptions: Record<string, string> = { services: '配置上游服务的连接、协议与超时，查看关联 Routes 和 Plugins。', routes: '管理请求匹配规则，连接 Service 并配置路由范围的插件。', consumers: '管理调用方身份、插件与六类认证凭证。', plugins: '管理全局、Service、Route 与 Consumer 范围的插件实例。', upstreams: '管理负载均衡算法、哈希配置、健康检查与 Targets。', certificates: '管理 PEM 证书和私钥，绑定 SNI 并检查证书到期时间。', ca_certificates: '管理受信任的 CA 证书。可用字段以当前 Kong schema 为准。', snis: '将 TLS 主机名称绑定到 Kong 证书。' };
/** Human-facing name fields only — never invent a label from the ID. */
export function entityDisplayName(entity: any): string | undefined {
  const value = entity?.name || entity?.username || entity?.target || entity?.client_id;
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
/** Confirm / title fallback: prefer a real name, else the raw ID (not abbreviated). */
export function entityName(entity: any) { return entityDisplayName(entity) || entity?.id || '未命名实体'; }
export function isEntityType(value?: string): value is EntityType { return entityTypes.includes(value as EntityType); }
export function entityTime(value?: number | string) { return value ? new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString('zh-CN', { hour12: false }) : '—'; }
export interface EntityPageData { items: any[]; nextCursor: string | null; size: number; total: null; indexed?: boolean; observed_at?: string; sync_error?: string | null; availability?: 'available' | 'forbidden' | 'missing'; }
