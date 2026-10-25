import { BadRequestException } from '@nestjs/common';

const factoryImmutableRoots = new WeakSet<object>();

/** Provenance for deterministic computation only; never an authority proof.
 * Neither a deep-frozen lookalike nor a child/Proxy can register itself. */
export function isFactoryImmutableJson(value: unknown): value is object {
  return value !== null && typeof value === 'object' && factoryImmutableRoots.has(value);
}

/** Authorization and transport must observe the same JSON, even when the
 * caller keeps a reference and changes it while an async policy check awaits. */
export function immutableJson<T>(value: T): T {
  if (value === undefined) return value;
  let encoded: string | undefined;
  try { encoded = JSON.stringify(value); } catch { throw new BadRequestException({ code: 'INVALID_KONG_BODY', message: '网关请求必须为可序列化的 JSON' }); }
  if (encoded === undefined || Buffer.byteLength(encoded, 'utf8') > 32 * 1024 * 1024) throw new BadRequestException({ code: 'INVALID_KONG_BODY', message: '网关请求 JSON 无效或超过大小限制' });
  const copy = JSON.parse(encoded);
  const freeze = (node: any): any => {
    if (node && typeof node === 'object') { for (const child of Object.values(node)) freeze(child); Object.freeze(node); }
    return node;
  };
  const frozen = freeze(copy);
  // Publish provenance only after cloning and the entire freeze succeeded.
  if (frozen !== null && typeof frozen === 'object') factoryImmutableRoots.add(frozen);
  return frozen;
}
