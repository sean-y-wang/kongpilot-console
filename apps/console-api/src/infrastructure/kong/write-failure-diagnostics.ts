import { HttpException } from '@nestjs/common';

/** Keep the public unknown-result contract intact while retaining a bounded
 * internal cause. Never include error messages, stacks, bodies, URLs or keys. */
export function writeFailureDiagnostic(stage: 'native-policy-response' | 'sdk-response', clusterId: string,
  error: unknown, operationId?: string) {
  let code = 'UNCLASSIFIED_AUTHORIZATION_FAILURE';
  if (error instanceof HttpException) {
    const response = error.getResponse();
    const candidate = typeof response === 'object' && response !== null ? (response as { code?: unknown }).code : null;
    if (typeof candidate === 'string' && /^[A-Z][A-Z0-9_]{2,95}$/.test(candidate)) code = candidate;
  }
  const id = (value: unknown) => typeof value === 'string'
    && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value) ? value : null;
  return { event: 'kong_write_response_authorization_failed', stage, clusterId: id(clusterId),
    operationId: id(operationId), code, writeResult: 'unknown_requires_verification', retryAllowed: false };
}
