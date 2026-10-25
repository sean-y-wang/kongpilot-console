/** Internal planning evidence. This is never a native execution capability or
 * an HTTP response DTO; callers seal it with their immutable change intent. */
export interface PreparedKongSchema {
  readonly version: 1;
  readonly clusterId: string;
  readonly canonicalPath: string;
  /** The Kong 1.5 DAO schema name (including credential DAO names). */
  readonly nativeType: string;
  readonly kongVersion: string;
  readonly adapter: 'kong-oss-1.5-v1';
  readonly clusterRevision: number;
  readonly schemaMaterial: KongWriteSchemaMaterial;
  readonly payloadHmac: string;
}
export interface KongWriteSchemaMaterial {
  readonly entity: { readonly name: string; readonly canonicalPath: string; readonly schema: unknown };
  readonly plugin?: { readonly name: string; readonly canonicalPath: string; readonly schema: unknown };
}
