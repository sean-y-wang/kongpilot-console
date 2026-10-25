/** No key is retained here. The UI owns the displayed value and clears it on invalidation. */
export class RevealLease {
  private generation = 0;
  begin() { return ++this.generation; }
  invalidate() { this.generation++; }
  accept(ticket: number, response: unknown, context: { credentialId: string; credentialGeneration: number; originalActorId?: string; currentActorId?: string; active: boolean; visible: boolean }, now = Date.now()): { key: string; expiresAt: string } | undefined {
    const row = response as { credentialId?: string; key?: string; generation?: number; expiresAt?: string } | null;
    if (ticket !== this.generation || !context.active || !context.visible || !context.originalActorId || context.currentActorId !== context.originalActorId || !row || row.credentialId !== context.credentialId || row.generation !== undefined && row.generation !== context.credentialGeneration || typeof row.key !== 'string' || row.key.length === 0 || row.key.length > 8192) return undefined;
    const requestedExpiry = row.expiresAt === undefined ? now + 60_000 : Date.parse(row.expiresAt);
    if (!Number.isFinite(requestedExpiry) || requestedExpiry <= now) return undefined;
    return { key: row.key, expiresAt: new Date(Math.min(now + 60_000, requestedExpiry)).toISOString() };
  }
}
