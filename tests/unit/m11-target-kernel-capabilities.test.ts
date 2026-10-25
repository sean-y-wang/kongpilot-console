import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';

/** Current-material adapter for UI capability projection only. It proves no
 * genuine handle, native receipt, real approval or SQL/baseline authority. */
describe('M11 Target weight Kernel capability projection', () => {
  it('allows valid HTTP V1 append-weight while rejecting scheduled or malformed health packets', async () => {
    const upstream = randomUUID(), oldId = randomUUID(), newId = randomUUID();
    const packet: any = { key: 'target-weight', order: 1, dependencies: [], nativeType: 'targets', nativeId: newId, originalNativeId: oldId,
      parentId: upstream, canonicalPath: `/upstreams/${upstream}/targets`, method: 'POST', permissionAction: 'write', mutationAction: 'update',
      body: { id: newId, target: '192.0.2.10:8080', weight: 80, tags: [] },
      before: { id: oldId, target: '192.0.2.10:8080', weight: 100, tags: [], upstream: { id: upstream } } };
    const envelope: any = { version: 1, prepared: { packets: [packet], metadataObligations: [] } }, intents: any = { executionMaterial: vi.fn(async () => envelope) };
    const db: any = { one: vi.fn(), query: vi.fn(), exec: vi.fn() }, kong: any = { request: vi.fn() }, writer: any = { execute: vi.fn() };
    const kernel = new EntityChangeExecutionService(db, {} as any, {} as any, {} as any, kong, {} as any, {} as any, {} as any,
      {} as any, intents, {} as any, {} as any, writer, {} as any);
    const plan: any = {}, actor: any = { user: { id: randomUUID() } };
    expect(await kernel.canExecute(plan, actor)).toBe(true);
    envelope.version = 2; expect(await kernel.canExecute(plan, actor)).toBe(false); envelope.version = 1;
    packet.mutationAction = 'mark_healthy'; expect(await kernel.canExecute(plan, actor)).toBe(false);
    packet.mutationAction = 'mark_unhealthy'; expect(await kernel.canExecute(plan, actor)).toBe(false);
    expect(db.exec).not.toHaveBeenCalled(); expect(kong.request).not.toHaveBeenCalled(); expect(writer.execute).not.toHaveBeenCalled();
  });
  it('exposes typed HTTP health execution/preflight capability without pretending it grants native authority or reversible state',async()=>{
    const upstream=randomUUID(),id=randomUUID(),packet:any={key:'health',order:1,dependencies:[],nativeType:'targets',nativeId:id,parentId:upstream,
      canonicalPath:`/upstreams/${upstream}/targets/${id}/healthy`,method:'POST',permissionAction:'write',mutationAction:'mark_healthy',
      before:{id,target:'192.0.2.10:8080',weight:100,tags:[],upstream:{id:upstream},created_at:1}},
      envelope:any={version:1,prepared:{packets:[packet],metadataObligations:[]}},intents:any={executionMaterial:vi.fn(async()=>envelope)},
      db:any={one:vi.fn(),query:vi.fn(),exec:vi.fn()},kong:any={request:vi.fn()},writer:any={execute:vi.fn()},
      kernel=new EntityChangeExecutionService(db,{} as any,{} as any,{} as any,kong,{} as any,{} as any,{} as any,{} as any,intents,{} as any,{} as any,writer,{} as any);
    expect(await kernel.canExecute({} as any,{} as any)).toBe(true);expect(await kernel.canPreflight({} as any,{} as any)).toBe(true);
    expect(db.exec).not.toHaveBeenCalled();expect(kong.request).not.toHaveBeenCalled();expect(writer.execute).not.toHaveBeenCalled();
    envelope.version=2;expect(await kernel.canExecute({} as any,{} as any)).toBe(false);
  });
});
