import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { EventCursor, eventConfirm, eventId, eventNativeType, eventObject, eventTags } from '../../apps/console-api/src/modules/events/events-input';
import { decodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
beforeEach(()=>vi.stubEnv('CURSOR_SIGNING_KEY','event-cursor-test-key-'.repeat(3)));afterEach(()=>vi.unstubAllEnvs());
describe('M7 strict shared metadata inputs and scope-bound keyset cursors',()=>{
  it.each(['workspace:pay','kos-ws-pay'])('rejects reserved workspace filter %s',tag=>expect(()=>eventTags([tag])).toThrow());
  it('encodes logical business tags exactly once, retaining their decode identity',()=>{
    const physical=eventTags(['team:支付','owner:alice','team:支付']);expect(physical).toHaveLength(2);expect(physical.map(decodeTag).sort()).toEqual(['owner:alice','team:支付'].sort());
  });
  it('refuses mutable prototype objects, nested pollution fields, foreign actor fields and oversized bodies',()=>{
    expect(()=>eventObject(Object.create({endpoint:'hidden'}),['endpoint'])).toThrow();
    expect(()=>eventObject(JSON.parse('{"endpoint":{"__proto__":{"role":"admin"}}}'),['endpoint'])).toThrow();
    expect(()=>eventObject({endpoint:'allowed',actorId:randomUUID()},['endpoint'])).toThrow();
    expect(()=>eventObject({endpoint:'x'.repeat(65536)},['endpoint'])).toThrow();
    expect(()=>eventObject({endpoint:Object.create({secret:'inherited'})},['endpoint'])).toThrow();
    expect(()=>eventObject({endpoint:new Date()},['endpoint'])).toThrow();
  });
  it('accepts the actual Nest platform Express query parser without losing its scope or strict fields',()=>{
    const require=createRequire(new URL('../../apps/console-api/package.json',import.meta.url)),platformPath=require.resolve('@nestjs/platform-express');
    const express=createRequire(platformPath)('express'),app=express();app.lazyrouter?.();
    // Express 5 initializes defaults when the application is created.
    const parser=app.get('query parser fn'),wid=randomUUID(),query=parser(`workspaceId=${wid}&size=20`);
    expect(Object.getPrototypeOf(query)).toBeNull();
    expect(eventObject(query,['workspaceId','size'])).toEqual({workspaceId:wid,size:'20'});
    expect(()=>eventObject(parser(`workspaceId=${wid}&actorId=${randomUUID()}`),['workspaceId'])).toThrow();
    expect(()=>eventObject(parser('constructor=admin'),['constructor'])).toThrow();
  });
  it.each(['vaults','credentials','notification_channels','event_subscriptions','keys'])('rejects %s as a typed native filter',type=>expect(()=>eventNativeType(type)).toThrow());
  it.each(['services','targets','key-auth','oauth2','acls'])('accepts explicit native kind %s',type=>expect(eventNativeType(type)).toBe(type));
  it('typed name confirmation is exact and cannot be a truthy client string',()=>{
    expect(()=>eventConfirm({revision:2,confirmed:'true',confirm_name:'payments'},'payments')).toThrow();
    expect(()=>eventConfirm({revision:2,confirmed:true,confirm_name:'other'},'payments')).toThrow();
    expect(()=>eventConfirm({revision:2,confirmed:true,confirm_name:'payments'},'payments')).not.toThrow();
  });
  it('preserves PostgreSQL microseconds and original time lower bound across next-page cursors',()=>{
    const cursor=new EventCursor(),position={id:randomUUID(),createdAt:'2026-10-11T06:00:00.123456Z',lowerBound:'2026-10-04T06:00:00.123Z'};
    expect(cursor.decode(cursor.encode('actor-cid-wid-v1-filters-size',position),'actor-cid-wid-v1-filters-size')).toEqual(position);
  });
  it.each(['other-actor','other-cluster','other-workspace','revoked-permission-version','different-filter','different-size'])('rejects cursor reuse under %s binding',binding=>{
    const cursor=new EventCursor(),value=cursor.encode('original',{id:randomUUID(),createdAt:new Date().toISOString()});expect(()=>cursor.decode(value,binding)).toThrow();
  });
  it('rejects tampered, expired and malformed keyset positions',()=>{
    const cursor=new EventCursor(),value=cursor.encode('original',{id:randomUUID(),createdAt:new Date().toISOString()});
    expect(()=>cursor.decode(value+'extra','original')).toThrow();vi.spyOn(Date,'now').mockReturnValue(Date.now()+900001);expect(()=>cursor.decode(value,'original')).toThrow();vi.restoreAllMocks();
    expect(()=>cursor.encode('original',{id:randomUUID(),createdAt:'2026-10-11 06:00:00+00'})).toThrow();expect(()=>eventId('../foreign')).toThrow();
  });
});
