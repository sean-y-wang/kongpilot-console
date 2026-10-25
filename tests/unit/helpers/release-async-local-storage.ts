import { AsyncLocalStorage } from 'node:async_hooks';
/** Suites that build a complete provider graph per case create many service-owned
 * AsyncLocalStorage instances. Once entered, Node keeps each instance on the
 * async-hook propagation list until disable(), so every later promise pays for
 * all earlier graphs. Call the returned function in afterEach to release them.
 * Test-only: production services are singletons. */
export function trackEnteredAsyncLocalStorage(): () => void {
  const entered = new Set<AsyncLocalStorage<unknown>>();
  const proto = AsyncLocalStorage.prototype as any;
  if (!proto.__kpTracked) {
    const run = proto.run, enter = proto.enterWith;
    proto.run = function (this: any, ...a: any[]) { proto.__kpSink?.add(this); return run.apply(this, a); };
    proto.enterWith = function (this: any, s: unknown) { proto.__kpSink?.add(this); return enter.call(this, s); };
    proto.__kpTracked = true;
  }
  proto.__kpSink = entered;
  return () => { for (const s of entered) s.disable(); entered.clear(); };
}
