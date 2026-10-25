import { KongExecutionContextService, KongPolicyHooks } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import type { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';

/** Transport unit tests deliberately replace only the DB authorization hook.
 * The real ALS capabilities, opaque tickets and lifecycle still execute. These
 * synthetic durable IDs do not represent a production authorization proof. */
export function nativeTransportContext(hooks?: KongPolicyHooks): KongExecutionContextService {
  const context = new KongExecutionContextService();
  context.installPolicy(hooks ?? { authorizeRequest: async () => ({ platformAdmin: true }), authorizeResponse: async (_ticket, result) => result });
  return context;
}
export function scopedNativeTransport(kong: KongService, context: KongExecutionContextService, clusterId: string): KongService {
  const actor = { id: 'synthetic-transport-user', username: 'unit', superAdmin: true };
  return new Proxy(kong, { get(target, key) {
    const method = Reflect.get(target, key);
    if (!['request', 'list', 'schema', 'pluginSchema'].includes(String(key))) return typeof method === 'function' ? method.bind(target) : method;
    return (...args: any[]) => context.runHttp({ requestId: 'transport-unit' }, async () => {
      context.bindHttpActor(actor, 'synthetic-session');
      return context.runActor({ actor, clusterId: args[0] || clusterId, module: 'entities', action: key === 'request' && args[1] !== 'GET' ? 'write' : 'read' }, async () => {
        const invoke = () => method.apply(target, args);
        if (key !== 'request' || args[1] === 'GET') return invoke();
        return context.runOperation({ actor, clusterId: args[0], workspaceId: 'synthetic-workspace', operationId: 'synthetic-durable-operation', entityType: 'services', action: 'update' }, async () => {
          if (args[1] !== 'DELETE') return invoke();
          return context.runArchiveDelete({ clusterId: args[0], workspaceId: 'synthetic-workspace', operationId: 'synthetic-durable-operation', entryId: 'synthetic-durable-archive', nodes: [{ path: args[2], type: 'services', id: args[2].split('/').at(-1) }] }, invoke);
        });
      });
    });
  } });
}
