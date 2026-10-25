import { ForbiddenException } from '@nestjs/common';
import type { KongExecutionContextService } from './execution-context.service';

// Only the actual decorator invocation registers its original immutable scope.
// Exporting a membership check cannot register a caller or a copied DTO.
const entityActorDomainScopes = new WeakSet<object>();
export function isEntityActorDomainScope(scope:object):boolean{return entityActorDomainScopes.has(scope);}

/** Domain entry points bind the verified HTTP principal before calling Kong. */
export function KongActorScope(options: { module?: string; moduleArg?: number; action?: string; queryArg?: number; actorArg?: number; workspaceArg?: number } = {}): MethodDecorator {
  return (_target, _key, descriptor: PropertyDescriptor) => {
    const original = descriptor.value;
    descriptor.value = function(this: { execution: KongExecutionContextService }, ...args: any[]) {
      const actor = options.actorArg === undefined ? args.at(-1) : args[options.actorArg];
      const query = options.queryArg === undefined ? undefined : args[options.queryArg];
      if (!actor?.user?.id || !this.execution) throw new ForbiddenException({ code: 'KONG_EXECUTION_CONTEXT_REQUIRED', message: '实体操作缺少已认证执行上下文' });
      const scope=Object.freeze({ actor: actor.user, clusterId: args[0], workspaceId: (options.workspaceArg === undefined ? undefined : args[options.workspaceArg]) ?? query?.workspaceId ?? actor.workspaceId,
        module: options.module ?? (options.moduleArg === undefined ? 'entities' : args[options.moduleArg]), action: options.action ?? 'read', requestId: actor.requestId });
      entityActorDomainScopes.add(scope);
      try{return Promise.resolve(this.execution.runActor(scope, () => original.apply(this, args))).finally(()=>entityActorDomainScopes.delete(scope));}
      catch(error){entityActorDomainScopes.delete(scope);throw error;}
    };
  };
}
