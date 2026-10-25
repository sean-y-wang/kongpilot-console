import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { WorkflowHandler } from './workflow.types';
import { EVENT_WORKFLOW_HANDLERS } from './event-workflow';

export const WORKFLOW_HANDLERS = ['portal.publication.draft', 'portal.publication.document', 'portal.publication.publish', 'portal.publication.unpublish', 'portal.page.draft', 'portal.page.publish', 'portal.page.unpublish', 'portal.settings.update', 'portal.developer.review', 'portal.application.update', 'portal.credential.activate', 'portal.credential.rotate', 'portal.credential.revoke', 'configuration_v2', 'configuration.metadata', 'toolbox.execute', 'governance.metadata', 'workflow.policy', 'entity.change', 'iam.metadata', 'metrics.setup.settings', 'control.metadata', 'entity.annotation', ...Object.keys(EVENT_WORKFLOW_HANDLERS)] as const;
/** Server functions are registered at bootstrap, never selected from an HTTP callback. */
@Injectable()
export class WorkflowRegistryService {
  private readonly handlers = new Map<string, WorkflowHandler>();
  register(name: string, handler: WorkflowHandler): void {
    if (!(WORKFLOW_HANDLERS as readonly string[]).includes(name) || this.handlers.has(name) || !handler?.authorize || !handler.inspect || !handler.apply) throw new Error('Invalid or duplicate workflow handler');
    this.handlers.set(name, Object.freeze(handler));
  }
  get(name: string): WorkflowHandler {
    const handler = this.handlers.get(name);
    if (!handler) throw new ServiceUnavailableException({ code: 'WORKFLOW_HANDLER_UNAVAILABLE', message: '工作流业务处理器尚未就绪，未执行变更' });
    return handler;
  }
}
