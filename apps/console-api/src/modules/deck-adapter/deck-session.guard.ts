import {CanActivate,ExecutionContext,Inject,Injectable,Optional} from '@nestjs/common';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {RequestFailureAuditService} from '../audit/request-failure-audit.service';
import {DeckSessionService} from './deck-session.service';
@Injectable()
export class DeckSessionGuard implements CanActivate{
 constructor(@Inject(DeckSessionService)private readonly sessions:DeckSessionService,@Inject(KongExecutionContextService)private readonly execution:KongExecutionContextService,@Optional() @Inject(RequestFailureAuditService)private readonly requestAudit?:RequestFailureAuditService){}
 async canActivate(context:ExecutionContext):Promise<boolean>{
  const req=context.switchToHttp().getRequest(),session=await this.sessions.authenticate(req.params.deckSessionId,req.rawHeaders);
  const authority=this.sessions.authority(session);this.execution.bindHttpActor(authority.user,authority.sessionId);
  this.requestAudit?.captureConsole(req);
  req.deckSession=session;req.user=authority.user;req.sessionId=authority.sessionId;return true;
 }
}
