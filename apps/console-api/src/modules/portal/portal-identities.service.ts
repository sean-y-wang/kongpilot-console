import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { filteredList } from '../../infrastructure/kong/filtered-list';
import { decodeTag } from '../../infrastructure/kong/tags';
import { PortalNativeService } from './portal-native.service';
import { portalObject,portalText } from './portal-input';
import { pageSize,type EntityActor } from '../entities/entities.types';
@Injectable()
export class PortalIdentitiesService {
  constructor(private readonly native:PortalNativeService){}
  async list(cid:string,query:Record<string,unknown>,actor:EntityActor,publishPicker=false):Promise<any>{portalObject(query,publishPicker?['workspaceId','size','cursor','search']:['workspaceId','type','module','size','cursor','search']);
    const type=publishPicker?'services':query.type,module=publishPicker?'portal':query.module,action=publishPicker?'write':'read';if(!['services','routes'].includes(String(type))||!['portal','workflows'].includes(String(module)))throw new BadRequestException({code:'INVALID_PORTAL_IDENTITY_KIND'});
    return this.native.actor(cid,actor,String(module),action,async()=>{if(!publishPicker)await this.native.authz.assertCluster(actor.user,cid,'roles','write',actor.workspaceId);await this.native.authz.assertCluster(actor.user,cid,String(module),action,actor.workspaceId);const scope=await this.native.workspaces.listScope(cid,actor.workspaceId),version=await this.native.authz.permissionVersion(actor.user),search=portalText(query.search??'',128,false),size=pageSize(query.size),path=`/${type}`;
      const binding=this.native.secrets.fingerprint({cid,type,module,action,workspace:scope.binding,actor:actor.user.id,version,size,search});
      const result=await this.native.context.runInternalRead(cid,'inventory',()=>filteredList(this.native.kong,cid,path,{size,...(scope.nativeTags?{tags:scope.nativeTags}:{})},typeof query.cursor==='string'?query.cursor:undefined,binding,async items=>{
        const visible=[];for(const item of items){if(!this.native.workspaces.matches(scope,item)||search&&!String(item.name??item.id).toLowerCase().includes(search.toLowerCase()))continue;try{await this.native.authz.assertScopedResource(actor.user,cid,String(module),action,String(type),item,scope.workspaceId);visible.push({id:item.id,name:item.name??item.id,tags:(item.tags??[]).map(decodeTag),workspaceId:scope.workspaceId});}catch(error){if(!(error instanceof ForbiddenException))throw error;}}return visible;
      }),{paths:[path],maxCalls:5,maxPages:5,maxRecords:500,maxBytes:2*1024*1024,workspaceId:scope.workspaceId});if(await this.native.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});return result;
    });
  }
}
