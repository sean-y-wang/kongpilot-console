import { ApiError } from '../api/client';

const secretName=/(?:password|passphrase|secret|private.?key|api.?key|token|authorization|cookie|credential|^key$|^cert$)/i;
const scriptName=/^(?:functions?|scripts?|lua|lua_code|source_code|pre_function|post_function)$/i;
const secretMaterial=/-----BEGIN|(?:[a-z][a-z\d+.-]*:\/\/)[^\s/]*@|(?:[?&])(?:token|key|password|secret|access_token)=|\b(?:authorization|proxy-authorization|cookie|set-cookie|(?:x[-_])?api[-_]key|access[-_]token|password|passphrase|secret)\b["']?\s*[:=,]|\b(?:Bearer|Basic)\s+\S+/i;

/** Native secret fields remain in the form and are omitted from public drafts.
 * Explicit embedded authentication material and executable scripts require a
 * user correction; silently dropping them would change the saved config. */
export function publicDraftMaterial(value:unknown):any{
  if(typeof value==='string'&&secretMaterial.test(value))throw new ApiError('草稿包含认证请求头、Cookie、私钥或含凭证的地址。请移除相关材料后再保存草稿。',400,'DRAFT_SECRET_FORBIDDEN');
  if(Array.isArray(value))return value.map(publicDraftMaterial).filter(item=>item!==undefined);
  if(value&&typeof value==='object'){
    const output:Record<string,unknown>={};
    for(const [key,item]of Object.entries(value)){
      if(scriptName.test(key))throw new ApiError('草稿不保存 Serverless 函数或脚本，请通过配置变更流程管理脚本。',400,'DRAFT_SCRIPT_FORBIDDEN');
      if(secretName.test(key)||['__proto__','prototype','constructor'].includes(key))continue;
      const prepared=publicDraftMaterial(item);if(prepared!==undefined)output[key]=prepared;
    }
    return output;
  }
  return value;
}
