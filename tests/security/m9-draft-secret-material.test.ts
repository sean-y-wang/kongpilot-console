import { describe, expect, it } from 'vitest';
import { assertPublicDraft } from '../../apps/console-api/src/modules/toolbox/toolbox-input';
import { publicDraftMaterial } from '../../apps/console-web/src/features/draft-material';

describe('M9 public draft material rejects identifiable embedded credentials and scripts',()=>{
  it.each(['Authorization: Bearer synthetic-token','Proxy-Authorization: Basic c3ludGhldGlj','Cookie: synthetic-session=private','Set-Cookie: synthetic-session=private','X-API-Key: synthetic-token','api_key=synthetic-token','access_token:synthetic-token'])('rejects an embedded request-transformer header value: %s',header=>{
    const payload={name:'request-transformer',config:{add:{headers:[header]}}};
    expect(()=>assertPublicDraft(payload)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'DRAFT_SECRET_FORBIDDEN'})}));
    expect(()=>publicDraftMaterial(payload)).toThrow(expect.objectContaining({code:'DRAFT_SECRET_FORBIDDEN'}));
  });
  it.each(['functions','function','script','scripts','lua','lua_code','source_code','pre_function','post_function'])('rejects executable %s material whose embedded secrets cannot be generically inferred',field=>{
    const payload={name:'pre-function',config:{[field]:['return "synthetic arbitrary script material"']}};
    expect(()=>assertPublicDraft(payload)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'DRAFT_SCRIPT_FORBIDDEN'})}));
    expect(()=>publicDraftMaterial(payload)).toThrow(expect.objectContaining({code:'DRAFT_SCRIPT_FORBIDDEN'}));
  });
  it.each(['https://synthetic-user:synthetic-password@example.com','postgresql://synthetic-user:synthetic-password@db.example/data','redis://:synthetic-password@cache.example','-----BEGIN PRIVATE KEY-----\nsynthetic'])('rejects known credential URI and PEM material: %s',value=>{
    const payload={config:{uri:value}};expect(()=>assertPublicDraft(payload)).toThrow();expect(()=>publicDraftMaterial(payload)).toThrow();
  });
  it('retains ordinary public transform headers, route paths, false and zero',()=>{
    const payload={name:'request-transformer',config:{add:{headers:['X-Team: pay','X-Trace-Id: public-value']}},paths:['/v1/tokenize','/cookies'],enabled:false,retries:0};
    expect(()=>assertPublicDraft(payload)).not.toThrow();expect(publicDraftMaterial(payload)).toEqual(payload);
  });
  it('omits known native secret fields without mutating the active editor material',()=>{
    const payload={name:'jwt',config:{password:'synthetic-password',nested:{secret:'synthetic-secret',publicValue:0}},enabled:false};
    expect(publicDraftMaterial(payload)).toEqual({name:'jwt',config:{nested:{publicValue:0}},enabled:false});expect(payload.config.password).toBe('synthetic-password');expect(payload.config.nested.secret).toBe('synthetic-secret');
  });
});
