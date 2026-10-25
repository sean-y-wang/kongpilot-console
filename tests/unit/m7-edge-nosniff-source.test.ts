import{describe,it,expect}from'vitest';
import{singleNosniffConfig}from'../../deploy/scripts/verify-m7-edge-nosniff-continuity.mjs';
describe('single edge nosniff author',()=>{
 it('adds only the proxy hide directive while retaining edge always',()=>{const old='    add_header X-Content-Type-Options nosniff always;\n        proxy_pass http://console-api:3000;\n        proxy_set_header Host $http_host;';const next=singleNosniffConfig(old);expect(next.replace('\n        proxy_hide_header X-Content-Type-Options;','')).toBe(old);expect(next).toContain('nosniff always;');});
 it('rejects absent or duplicate author/upstream and an existing hide directive',()=>{const old='    add_header X-Content-Type-Options nosniff always;\n        proxy_pass http://console-api:3000;';for(const bad of [old.replace('nosniff always','nosniff'),old+old,old+'\n        proxy_hide_header X-Content-Type-Options;'])expect(()=>singleNosniffConfig(bad)).toThrow('BOUNDARY');});
});
