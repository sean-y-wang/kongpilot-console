import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { isFactoryImmutableJson } from './kong/immutable-json';

/** Stable JSON representation used by secret fingerprints and the audit chain.
 * Single-buffer writer; output is byte-identical to the original recursive
 * entries/filter/sort/map formulation (same key order, undefined skipping,
 * Date ISO handling and unrepresentable-value rejection). */
export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  writeCanonicalJson(value, out);
  return out.join('');
}
function writeCanonicalJson(value: unknown, out: string[]): void {
  if (value === null || typeof value !== 'object') {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) throw new Error('Value cannot be represented as JSON');
    out.push(serialized); return;
  }
  if (Array.isArray(value)) {
    out.push('[');
    for (let index = 0; index < value.length; index++) { if (index) out.push(','); writeCanonicalJson(value[index], out); }
    out.push(']'); return;
  }
  if (value instanceof Date) { out.push(JSON.stringify(value.toISOString())); return; }
  const record = value as Record<string, unknown>, keys = Object.keys(record).sort();
  out.push('{'); let first = true;
  for (const name of keys) {
    const item = record[name]; if (item === undefined) continue;
    if (!first) out.push(','); first = false;
    out.push(JSON.stringify(name), ':'); writeCanonicalJson(item, out);
  }
  out.push('}');
}

function encryptionKey(): Buffer {
  const encoded = process.env.CONSOLE_ENCRYPTION_KEY;
  if (!encoded) throw new Error('CONSOLE_ENCRYPTION_KEY is required; provide a 32-byte hex or base64 key');
  if (/^[a-f\d]{64}$/i.test(encoded)) return Buffer.from(encoded, 'hex');
  if (!/^[A-Za-z\d+/]+={0,2}$/.test(encoded)) throw new Error('CONSOLE_ENCRYPTION_KEY must be hex or base64');
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) {
    throw new Error('CONSOLE_ENCRYPTION_KEY must encode exactly 32 bytes');
  }
  return key;
}

function secretField(name: string): boolean {
  const compact = name.replace(/[^a-z\d]/gi, '').toLowerCase();
  // Public schema metadata and identifiers are not credential material.
  if (['keyname', 'keynames', 'keyid', 'keyids', 'keyversion', 'credentialtype', 'credentialid',
    'credentialids', 'secretid', 'secretids', 'tokenendpoint', 'tokenexpiration',
    'tokentype', 'tokenexp', 'tokenexpirationtime', 'refreshtokenttl', 'secretisbase64', 'enablepasswordgrant'].includes(compact)) return false;
  return compact === 'key' || compact === 'keys' || compact === 'pwd' || compact === 'passwd'
    || compact.includes('password') || compact.includes('secret') || compact.includes('privatekey')
    || compact.includes('apikey') || compact.includes('accesstoken') || compact.includes('refreshtoken')
    || compact.includes('idtoken') || compact.includes('csrftoken') || compact === 'xportalcsrf' || compact === 'token' || compact === 'tokens'
    || compact === 'authorization' || compact === 'proxyauthorization' || compact === 'cookie'
    || compact === 'setcookie' || compact === 'jwt' || compact === 'jwtkey'
    || compact === 'clientkey' || compact === 'signingkey' || compact === 'provisionkey'
    || ['awskey','awsaccesskey','awsaccesskeyid','accesskey','accesskeyid'].includes(compact)
    || compact === 'credentials' || compact === 'headervalue';
}

@Injectable()
export class SecretService {
  private readonly key = encryptionKey();
  #fingerprintMemo = new WeakMap<object, string>();
  #fingerprintMemoEntries = 0;

  encrypt(value: unknown, context = ''): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(`kongos-secret:v1:${context}`, 'utf8'));
    const plaintext = canonicalJson(value);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), encrypted.toString('base64url')].join('.');
  }

  decrypt<T = any>(encrypted: string, context = ''): T {
    const parts = encrypted.split('.');
    if (parts.length !== 4 || parts[0] !== 'v1' || parts.slice(1).some(part => !/^[A-Za-z\d_-]+$/.test(part))) {
      throw new Error('Unsupported or invalid encrypted value');
    }
    const [, rawIv, rawTag, rawCiphertext] = parts;
    const iv = Buffer.from(rawIv, 'base64url');
    const tag = Buffer.from(rawTag, 'base64url');
    if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted value');
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAAD(Buffer.from(`kongos-secret:v1:${context}`, 'utf8'));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(Buffer.from(rawCiphertext, 'base64url')), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8')) as T;
  }

  /** Keyed digest prevents easy offline guessing of low-entropy credential values. */
  fingerprint(value: unknown): string {
    const immutableRoot = isFactoryImmutableJson(value);
    if (immutableRoot) {
      const prior = this.#fingerprintMemo.get(value);
      if (prior !== undefined) return prior;
    }
    const digest = createHmac('sha256', this.key).update('kongos-fingerprint:v1:').update(canonicalJson(value)).digest('hex');
    if (immutableRoot) {
      // The cache owns only digests and weak keys, never canonical plaintext.
      // New factory references still compute; this caches no current SQL fact,
      // authorization decision, lease, namespace verification or Native grant.
      if (this.#fingerprintMemoEntries >= 4096) {
        this.#fingerprintMemo = new WeakMap<object, string>(); this.#fingerprintMemoEntries = 0;
      }
      this.#fingerprintMemo.set(value, digest); this.#fingerprintMemoEntries++;
    }
    return digest;
  }

  redact(value: unknown): any {
    const seen = new WeakSet<object>();
    const hidden = (item: unknown): string => {
      try { return `[REDACTED:${this.fingerprint(item).slice(0, 16)}]`; }
      catch { return '[REDACTED]'; }
    };
    const visit = (item: unknown, depth: number): any => {
      if (item === undefined) return undefined;
      if (depth > 50) return '[DEPTH_LIMIT]';
      if (typeof item === 'string') {
        if (/-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/.test(item)
          || /^(?:Bearer|Basic)\s+\S+/i.test(item)
          || /(?:^|\r?\n)(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)\s*:/i.test(item)
          || /^v1\.[A-Za-z\d_-]+\.[A-Za-z\d_-]+\.[A-Za-z\d_-]+$/.test(item)) return hidden(item);
        // Connection URLs may contain userinfo; remove it without exposing its password.
        if (/^[a-z][a-z\d+.-]*:\/\/[^/\s]*@/i.test(item)) {
          try {
            const url = new URL(item);
            if (url.username || url.password) {
              url.username = 'REDACTED';
              url.password = '';
              return url.toString();
            }
          } catch { return hidden(item); }
        }
        return item;
      }
      if (item === null || typeof item !== 'object') return item;
      if (item instanceof Date) return item.toISOString();
      if (Buffer.isBuffer(item)) return hidden(item.toString('base64'));
      if (seen.has(item)) return '[CIRCULAR]';
      seen.add(item);
      if (Array.isArray(item)) return item.map(child => visit(child, depth + 1));
      const output = Object.create(null) as Record<string, unknown>;
      const object = item as Record<string, unknown>;
      // Historical JSON Patch stores a secret under `value`, outside its original
      // field context. Decode each pointer segment before classifying that value.
      const secretPatch = typeof object.op === 'string' && ['add','replace','test'].includes(object.op)
        && typeof object.path === 'string' && object.path.startsWith('/')
        && object.path.slice(1).split('/').some(segment => secretField(segment.replace(/~1/g,'/').replace(/~0/g,'~')));
      for (const [name, child] of Object.entries(item as Record<string, unknown>)) {
        if (child === undefined) continue;
        const credentialFlag = name.replace(/[^a-z\d]/gi,'').toLowerCase()==='credentials' && typeof child==='boolean';
        output[name] = child !== null && (secretPatch && name === 'value' && typeof child!=='boolean' || secretField(name) && !credentialFlag) ? hidden(child) : visit(child, depth + 1);
      }
      return output;
    };
    return visit(value, 0);
  }

  /** Kong validators can echo a rejected secret in an otherwise unlabelled error string. */
  redactError(responseValue:unknown,requestBody:unknown):any{
    const request=this.redact(requestBody),values=new Set<string>();
    let nodes=0,totalBytes=0,overBudget=false;const rememberedObjects=new WeakSet<object>();
    const remember=(value:unknown):void=>{
      if(++nodes>10000){overBudget=true;return;}
      if(value===null||value===undefined)return;
      if(typeof value==='string'||typeof value==='number'){
        const text=String(value);if(!text)return;
        if(values.size>=512||text.length>8192||totalBytes+text.length>131072){overBudget=true;return;}
        if(!values.has(text)){values.add(text);totalBytes+=text.length;}
        const header=/^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)\s*:\s*(.+)$/i.exec(text);
        if(header)remember(header[1]);
        const token=/^(?:Bearer|Basic)\s+(.+)$/i.exec(text);
        if(token)remember(token[1]);
        return;
      }
      if(typeof value==='object'){
        if(rememberedObjects.has(value)){overBudget=true;return;}rememberedObjects.add(value);
        for(const child of Object.values(value as any))remember(child);
      }
    };
    const collect=(plain:unknown,safe:any):void=>{
      if(++nodes>10000){overBudget=true;return;}
      if(typeof safe==='string'&&safe.startsWith('[REDACTED')){remember(plain);return;}
      // URL masking preserves the destination, so its safe value does not
      // start with the normal redaction marker. Validators may echo either
      // the whole URL or an encoded/decoded userinfo scalar in free text.
      if(typeof plain==='string'&&/^[a-z][a-z\d+.-]*:\/\/[^/\s]*@/i.test(plain)){
        try{
          const url=new URL(plain);
          if(url.username||url.password){
            remember(plain);
            for(const part of [url.username,url.password])if(part){remember(part);try{remember(decodeURIComponent(part));}catch{/* Keep the original encoded form. */}}
          }
        }catch{remember(plain);}
      }
      if(plain&&typeof plain==='object'&&safe&&typeof safe==='object'){
        for(const [key,child]of Object.entries(plain))collect(child,safe[key]);
      }
    };
    collect(requestBody,request);
    const secrets=[...values].sort((a,b)=>b.length-a.length);
    const seen=new WeakSet<object>();let responseNodes=0;
    const scrub=(value:any):any=>{
      if(++responseNodes>10000)return '[REDACTED]';
      if(typeof value==='string'){
        if(value.startsWith('[REDACTED'))return '[REDACTED]';
        if(overBudget)return '[REDACTED]';
        let text=value.slice(0,65536);
        for(const secret of secrets)text=text.split(secret).join('[REDACTED]');
        return text+(value.length>65536?'[TRUNCATED]':'');
      }
      if(typeof value==='number'&&values.has(String(value)))return '[REDACTED]';
      if(value===null||typeof value!=='object')return value;
      if(seen.has(value))return '[CIRCULAR]';seen.add(value);
      if(Array.isArray(value))return value.map(scrub);
      return Object.fromEntries(Object.entries(value).map(([key,child])=>[key,scrub(child)]));
    };
    return scrub(this.redact(responseValue));
  }
}
