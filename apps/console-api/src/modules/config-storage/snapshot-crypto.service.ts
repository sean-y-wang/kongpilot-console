import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';

export interface ConfigurationMaterialIdentity {
  clusterId: string; workspaceId: string; jobId: string; materialId: string;
  artifactId: string; artifactKind: 'snapshot' | 'plan' | 'import' | 'export';
}
export interface ConfigurationCipherSection {
  section: 'page' | 'cursor' | 'object' | 'manifest' | 'plan-step' | 'export' | 'receipt';
  key: string; entityType?: string | null; nativeId?: string | null; parentId?: string | null;
  credentialKind?: string | null;
}
const fail = () => new ConflictException({code: 'CONFIGURATION_MATERIAL_UNAVAILABLE', message: '配置加密材料不可用'});

@Injectable()
export class SnapshotCryptoService {
  constructor(private readonly secrets: SecretService) {}
  private materialContext(identity: ConfigurationMaterialIdentity): string {
    return 'configuration-material:' + canonicalJson(identity);
  }
  private aad(identity: ConfigurationMaterialIdentity, section: ConfigurationCipherSection): Buffer {
    return Buffer.from('kongos-configuration:v1:' + canonicalJson({identity, section}), 'utf8');
  }
  createWrappedKey(identity: ConfigurationMaterialIdentity): string {
    const key = randomBytes(32);
    try { return this.secrets.encrypt({dek: key.toString('base64url')}, this.materialContext(identity)); }
    finally { key.fill(0); }
  }
  /** The DEK cannot be returned; it is erased when the authorized callback ends. */
  async withKey<T>(identity: ConfigurationMaterialIdentity, wrappedKey: string | null, fn: (key: Buffer) => Promise<T>): Promise<T> {
    if (!wrappedKey) throw fail();
    let key: Buffer;
    try {
      const value = this.secrets.decrypt<{dek: string}>(wrappedKey, this.materialContext(identity));
      if (!value || typeof value.dek !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.dek)) throw fail();
      key = Buffer.from(value.dek, 'base64url');
      if (key.length !== 32 || key.toString('base64url') !== value.dek) throw fail();
    } catch { throw fail(); }
    try { return await fn(key); } finally { key.fill(0); }
  }
  encrypt(key: Buffer, identity: ConfigurationMaterialIdentity, section: ConfigurationCipherSection, value: unknown): string {
    const plain = Buffer.from(canonicalJson(value), 'utf8');
    if (plain.length > 33554432) { plain.fill(0); throw new BadRequestException({code: 'CONFIGURATION_BYTE_BUDGET', message: '配置材料超过字节预算'}); }
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
    try {
      cipher.setAAD(this.aad(identity, section));
      const bytes = Buffer.concat([cipher.update(plain), cipher.final()]);
      return ['c1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), bytes.toString('base64url')].join('.');
    } finally { plain.fill(0); }
  }
  decrypt<T>(key: Buffer, identity: ConfigurationMaterialIdentity, section: ConfigurationCipherSection, encrypted: string): T {
    try {
      const parts = encrypted.split('.');
      if (parts.length !== 4 || parts[0] !== 'c1' || parts.slice(1).some(p => !/^[A-Za-z0-9_-]+$/.test(p)) || encrypted.length > 50332000) throw fail();
      const [iv, tag, ciphertext] = parts.slice(1).map(p => Buffer.from(p, 'base64url'));
      if (iv.length !== 12 || tag.length !== 16 || ciphertext.length > 33554432 || [iv,tag,ciphertext].some((b,i) => b.toString('base64url') !== parts[i+1])) throw fail();
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(this.aad(identity, section)); decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      try { return JSON.parse(plain.toString('utf8')) as T; } finally { plain.fill(0); }
    } catch { throw fail(); }
  }
}
