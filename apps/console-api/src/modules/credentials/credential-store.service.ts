import { ConflictException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';

export const CREDENTIAL_KINDS = ['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'] as const;
export type CredentialKind = typeof CREDENTIAL_KINDS[number];
export interface RememberedCredential { credential: any; rawInput: Record<string, unknown>; }

@Injectable()
export class CredentialStoreService {
  constructor(private readonly db: DbService, private readonly secrets: SecretService) {}

  private context(clusterId: string, consumerId: string, kind: string, id: string): string {
    return `credential:${clusterId}:${consumerId}:${kind}:${id}`;
  }

  async save(clusterId: string, consumerId: string, kind: string, credential: any, rawInput: Record<string, unknown> = {}): Promise<void> {
    if (!CREDENTIAL_KINDS.includes(kind as CredentialKind) || !credential?.id) throw new Error('Invalid credential storage input');
    const old = await this.get(clusterId, consumerId, kind, credential.id);
    const remembered = { ...old?.rawInput, ...rawInput };
    // A password changed outside this console makes a remembered plaintext unreliable.
    if (kind === 'basic-auth' && rawInput.password === undefined && old?.credential.password !== credential.password) delete remembered.password;
    const recoverable = kind !== 'basic-auth' || typeof remembered.password === 'string';
    const payload = this.secrets.encrypt({ credential, rawInput: remembered }, this.context(clusterId, consumerId, kind, credential.id));
    await this.db.exec(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,masked_summary,recovery_capability)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
      ON CONFLICT(cluster_id,consumer_id,credential_type,kong_id) DO UPDATE SET payload_secret=EXCLUDED.payload_secret,
      masked_summary=EXCLUDED.masked_summary,recovery_capability=EXCLUDED.recovery_capability,state='active',updated_at=now()`,
      [randomUUID(),clusterId,consumerId,kind,credential.id,payload,JSON.stringify(this.secrets.redact(credential)),recoverable?'complete':'requires_rotation']);
  }

  async get(clusterId: string, consumerId: string, kind: string, id: string): Promise<RememberedCredential | null> {
    const row = await this.db.one<{payload_secret:string}>(
      'SELECT payload_secret FROM credential_refs WHERE cluster_id=$1 AND consumer_id=$2 AND credential_type=$3 AND kong_id=$4',
      [clusterId,consumerId,kind,id]);
    return row ? this.secrets.decrypt<RememberedCredential>(row.payload_secret, this.context(clusterId,consumerId,kind,id)) : null;
  }

  async getRestorePayload(clusterId: string, consumerId: string, kind: string, id: string, remote: any): Promise<any> {
    const payload = { ...remote };
    delete payload.created_at; delete payload.updated_at; delete payload.ttl;
    if (kind === 'basic-auth') {
      const known = await this.get(clusterId,consumerId,kind,id);
      if (typeof known?.rawInput.password !== 'string' || known.credential.password !== remote.password) {
        throw new ConflictException({code:'BASIC_AUTH_NOT_RECOVERABLE',message:'此 Basic-auth 凭证缺少可信原密码，删除已停止；请先在控制台轮换密码'});
      }
      payload.password = known.rawInput.password;
    }
    if (kind === 'oauth2' && remote.hash_secret === true) {
      const known = await this.get(clusterId,consumerId,kind,id);
      if (typeof known?.rawInput.client_secret !== 'string'||known.credential.client_secret!==remote.client_secret) {
        throw new ConflictException({code:'OAUTH_SECRET_NOT_RECOVERABLE',message:'此 OAuth 客户端缺少可信原始 client_secret，删除已停止；请先轮换凭证'});
      }
      payload.client_secret = known.rawInput.client_secret;
    }
    return payload;
  }

  async remove(clusterId: string, consumerId: string, kind: string, id: string): Promise<void> {
    await this.db.exec("UPDATE credential_refs SET state='revoked',updated_at=now() WHERE cluster_id=$1 AND consumer_id=$2 AND credential_type=$3 AND kong_id=$4",
      [clusterId,consumerId,kind,id]);
  }
}
