import { BadRequestException } from '@nestjs/common';
import { createPrivateKey, createPublicKey, timingSafeEqual, X509Certificate } from 'node:crypto';

export function inspectCertificate(cert: string, key?: string): any {
  try {
    const certificates = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if (!certificates?.length) throw new Error('not PEM');
    const chain = certificates.map(pem => new X509Certificate(pem));
    const leaf = chain[0];
    if (key !== undefined) {
      const expected = leaf.publicKey.export({ type: 'spki', format: 'der' });
      const actual = createPublicKey(createPrivateKey(key)).export({ type: 'spki', format: 'der' });
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error('key mismatch');
    }
    const expiresAt = new Date(leaf.validTo).toISOString();
    const daysRemaining = Math.floor((Date.parse(expiresAt) - Date.now()) / 86_400_000);
    return { subject: leaf.subject, issuer: leaf.issuer, serial_number: leaf.serialNumber, fingerprint: leaf.fingerprint256, valid_from: new Date(leaf.validFrom).toISOString(), expires_at: expiresAt, days_remaining: daysRemaining, expired: daysRemaining < 0, expiring_soon: daysRemaining >= 0 && daysRemaining <= 30, subject_alt_name: leaf.subjectAltName || null, chain_length: chain.length, key_matches: key === undefined ? null : true };
  } catch {
    throw new BadRequestException({ code: 'INVALID_CERTIFICATE', message: '证书或私钥无法解析，或证书与私钥不匹配；仅支持未加密的 PEM 私钥' });
  }
}
