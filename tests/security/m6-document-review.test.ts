import 'reflect-metadata';
import { beforeEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalDocumentService } from '../../apps/console-api/src/modules/portal/portal-document.service';

let service: PortalDocumentService;
const spec = (openapi = '3.0.3'): any => ({
  openapi,
  info: { title: 'Independent document review', version: '1' },
  paths: { '/pay': { post: { responses: { '200': { description: 'OK' } } } } },
});

beforeEach(() => {
  process.env.CONSOLE_ENCRYPTION_KEY = randomBytes(32).toString('hex');
  service = new PortalDocumentService(new SecretService());
});

describe('M6 independent document publication review', () => {
  it.each([
    ['writeOnly', { writeOnly: true }],
    ['x-sensitive', { 'x-sensitive': true }],
    ['password-format', { format: 'password' }],
  ])('propagates %s sensitivity into nested schema defaults/examples', (_, marker) => {
    const source = spec();
    source.components = { schemas: { Payload: {
      type: 'object', ...marker,
      required: ['value'],
      properties: { value: { type: 'string', default: 'review-private-default', example: 'review-private-example' } },
    } } };
    const document = service.parse(source, null).document;
    expect(document.components.schemas.Payload.required).toEqual(['value']);
    expect(document.components.schemas.Payload.properties.value.type).toBe('string');
    expect(JSON.stringify(document)).not.toContain('review-private-default');
    expect(JSON.stringify(document)).not.toContain('review-private-example');
  });

  it('scrubs a shared schema sample reached by a sensitive property reference', () => {
    const source = spec();
    source.components = { schemas: {
      SharedText: { type: 'string', default: 'review-private-default', example: 'review-private-example' },
      Login: { type: 'object', required: ['password'], properties: { password: { $ref: '#/components/schemas/SharedText' } } },
    } };
    const document = service.parse(source, null).document;
    expect(document.components.schemas.Login.required).toEqual(['password']);
    expect(document.components.schemas.Login.properties.password.$ref).toBe('#/components/schemas/SharedText');
    expect(document.components.schemas.SharedText.type).toBe('string');
    expect(JSON.stringify(document)).not.toContain('review-private-default');
    expect(JSON.stringify(document)).not.toContain('review-private-example');
  });

  it('scrubs a shared schema sample reached by an Authorization parameter reference', () => {
    const source = spec();
    source.components = { schemas: { SharedText: { type: 'string', default: 'review-private-default' } } };
    source.paths['/pay'].post.parameters = [{ name: 'Authorization', in: 'header', schema: { $ref: '#/components/schemas/SharedText' } }];
    expect(JSON.stringify(service.parse(source, null).document)).not.toContain('review-private-default');
  });

  it('preserves public structural metadata and harmless schema defaults', () => {
    const source = spec('3.1.0');
    source.components = { schemas: { Body: { type: 'object', required: ['password', 'key'], properties: {
      password: { type: 'string', format: 'password', description: 'Login password', default: 'review-private-default' },
      key: { type: 'string', example: 'review-private-example' },
      credentials: { type: 'boolean', default: false },
      count: { type: 'integer', default: 2 },
    } } } };
    const schema = service.parse(source, null).document.components.schemas.Body;
    expect(schema.required).toEqual(['password', 'key']);
    expect(schema.properties.password).toEqual({ type: 'string', format: 'password', description: 'Login password' });
    expect(schema.properties.key).toEqual({ type: 'string' });
    expect(schema.properties.credentials).toEqual({ type: 'boolean', default: false });
    expect(schema.properties.count).toEqual({ type: 'integer', default: 2 });
  });

  it('counts OpenAPI 3.1 webhooks toward the 2,000-operation budget', () => {
    const source = spec('3.1.0');
    source.webhooks = Object.fromEntries(Array.from({ length: 2001 }, (_, index) => [`hook-${index}`, { post: { responses: {} } }]));
    expect(() => service.parse(source, null)).toThrow();
  });

  it('counts OpenAPI callback operations toward the 2,000-operation budget', () => {
    const source = spec();
    source.paths['/pay'].post.callbacks = { Notify: Object.fromEntries(Array.from({ length: 2001 }, (_, index) => [`{$request.body#/callbackUrl}/${index}`, { post: { responses: {} } }])) };
    expect(() => service.parse(source, null)).toThrow();
  });

  it.each([
    'https://reader&#58;review-private-password&#64;example.test',
    'https:\t//reader:review-private-password@example.test',
    '//reader:review-private-password@example.test',
  ])('rejects document URL userinfo after normalization: %s', value => {
    const source = spec();
    source.info.description = value;
    expect(() => service.parse(source, null)).toThrow();
  });

  it('rejects entity-encoded Markdown URL userinfo', () => {
    expect(() => service.markdown('[Docs](https://reader&#58;review-private-password&#64;example.test)')).toThrow();
  });

  it('rejects fully entity-encoded HTML consistently with encoded angle brackets', () => {
    const source = spec();
    source.info.description = '&#60;&#115;cript&#62;review&#60;/&#115;cript&#62;';
    expect(() => service.parse(source, null)).toThrow();
    expect(() => service.markdown(source.info.description)).toThrow();
  });
});
