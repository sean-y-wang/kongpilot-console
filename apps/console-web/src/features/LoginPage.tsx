import { useState } from 'react';
import { Alert, Button, Divider, Form, Input, Select, Space, Typography } from 'antd';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { useAuth } from '../app/AuthContext';
import { api, errorMessage } from '../api/client';
import { useQuery } from '@tanstack/react-query';
import { BrandMark, PRODUCT_BRAND } from '../components/BrandIdentity';
import { AppearanceToggle } from '../../../../packages/contracts/src/PilotAppearance';

export function LoginPage() {
  const auth = useAuth();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [providerId, setProviderId] = useState('');
  const providers = useQuery({ queryKey: ['auth-providers'], queryFn: () => api<{ items: { id: string; name: string; type: 'ldap' | 'oidc' }[] }>('/auth/providers'), retry: false });
  async function sso(id: string) {
    setSubmitting(true); setError(null);
    try { const result = await api<{ authorizationUrl: string }>(`/auth/oidc/${encodeURIComponent(id)}/start?redirect=/`); const target = new URL(result.authorizationUrl); if (target.protocol !== 'https:') throw new Error('身份提供方必须使用 HTTPS。'); window.location.assign(target.toString()); }
    catch (e) { setError(errorMessage(e)); setSubmitting(false); }
  }
  async function submit(values: { username: string; password: string }) {
    setSubmitting(true); setError(null);
    try { if (providerId) await auth.loginLdap(providerId, values.username, values.password); else await auth.login(values.username, values.password); }
    catch (e) { setError(errorMessage(e)); }
    finally { setSubmitting(false); }
  }
  return <div className="login-page"><div className="login-appearance-control"><AppearanceToggle /></div>
    <section className="login-story"><BrandMark large /><span className="login-product">{PRODUCT_BRAND.name}</span><span className="login-product-subtitle">{PRODUCT_BRAND.chineseName}</span></section>
    <section className="login-content"><div className="login-form"><Typography.Title level={2}>登录控制台</Typography.Title>{(error || auth.error) && <Alert type="error" showIcon message={error ?? auth.error?.message} style={{ marginBottom: 20 }} />}{providers.data?.items.some(item => item.type === 'ldap') && <Select aria-label="账号认证方式" value={providerId} onChange={setProviderId} style={{ width: '100%', marginBottom: 24 }} options={[{ value: '', label: '控制台账号' }, ...providers.data.items.filter(item => item.type === 'ldap').map(item => ({ value: item.id, label: item.name }))]} />}<Form layout="vertical" onFinish={submit} requiredMark={false} autoComplete="on"><Form.Item name="username" label="账号" rules={[{ required: true, message: '请输入账号' }]}><Input size="large" prefix={<UserOutlined />} placeholder="账号" autoComplete="username" /></Form.Item><Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}><Input.Password size="large" prefix={<LockOutlined />} placeholder="密码" autoComplete="current-password" /></Form.Item><Button htmlType="submit" type="primary" size="large" block loading={submitting}>登录控制台</Button></Form>{providers.data?.items.some(item => item.type === 'oidc') && <><Divider>企业单点登录</Divider><Space direction="vertical" style={{ width: '100%' }}>{providers.data.items.filter(item => item.type === 'oidc').map(item => <Button key={item.id} block disabled={submitting} onClick={() => void sso(item.id)}>{item.name} 登录</Button>)}</Space></>}</div></section>
  </div>;
}
