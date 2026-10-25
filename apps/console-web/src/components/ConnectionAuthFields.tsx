import { Form, Input, Select } from 'antd';

export function ConnectionAuthFields({ editing = false }: { editing?: boolean }) {
  const mode = Form.useWatch('auth_type');
  return <>
    <Form.Item name="auth_type" label="连接认证" initialValue={editing ? 'keep' : 'none'}><Select options={[
      ...(editing ? [{ value: 'keep', label: '保持原认证' }] : []),
      { value: 'none', label: '无认证' }, { value: 'bearer', label: 'Bearer Token' },
      { value: 'basic', label: 'Basic Auth' }, { value: 'header', label: '自定义请求头' },
    ]} /></Form.Item>
    {mode === 'bearer' && <Form.Item name="auth_token" label="Token" rules={[{ required: true, message: '请输入 Token' }]}><Input.Password autoComplete="off" placeholder="仅提交至控制台后端，加密保存" /></Form.Item>}
    {mode === 'basic' && <><Form.Item name="auth_username" label="认证用户名" rules={[{ required: true, message: '请输入认证用户名' }]}><Input autoComplete="off" /></Form.Item><Form.Item name="auth_password" label="认证密码" rules={[{ required: true, message: '请输入认证密码' }]}><Input.Password autoComplete="new-password" /></Form.Item></>}
    {mode === 'header' && <><Form.Item name="auth_header_name" label="请求头名称" rules={[{ required: true, message: '请输入请求头名称' }]}><Input placeholder="例如 X-Admin-Token" /></Form.Item><Form.Item name="auth_header_value" label="请求头值" rules={[{ required: true, message: '请输入请求头值' }]}><Input.Password autoComplete="off" /></Form.Item></>}
  </>;
}

export function connectionAuth(values: Record<string, any>) {
  if (!values.auth_type || values.auth_type === 'keep') return undefined;
  if (values.auth_type === 'bearer') return { type: 'bearer', token: values.auth_token };
  if (values.auth_type === 'basic') return { type: 'basic', username: values.auth_username, password: values.auth_password };
  if (values.auth_type === 'header') return { type: 'header', header_name: values.auth_header_name, header_value: values.auth_header_value };
  return { type: 'none' };
}
