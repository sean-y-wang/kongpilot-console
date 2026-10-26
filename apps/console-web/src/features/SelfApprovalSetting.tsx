import { App, Alert, Card, Space, Switch, Typography } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, errorMessage } from '../api/client';
import { useAuth } from '../app/AuthContext';
import { mutationConfirm } from '../components/MutationConfirm';

type Setting = { enabled: boolean; revision: number; updatedBy: string | null; updatedAt: string | null };

/** Platform-wide super-admin self-approval switch (default off). Visible to super-admins only. */
export function SelfApprovalSetting() {
  const { user } = useAuth();
  const { message, modal } = App.useApp();
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['workflow-self-approval'], enabled: !!user?.superAdmin, queryFn: () => api<Setting>('/workflow-settings/self-approval') });
  const update = useMutation({
    mutationFn: (enabled: boolean) => api<Setting>('/workflow-settings/self-approval', { method: 'PUT', body: JSON.stringify({ enabled, revision: query.data!.revision, confirmed: true }) }),
    onSuccess: () => { message.success('已更新自审批设置'); void client.invalidateQueries({ queryKey: ['workflow-self-approval'] }); void client.invalidateQueries({ queryKey: ['workflows'] }); },
    onError: error => message.error(errorMessage(error)),
  });
  if (!user?.superAdmin) return null;
  const toggle = (enabled: boolean) => mutationConfirm(modal, { title: enabled ? '启用超级管理员自审批？' : '关闭超级管理员自审批？', expected: enabled ? '启用自审批' : '关闭自审批', danger: enabled, description: enabled ? '启用后，超级管理员可以审批自己提交的工单（仅限通过，记录为自审批并写入审计）。' : '关闭后，已自审批但尚未执行的工单将无法执行。', onConfirm: async () => { await update.mutateAsync(enabled); } });
  return <Card size="small" title="超级管理员自审批" style={{ marginBottom: 16 }} data-testid="self-approval-setting">
    {query.isError ? <Alert type="error" showIcon message={errorMessage(query.error)} /> : <Space wrap>
      <Switch checked={query.data?.enabled ?? false} loading={query.isLoading || update.isPending} disabled={!query.data} onChange={checked => toggle(checked)} aria-label="超级管理员自审批" />
      <Typography.Text type="secondary">{query.data?.enabled ? '已启用：超级管理员可通过自己提交的工单，记录将标记为“自审批”。' : '未启用（默认）：任何人都不能审批自己提交的工单。'}</Typography.Text>
    </Space>}
  </Card>;
}
