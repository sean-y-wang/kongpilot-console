import { Alert, Input } from 'antd';
import { ExclamationCircleOutlined } from '@ant-design/icons';
import { ApiError, errorMessage, getApiActorId } from '../api/client';

const activeDialogs = new Set<any>();
export function closeMutationConfirmDialogs() { for (const dialog of activeDialogs) dialog.destroy?.(); activeDialogs.clear(); }

export function mutationConfirm(modal: any, options: { title: string; description: string; expected: string; onConfirm: () => Promise<void>; danger?: boolean; okText?: string }) {
  let typed = '';
  let uncertain = false;
  let running = false;
  const originalActorId = getApiActorId();
  const content = <><p>{options.description}</p><p>输入 <strong className="mono">{options.expected}</strong> 确认：</p><Input aria-label="确认名称" autoComplete="off" placeholder={options.expected} onChange={event => { typed = event.target.value; dialog.update({ okButtonProps: { danger: options.danger ?? true, loading: running, disabled: running || uncertain || typed !== options.expected } }); }} /></>;
  const dialog = modal.confirm({ title: options.title, icon: <ExclamationCircleOutlined />, content, okText: options.okText ?? '确认执行', cancelText: '取消', onCancel: () => activeDialogs.delete(dialog), okButtonProps: { danger: options.danger ?? true, disabled: true }, onOk: (close: () => void) => {
    if (running || uncertain || typed !== options.expected) return;
    if (getApiActorId() !== originalActorId) { activeDialogs.delete(dialog); close(); return; }
    running = true;
    dialog.update({ okButtonProps: { danger: options.danger ?? true, loading: true, disabled: true } });
    // AntD's explicit-close callback deliberately returns no rejected Promise:
    // ActionButton otherwise rethrows even a handled rejection as a page error.
    void Promise.resolve().then(() => { if (getApiActorId() !== originalActorId) throw new ApiError('登录账号已切换，请重新审阅当前账号的操作。', 401, 'SESSION_CHANGED'); return options.onConfirm(); }).then(() => { running = false; activeDialogs.delete(dialog); close(); }, error => {
      running = false;
      uncertain = error instanceof ApiError && (error.recovery?.state === 'uncertain' || !!error.recovery?.kind && ['partial', 'running'].includes(error.recovery.state ?? '') || /UNKNOWN|UNCERTAIN/.test(error.code ?? ''));
      dialog.update({ content: <>{content}<Alert type={uncertain ? 'warning' : 'error'} showIcon message={uncertain ? '写入结果待核验' : '操作未完成'} description={uncertain && (error.recovery?.idempotencyKey || error.recovery?.operationId) ? '请关闭确认框，核验原操作回执后再进行下一次写入。' : errorMessage(error)} style={{ marginTop: 16 }} /></>, okButtonProps: { danger: options.danger ?? true, loading: false, disabled: uncertain || typed !== options.expected } });
    }).catch(() => { running = false; });
  } });
  activeDialogs.add(dialog);
}
