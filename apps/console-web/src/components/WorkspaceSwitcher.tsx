import { Button, Select } from 'antd';
import { useWorkspace } from '../app/WorkspaceContext';
export function WorkspaceSwitcher() {
  const context = useWorkspace();
  return <Select aria-label="选择工作区" className="workspace-select" value={context.workspaceId} loading={context.loading} placeholder="选择工作区" onChange={context.selectWorkspace} options={context.workspaces.map(row => ({ value: row.id, label: `${row.name}${row.is_default ? ' · 默认' : ''}${row.status === 'disabled' ? ' · 只读' : ''}` }))} popupRender={menu => <>{menu}{context.hasMore && <Button block type="text" loading={context.loadingMore} onMouseDown={event => event.preventDefault()} onClick={() => void context.loadMore()}>加载更多工作区</Button>}</>} />;
}
