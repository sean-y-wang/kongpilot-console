import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, Layout, Menu, Select, Button, Dropdown, Avatar, Space, App } from 'antd';
import { LogoutOutlined } from '@ant-design/icons';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { WorkspaceSwitcher } from '../components/WorkspaceSwitcher';
import { QueryError, UncertainOperationsBanner } from '../components/Shared';
import { errorMessage } from '../api/client';
import { usePermissions } from '../app/Permissions';
import { NotificationBell } from '../components/NotificationBell';
import { BrandMark, PRODUCT_BRAND } from '../components/BrandIdentity';
import { AppearanceToggle, usePilotAppearance } from '../../../../packages/contracts/src/PilotAppearance';

const { Sider, Header, Content } = Layout;
export const entityNavigation = [
  { key: 'services', label: 'Services', icon: <PilotIcon name="service" /> },
  { key: 'routes', label: 'Routes', icon: <PilotIcon name="route" /> },
  { key: 'consumers', label: 'Consumers', icon: <PilotIcon name="users" /> },
  { key: 'plugins', label: 'Plugins', icon: <PilotIcon name="plugin" /> },
  { key: 'upstreams', label: 'Upstreams', icon: <PilotIcon name="upstream" /> },
  { key: 'certificates', label: 'Certificates', icon: <PilotIcon name="certificate" /> },
  { key: 'ca_certificates', label: 'CA Certificates', icon: <PilotIcon name="key" /> },
  { key: 'snis', label: 'SNIs', icon: <PilotIcon name="globe" /> },
];

type NavigationItem = { key: string; label: string; icon: ReactNode; disabled?: boolean };
function NavigationGroup({ id, label, items, selected, onNavigate }: { id: string; label: string; items: NavigationItem[]; selected: string; onNavigate: (key: string) => void }) {
  const { mode } = usePilotAppearance();
  const [expanded, setExpanded] = useState(true);
  const active = items.some(item => item.key === selected);
  useEffect(() => { if (active) setExpanded(true); }, [active, selected]);
  if (!items.length) return null;
  return <section className="navigation-group">
    <button type="button" className="navigation-group-toggle" aria-label={`${expanded ? '收起' : '展开'}${label}菜单`} aria-expanded={expanded} aria-controls={`navigation-${id}`} onClick={() => setExpanded(value => !value)}>
      <span>{label}</span><span className="navigation-group-count">{items.length}</span>{expanded ? <PilotIcon name="chevron-down" /> : <PilotIcon name="chevron-right" />}
    </button>
    <div id={`navigation-${id}`} hidden={!expanded}><Menu theme={mode} mode="inline" selectedKeys={[selected]} onClick={({ key }) => onNavigate(key)} items={items} /></div>
  </section>;
}

export function ConsoleLayout() {
  const { mode } = usePilotAppearance();
  const { user, logout } = useAuth();
  const { clusterId, clusters, selectCluster, query } = useCluster();
  const workspace = useWorkspace();
  const permission = usePermissions();
  const { message } = App.useApp();
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => { const close = (event: KeyboardEvent) => { if (event.key === 'Escape' && window.matchMedia('(max-width: 991px)').matches) setCollapsed(true); }; window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close); }, []);
  const location = useLocation();
  const navigate = useNavigate();
  async function leave() {
    try { await logout(); } catch (e) { void message.error(errorMessage(e)); }
  }
  const selected = location.pathname.startsWith('/entities/') ? location.pathname.split('/')[2] : location.pathname.startsWith('/configuration/gitops') ? 'gitops' : location.pathname.split('/')[1] || 'overview';
  const navigationRef = useRef<HTMLElement>(null);
  const [scrollEdges, setScrollEdges] = useState({ above: false, below: false });
  useEffect(() => {
    const navigation = navigationRef.current;
    if (!navigation) return;
    const update = () => {
      const above = navigation.scrollTop > 1;
      const below = navigation.scrollTop + navigation.clientHeight < navigation.scrollHeight - 1;
      setScrollEdges(current => current.above === above && current.below === below ? current : { above, below });
    };
    const observer = new ResizeObserver(update);
    observer.observe(navigation);
    if (navigation.firstElementChild) observer.observe(navigation.firstElementChild);
    navigation.addEventListener('scroll', update, { passive: true });
    update();
    return () => { observer.disconnect(); navigation.removeEventListener('scroll', update); };
  }, []);
  useEffect(() => {
    if (collapsed) return;
    const frame = requestAnimationFrame(() => {
      const navigation = navigationRef.current;
      const item = navigation?.querySelector<HTMLElement>('.ant-menu-item-selected');
      if (!navigation || !item || !item.getClientRects().length) return;
      const bounds = navigation.getBoundingClientRect(), active = item.getBoundingClientRect();
      if (active.top < bounds.top + 8) navigation.scrollTop -= bounds.top + 8 - active.top;
      else if (active.bottom > bounds.bottom - 8) navigation.scrollTop += active.bottom - bounds.bottom + 8;
    });
    return () => cancelAnimationFrame(frame);
  }, [selected, collapsed]);
  function scrollNavigation(direction: number) {
    const navigation = navigationRef.current;
    if (navigation) navigation.scrollBy({ top: direction * navigation.clientHeight * .75, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
  }
  return <Layout className="console-root">
    {!collapsed && <button type="button" className="sidebar-backdrop" aria-label="关闭侧边导航" onClick={() => setCollapsed(true)} />}
    <Sider width={248} theme={mode} breakpoint="lg" collapsedWidth={0} collapsed={collapsed} onCollapse={setCollapsed} trigger={null} className="console-sidebar">
      <Link to="/" className="brand"><BrandMark /><span className="brand-wordmark">{PRODUCT_BRAND.name}<small className="brand-caption">{PRODUCT_BRAND.chineseName}</small></span></Link>
      <Button className="sidebar-close" type="text" icon={<PilotIcon name="close" />} aria-label="关闭导航" onClick={() => setCollapsed(true)} />
      <nav ref={navigationRef} className="sidebar-navigation" aria-label="控制台功能导航" tabIndex={0}><div className="sidebar-navigation-content">
      <NavigationGroup id="console" label="控制台" selected={selected} onNavigate={key => navigate(key === 'overview' ? '/' : `/${key}`)} items={[
        { key: 'overview', label: '总览', icon: <PilotIcon name="overview" /> },
        { key: 'clusters', label: '集群管理', icon: <PilotIcon name="cluster" /> },
        { key: 'data-sources', label: '数据源管理', icon: <PilotIcon name="database" /> },
        { key: 'plugin-center', label: '插件中心', icon: <PilotIcon name="plugin" /> },
        { key: 'workspaces', label: '工作区管理', icon: <PilotIcon name="users" /> },
      ].filter(item => permission.has(({ overview: 'overview', clusters: 'clusters', 'data-sources': 'data-sources', 'plugin-center': 'plugins', workspaces: 'workspaces' } as Record<string, string>)[item.key]))} />
      <NavigationGroup id="entities" label="网关实体" selected={selected} onNavigate={key => navigate(`/entities/${key}`)} items={entityNavigation.filter(item => permission.has(item.key))} />
      <NavigationGroup id="platform" label="平台管理" selected={selected} onNavigate={key => navigate(key === 'gitops' ? '/configuration/gitops' : `/${key}`)} items={[
        { key: 'authorized-children', label: '授权子实体', icon: <PilotIcon name="key" /> },
        { key: 'recycle-bin', label: '回收站', icon: <PilotIcon name="trash" /> },
        { key: 'workspace-migrations', label: '工作区迁移', icon: <PilotIcon name="route" /> },
        { key: 'vitals', label: 'Vitals 监控', icon: <PilotIcon name="chart" /> },
        { key: 'portal', label: '开发者门户', icon: <PilotIcon name="globe" /> },
        { key: 'workflows', label: '变更审批', icon: <PilotIcon name="approval" /> },
        { key: 'audit', label: '审计日志', icon: <PilotIcon name="audit" /> },
        { key: 'events', label: '事件中心', icon: <PilotIcon name="event" /> },
        { key: 'notifications', label: '通知中心', icon: <PilotIcon name="bell" /> },
        { key: 'snapshots', label: '配置快照', icon: <PilotIcon name="snapshot" /> },
        { key: 'configuration', label: '导入导出 / Diff', icon: <PilotIcon name="exchange" /> },
        { key: 'gitops', label: 'GitOps', icon: <PilotIcon name="git" /> },
        { key: 'toolbox', label: '运维工具箱', icon: <PilotIcon name="toolbox" /> },
        { key: 'governance', label: '配置治理', icon: <PilotIcon name="check-circle" /> },
        { key: 'access', label: '身份与权限', icon: <PilotIcon name="settings" />, disabled: false },
      ].filter(item => item.key === 'governance' ? ['governance', 'lint', 'drift', 'promote'].some(module => permission.has(module)) : item.key === 'toolbox' ? ['toolbox','batches','drafts'].some(module => permission.has(module)) : item.key === 'authorized-children' ? permission.has('consumers') || permission.has('upstreams') : item.key === 'portal' ? ['portal', 'developers', 'applications'].some(module => permission.has(module)) : item.key === 'access' ? ['users', 'teams', 'roles', 'permissions'].some(module => permission.has(module)) : permission.has(item.key === 'configuration' ? 'snapshots' : item.key === 'workspace-migrations' ? 'workspaces' : item.key === 'vitals' ? 'monitoring' : item.key))} />
      </div></nav>
      <div className="sidebar-footer"><div className="sidebar-scroll-controls"><Button type="text" size="small" icon={<PilotIcon name="chevron-up" />} aria-label="向上滚动导航菜单" disabled={!scrollEdges.above} onClick={() => scrollNavigation(-1)} /><Button type="text" size="small" icon={<PilotIcon name="chevron-down" />} aria-label="向下滚动查看更多菜单" disabled={!scrollEdges.below} onClick={() => scrollNavigation(1)} /></div></div>
    </Sider>
    <Layout className="main-layout">
      <Header className="console-header"><Link to="/" className="mobile-product">{PRODUCT_BRAND.name}</Link><div className="header-controls"><Button className="sidebar-toggle" type="text" icon={<PilotIcon name="menu" />} onClick={() => setCollapsed(!collapsed)} aria-label="切换导航" aria-expanded={!collapsed} /><span className="header-label">集群</span><Select aria-label="选择集群" className="cluster-select" value={clusterId} loading={query.isLoading} placeholder="选择集群" onChange={selectCluster} options={clusters.map(item => ({ value: item.id, label: `${item.name} · ${item.environment}` }))} /><div className="header-divider" /><WorkspaceSwitcher /></div><Space className="header-user"><AppearanceToggle /><NotificationBell /><Dropdown trigger={['click']} menu={{ items: [{ key: 'profile', label: '我的账号', onClick: () => navigate('/profile') }, { key: 'manual', icon: <PilotIcon name="audit" />, label: '用户使用手册', onClick: () => navigate('/help/user-guide') }, { type: 'divider' }, { key: 'version', disabled: true, label: `${PRODUCT_BRAND.name} ${PRODUCT_BRAND.versionLabel}` }, { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: () => void leave() }] }}><Button type="text" className="user-button" aria-label="用户菜单"><Avatar size={28} className="user-avatar">{user?.username?.[0]?.toUpperCase()}</Avatar><span>{user?.displayName || user?.username}</span><PilotIcon name="chevron-down" style={{ fontSize: 10 }} /></Button></Dropdown></Space></Header>
      <Content className="console-content">{workspace.error ? <QueryError error={workspace.error} retry={() => void workspace.refresh()} /> : null}{workspace.selectionNotice && <Alert type="warning" showIcon message={workspace.selectionNotice} style={{ marginBottom: 18 }} />}<UncertainOperationsBanner />{workspace.readonlyWorkspace && <Alert type="warning" showIcon message="当前工作区已停用，仅可读取网关配置" description="可以在工作区管理中重新启用；停用状态下原生配置写入与恢复被阻止。" style={{ marginBottom: 18 }} />}<Outlet /></Content>
    </Layout>
  </Layout>;
}
