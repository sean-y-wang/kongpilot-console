import React from 'react';
import ReactDOM from 'react-dom/client';
import { App as AntApp, Spin } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes, useParams } from 'react-router-dom';
import { AuthProvider, useAuth } from './app/AuthContext';
import { ClusterProvider, useCluster } from './app/ClusterContext';
import { WorkspaceProvider, useWorkspace } from './app/WorkspaceContext';
import { ConsoleLayout } from './layouts/ConsoleLayout';
import { LoginPage } from './features/LoginPage';
import { OverviewPage } from './features/OverviewPage';
import { ClustersPage } from './features/ClustersPage';
import { DataSourcesPage } from './features/DataSourcesPage';
import { EntitiesPage } from './features/EntitiesPage';
import { RecycleBinPage } from './features/RecycleBinPage';
import { PluginCenterPage } from './features/PluginCenterPage';
import { WorkspacesPage } from './features/WorkspacesPage';
import { WorkspaceMigrationsPage } from './features/WorkspaceMigrationsPage';
import { AuthorizedChildrenPage } from './features/AuthorizedChildrenPage';
import { IAMPage } from './features/IAMPage';
import { ProfilePage } from './features/ProfilePage';
import { ToolboxPage } from './features/ToolboxPage';
import { GovernancePage } from './features/GovernancePage';
import { PermissionGate, usePermissions } from './app/Permissions';
import { PortalAdminPage } from './features/PortalAdminPage';
import { WorkflowsPage, WorkflowDetailPage } from './features/WorkflowsPage';
import { AuditPage } from './features/AuditPage';
import { EventCenterPage } from './features/EventCenterPage';
import { NotificationsPage } from './features/NotificationsPage';
import { SnapshotsPage } from './features/SnapshotsPage';
import { SnapshotDetailPage } from './features/SnapshotDetailPage';
import { ConfigurationPage } from './features/ConfigurationPage';
import { ConfigurationPlanPage } from './features/ConfigurationPlanPage';
import { ConfigurationJobPage } from './features/ConfigurationJobPage';
import { GitOpsPage } from './features/GitOpsPage';
import './app/i18n';
import './styles.css';
import { BrandMark, PRODUCT_BRAND } from './components/BrandIdentity';
import { AppearanceToggle, PilotThemeProvider } from '../../../packages/contracts/src/PilotAppearance';
import '../../../packages/contracts/src/pilot-visual.css';
import '../../../packages/contracts/src/pilot-appearance.css';

const ManualPage = React.lazy(() => import('./features/ManualPage').then(module => ({ default: module.ManualPage })));
const VitalsPage = React.lazy(() => import('./features/VitalsPage').then(module => ({ default: module.VitalsPage })));

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: false } } });

function AuthenticatedApp() {
  const { user, loading } = useAuth();
  if (loading) return <div className="app-loading"><BrandMark large /><Spin size="large" /><p>正在连接 {PRODUCT_BRAND.name}…</p></div>;
  if (!user) return <LoginPage />;
  if (user.forcePasswordChange) return <div className="forced-profile"><div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}><AppearanceToggle /></div><ProfilePage /></div>;
  return <ClusterProvider key={`${user.id}:${user.permissionsVersion}`}><WorkspaceProvider><Routes><Route element={<ConsoleLayout />}><Route index element={<HomePage />} /><Route path="profile" element={<ProfilePage />} /><Route path="help/:manual" element={<ManualPage />} /><Route path="toolbox" element={<ToolboxRoute />} /><Route path="governance" element={<GovernanceRoute />} /><Route path="vitals" element={<PermissionGate module="monitoring"><VitalsPage /></PermissionGate>} /><Route path="portal" element={<PortalRoute />} /><Route path="workflows" element={<PermissionGate module="workflows"><WorkflowsPage /></PermissionGate>} /><Route path="workflows/:id" element={<PermissionGate module="workflows"><WorkflowDetailPage /></PermissionGate>} /><Route path="audit" element={<PermissionGate module="audit"><AuditPage /></PermissionGate>} /><Route path="events" element={<PermissionGate module="events"><EventCenterPage /></PermissionGate>} /><Route path="notifications" element={<PermissionGate module="notifications"><NotificationsPage /></PermissionGate>} /><Route path="snapshots" element={<PermissionGate module="snapshots"><SnapshotsPage /></PermissionGate>} /><Route path="snapshots/:id" element={<PermissionGate module="snapshots"><SnapshotDetailPage /></PermissionGate>} /><Route path="configuration" element={<PermissionGate module="snapshots"><ConfigurationPage /></PermissionGate>} /><Route path="configuration/plans/:id" element={<PermissionGate module="snapshots"><ConfigurationPlanPage /></PermissionGate>} /><Route path="configuration/jobs/:id" element={<ConfigurationJobRoute />} /><Route path="configuration/gitops" element={<PermissionGate module="gitops"><GitOpsPage /></PermissionGate>} /><Route path="access" element={<IAMPage />} /><Route path="authorized-children" element={<ChildrenRoute />} /><Route path="clusters" element={<PermissionGate module="clusters"><ClustersPage /></PermissionGate>} /><Route path="data-sources" element={<PermissionGate module="data-sources"><DataSourcesPage /></PermissionGate>} /><Route path="plugin-center" element={<PermissionGate module="plugins"><PluginCenterPage /></PermissionGate>} /><Route path="workspaces" element={<PermissionGate module="workspaces"><WorkspacesPage /></PermissionGate>} /><Route path="workspace-migrations" element={<PermissionGate module="workspaces"><WorkspaceMigrationsPage /></PermissionGate>} /><Route path="entities/:entityType" element={<EntityRoute />} /><Route path="entities/:entityType/:entityId" element={<EntityRoute />} /><Route path="recycle-bin" element={<PermissionGate module="recycle-bin"><RecycleBinPage /></PermissionGate>} /><Route path="*" element={<Navigate to="/" replace />} /></Route></Routes></WorkspaceProvider></ClusterProvider>;
}
function ToolboxRoute() { const permission=usePermissions(),{clusterId}=useCluster(),{workspaceId}=useWorkspace(); return ['toolbox','batches','drafts'].some(module=>permission.has(module)) ? <ToolboxPage key={`${clusterId}:${workspaceId}:${permission.version}`}/> : <PermissionGate module="toolbox"><ToolboxPage/></PermissionGate>; }
function GovernanceRoute() { const permission = usePermissions(), { clusterId } = useCluster(), { workspaceId } = useWorkspace(); return ['governance', 'lint', 'drift', 'promote'].some(module => permission.has(module)) ? <GovernancePage key={`${clusterId}:${workspaceId}:${permission.version}`} /> : <PermissionGate module="governance"><GovernancePage /></PermissionGate>; }
function PortalRoute() { const permission = usePermissions(); return ['portal', 'developers', 'applications'].some(module => permission.has(module)) ? <PortalAdminPage /> : <PermissionGate module="portal"><PortalAdminPage /></PermissionGate>; }
function ConfigurationJobRoute() { const permission = usePermissions(); return <PermissionGate module={permission.has('snapshots') ? 'snapshots' : 'gitops'}><ConfigurationJobPage /></PermissionGate>; }
function EntityRoute() { const { entityType = '' } = useParams(); return <PermissionGate module={entityType}><EntitiesPage /></PermissionGate>; }
function ChildrenRoute() { const permission = usePermissions(); return permission.has('consumers') || permission.has('upstreams') ? <AuthorizedChildrenPage /> : <PermissionGate module="consumers"><AuthorizedChildrenPage /></PermissionGate>; }
function HomePage() { const permission = usePermissions(); const target = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'].find(type => permission.has(type)); return permission.has('overview') ? <OverviewPage /> : target ? <Navigate to={`/entities/${target}`} replace /> : permission.has('monitoring') ? <Navigate to="/vitals" replace /> : ['portal', 'developers', 'applications'].some(module => permission.has(module)) ? <Navigate to="/portal" replace /> : permission.has('workflows') ? <Navigate to="/workflows" replace /> : permission.has('audit') ? <Navigate to="/audit" replace /> : permission.has('events') ? <Navigate to="/events" replace /> : permission.has('notifications') ? <Navigate to="/notifications" replace /> : permission.has('snapshots') ? <Navigate to="/snapshots" replace /> : permission.has('gitops') ? <Navigate to="/configuration/gitops" replace /> : ['governance', 'lint', 'drift', 'promote'].some(module => permission.has(module)) ? <Navigate to="/governance" replace /> : <ProfilePage />; }

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><PilotThemeProvider><AntApp><QueryClientProvider client={queryClient}><BrowserRouter><AuthProvider><React.Suspense fallback={<div className="app-loading"><Spin size="large" /><p>正在加载页面…</p></div>}><AuthenticatedApp /></React.Suspense></AuthProvider></BrowserRouter></QueryClientProvider></AntApp></PilotThemeProvider></React.StrictMode>,
);
