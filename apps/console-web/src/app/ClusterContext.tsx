import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { api } from '../api/client';
import { listData, normalizeCluster, type Cluster } from '../api/types';

interface ClusterContextValue {
  clusters: Cluster[];
  cluster: Cluster | undefined;
  clusterId: string | undefined;
  selectCluster: (id: string) => void;
  query: UseQueryResult<Cluster[], Error>;
}
const ClusterContext = createContext<ClusterContextValue | null>(null);
export const clustersQueryKey = ['clusters'];

export function ClusterProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState<string | undefined>(() => sessionStorage.getItem('kongos.clusterId') ?? undefined);
  const query = useQuery({ queryKey: clustersQueryKey, queryFn: async () => listData(await api<any>('/clusters')).map(normalizeCluster) });
  const clusters = query.data ?? [];
  const cluster = clusters.find(item => item.id === selected) ?? clusters[0];
  useEffect(() => {
    if (cluster?.id) sessionStorage.setItem('kongos.clusterId', cluster.id);
    else sessionStorage.removeItem('kongos.clusterId');
  }, [cluster?.id]);
  function selectCluster(id: string) { setSelected(id); sessionStorage.setItem('kongos.clusterId', id); }
  return <ClusterContext.Provider value={{ clusters, cluster, clusterId: cluster?.id, selectCluster, query }}>{children}</ClusterContext.Provider>;
}

export function useCluster() {
  const value = useContext(ClusterContext);
  if (!value) throw new Error('ClusterProvider is required');
  return value;
}

export function useOptionalCluster() { return useContext(ClusterContext); }
