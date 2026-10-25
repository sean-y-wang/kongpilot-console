// SQL011 exports are immutable artifacts without a revision column. Their
// real material revision changes when online material is destroyed; the
// composite join keeps the download intent bound to that exact artifact.
const materialJoin = `JOIN configuration_materials m ON m.id=e.material_id
  AND m.cluster_id=e.cluster_id AND m.workspace_id=e.workspace_id
  AND m.job_id=e.job_id AND m.artifact_id=e.artifact_id AND m.artifact_kind='export'`;
const ownExport = `WHERE e.id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3 AND e.created_by=$4`;

export const EXPORT_PROJECTION_QUERY = `SELECT m.revision,e.expires_at,e.state,m.state AS material_state
  FROM configuration_exports e ${materialJoin} ${ownExport}`;
export const EXPORT_DOWNLOAD_QUERY = `SELECT e.*,j.scope_kind,j.root_ids,m.revision AS export_revision,m.state AS material_state
  FROM configuration_exports e ${materialJoin}
  JOIN configuration_jobs j ON j.id=e.job_id AND j.cluster_id=e.cluster_id AND j.workspace_id=e.workspace_id ${ownExport}`;
