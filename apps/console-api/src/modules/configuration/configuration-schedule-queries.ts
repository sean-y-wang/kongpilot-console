/** Lock the mutable policy pointer while reading its immutable version. Row
 * locks require UPDATE privileges; historical versions intentionally have
 * only SELECT/INSERT privileges and cannot change during the transaction. */
export function scheduleAuthorityQuery(lock: boolean): string {
  return `SELECT s.owner_user_id,s.state,s.current_version,s.transport_scope,v.policy_hmac FROM config_snapshot_schedules s JOIN config_snapshot_schedule_versions v
        ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3${lock?' FOR SHARE OF s':''}`;
}
