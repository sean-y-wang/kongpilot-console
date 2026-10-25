import { DbService } from './db.service';

/** Dedicated job: owner credentials exist only in this process, never in console-api. */
export async function provisionRuntimeRole(db: DbService): Promise<void> {
  const role = process.env.CONSOLE_DB_RUNTIME_USER;
  const password = process.env.CONSOLE_DB_RUNTIME_PASSWORD;
  if (!role || !/^[a-z_][a-z\d_]{2,62}$/i.test(role) || /^pg_/i.test(role)) {
    throw new Error('CONSOLE_DB_RUNTIME_USER must be a valid non-system PostgreSQL role name');
  }
  if (!password || password.length < 16) throw new Error('CONSOLE_DB_RUNTIME_PASSWORD must contain at least 16 characters');
  await db.transaction(async tx => {
    await tx.exec('SELECT pg_advisory_xact_lock($1)', [1545015003]);
    await tx.exec("SELECT set_config('kongos.runtime_role', $1, true), set_config('kongos.runtime_password', $2, true)", [role, password]);
    // PostgreSQL utility statements cannot bind identifiers/passwords. Inputs are bound to
    // local settings; server-side format(%I/%L) performs the required escaping.
    await tx.exec(`DO $kongos_role$
    DECLARE
      runtime_role text := current_setting('kongos.runtime_role');
      runtime_password text := current_setting('kongos.runtime_password');
      role_row record;
      immutable_table text;
    BEGIN
      IF runtime_role = current_user THEN RAISE EXCEPTION 'Runtime role must differ from migration owner'; END IF;
      SELECT * INTO role_row FROM pg_roles WHERE rolname = runtime_role;
      IF FOUND THEN
        IF role_row.rolsuper OR role_row.rolcreatedb OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls
          OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_row.oid) THEN
          RAISE EXCEPTION 'Existing runtime role has elevated privileges or memberships';
        END IF;
        EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', runtime_role, runtime_password);
      ELSE
        EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', runtime_role, runtime_password);
      END IF;
      EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), runtime_role);
      EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', runtime_role);
      REVOKE CREATE ON SCHEMA public FROM PUBLIC;
      EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', runtime_role);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', runtime_role);
      EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', runtime_role);
      EXECUTE format('REVOKE ALL ON schema_migrations FROM %I', runtime_role);
      EXECUTE format('GRANT SELECT ON schema_migrations TO %I', runtime_role);
      -- This fixed server-owned allowlist is applied AFTER broad runtime grants.
      -- Existence checks keep migration jobs compatible with earlier milestones.
      FOREACH immutable_table IN ARRAY ARRAY['audit_events','workflow_definition_versions',
        'workflow_definition_stages','workflow_versions','workflow_approvals','workflow_events',
        'portal_publication_revisions','portal_publication_proofs','portal_content_revisions',
        'portal_failed_issue_abandonments','audit_event_scopes','event_records',
        'notification_channel_versions','event_subscription_versions',
        'user_notification_subscription_versions','event_delivery_attempts','event_detection_observations',
        'configuration_job_pages','configuration_staged_objects','configuration_staged_collections',
        'config_snapshot_versions','config_snapshot_collections','config_snapshot_objects',
        'configuration_plan_versions','configuration_plan_objects','configuration_job_attempts','configuration_durable_issues','configuration_durable_bindings','configuration_durable_rejections',
        'configuration_gitops_runs','config_snapshot_schedule_versions','configuration_imports',
        'toolbox_metadata_operations','configuration_draft_versions','toolbox_batches','toolbox_debug_runs',
        'configuration_recycle_graphs','configuration_recycle_components','workspace_migration_workflow_bindings',
        'governance_rule_versions','governance_schedule_versions','governance_reports','governance_findings',
        'governance_comparisons','governance_fix_links','governance_metadata_requests',
        'configuration_job_origin_bindings','configuration_plan_origin_bindings','promotion_recovery_bindings',
        'workflow_candidate_versions','workflow_candidates','workflow_approval_sets',
        'workflow_approval_set_members','workflow_approval_invalidations','workflow_policy_requests',
        'entity_change_intents','entity_change_intent_versions','entity_change_intent_packets',
        'entity_change_submissions','entity_change_execution_sources','entity_change_baselines','entity_change_baseline_objects',
        'entity_change_baseline_pins','entity_change_packet_attempts','entity_change_packet_events','entity_change_recovery_links',
        'entity_change_recycle_payload_references','entity_change_recycle_archives','entity_change_recycle_nodes','entity_change_recycle_packets','entity_change_recycle_receipts',
        'entity_change_recycle_restore_present_facts','entity_change_target_result_observations','entity_change_target_health_baselines',
        'iam_change_intents','iam_metadata_requests','iam_workflow_mutation_facts',
        'metrics_setup_intents','metrics_setup_plugin_material','metrics_setup_requests','metrics_setup_completion_facts',
        'control_change_intents','control_metadata_requests','control_workflow_mutation_facts',
        'annotation_change_intents','entity_annotation_requests','annotation_workflow_mutation_facts',
        'entity_change_owner_delegations','entity_change_schedules','entity_change_schedule_activations','entity_change_schedule_claims','entity_change_schedule_leases','entity_change_schedule_events',
        'workflow_executor_delegations','workflow_schedules','workflow_schedule_activations','workflow_schedule_claims',
        'workflow_schedule_leases','workflow_schedule_outcomes','workflow_schedule_events','workflow_execution_origins','workflow_configuration_execution_origins','workflow_unknown_result_dispositions','workflow_unknown_result_abandon_requests','workflow_unsent_result_abandon_requests']
      LOOP
        IF to_regclass(format('public.%I', immutable_table)) IS NOT NULL THEN
          EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.%I FROM %I', immutable_table, runtime_role);
          EXECUTE format('GRANT SELECT, INSERT ON TABLE public.%I TO %I', immutable_table, runtime_role);
        END IF;
      END LOOP;
      IF to_regclass('public.workflow_schedule_progress') IS NOT NULL THEN
        EXECUTE format('REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.workflow_schedule_progress FROM %I', runtime_role);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE public.workflow_schedule_progress TO %I', runtime_role);
      END IF;
    END;
    $kongos_role$`);
  });
}

async function main(): Promise<void> {
  const db = new DbService();
  try {
    await db.migrateAndSeed();
    await provisionRuntimeRole(db);
    process.stdout.write('Console migrations, bootstrap and runtime database permissions ready\n');
  } finally { await db.onModuleDestroy(); }
}

if (require.main === module) {
  main().catch(() => {
    // Error details may contain database connection information; do not print them.
    process.stderr.write('Console database initialization failed; verify migration credentials, schema and bootstrap settings\n');
    process.exitCode = 1;
  });
}
