ALTER TABLE index_sync_state ADD COLUMN cycle_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE entity_index ADD COLUMN sync_cycle uuid;
CREATE INDEX entity_index_cycle ON entity_index(cluster_id,entity_type,sync_cycle);
