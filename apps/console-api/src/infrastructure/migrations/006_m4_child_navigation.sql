-- A derived navigation cache, never an authorization source. Child records
-- are reread via the nested Kong endpoint before use; no secrets are stored.
CREATE TABLE entity_parent_index (
 cluster_id uuid NOT NULL REFERENCES clusters(id),
 child_type text NOT NULL CHECK(child_type IN ('targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
 child_id uuid NOT NULL,
 parent_type text NOT NULL CHECK(parent_type IN ('upstreams','consumers')),
 parent_id uuid NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,child_type,child_id),
 CHECK((child_type='targets' AND parent_type='upstreams') OR (child_type<>'targets' AND parent_type='consumers'))
);
CREATE INDEX entity_parent_index_parent ON entity_parent_index(cluster_id,parent_type,parent_id,child_type,child_id);
