CREATE TABLE IF NOT EXISTS didstore (
  id text PRIMARY KEY,
  root text DEFAULT '',
  did text DEFAULT '',
  signing_pubkey text DEFAULT '',
  encrypting_pubkey text DEFAULT '',
  secret_cypher text DEFAULT '',
  secret_nonce text DEFAULT '',
  secret_master text DEFAULT '',
  challenge text DEFAULT '',
  status text DEFAULT 'init',
  agent_id text DEFAULT '',
  supersedes text DEFAULT '',
  superseded_by text DEFAULT '',
  superseded_at timestamp,
  created timestamp DEFAULT current_timestamp,
  modified timestamp
);
CREATE INDEX IF NOT EXISTS didstore_root_idx ON didstore (root);
CREATE INDEX IF NOT EXISTS didstore_superseded_by_idx ON didstore (superseded_by);
