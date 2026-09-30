-- OpenBao V3 change kernel durable records.
-- Dialect-neutral DDL: valid for PostgreSQL 16+ and SQLite 3.35+.
-- Timestamps are ISO-8601 UTC text. JSON columns hold canonical JSON that the
-- kernel has checked for secret-shaped values before persisting.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL,
  checksum TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_requests (
  change_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  exclusion_key TEXT NOT NULL,
  request_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  submitted_by TEXT NOT NULL,
  authorization_digest TEXT NOT NULL,
  production_gate_digest TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  source_sha TEXT NOT NULL,
  status TEXT NOT NULL,
  status_reason TEXT NOT NULL DEFAULT '',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (status IN ('AWAITING_APPROVAL','COMMITTED','EXECUTING','SUCCEEDED','RETRY','RECONCILIATION_REQUIRED','DEAD_LETTER','REJECTED'))
);
CREATE INDEX IF NOT EXISTS change_requests_env_idx ON change_requests (environment, status, created_at);
CREATE INDEX IF NOT EXISTS change_requests_tenant_idx ON change_requests (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS plans (
  plan_id TEXT PRIMARY KEY,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  plan_digest TEXT NOT NULL,
  environment TEXT NOT NULL,
  source_sha TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  resource_fingerprint TEXT NOT NULL,
  create_count INTEGER NOT NULL,
  change_count INTEGER NOT NULL,
  destroy_count INTEGER NOT NULL,
  plan_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (destroy_count = 0)
);

CREATE TABLE IF NOT EXISTS operations (
  operation_id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES plans (plan_id),
  sequence INTEGER NOT NULL,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  name TEXT NOT NULL,
  resource_kind TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (plan_id, sequence),
  CHECK (action IN ('create','update')),
  CHECK (status IN ('PLANNED','CONFIRMED','FAILED','UNKNOWN'))
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  approver TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  environment TEXT NOT NULL,
  exclusion_key TEXT NOT NULL,
  evidence_ref TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
  attempt_id TEXT PRIMARY KEY,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  attempt_number INTEGER NOT NULL,
  holder TEXT NOT NULL,
  fence_token INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  UNIQUE (change_id, attempt_number),
  CHECK (outcome IN ('STARTED','SUCCEEDED','RETRY','RECONCILIATION_REQUIRED','DEAD_LETTER'))
);

CREATE TABLE IF NOT EXISTS dispatch_intents (
  intent_id TEXT PRIMARY KEY,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  attempt_id TEXT NOT NULL REFERENCES attempts (attempt_id),
  operation_id TEXT NOT NULL REFERENCES operations (operation_id),
  exclusion_key TEXT NOT NULL,
  fence_token INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  resolution TEXT NOT NULL DEFAULT '',
  CHECK (status IN ('INTENDED','CONFIRMED','FAILED','UNKNOWN'))
);
CREATE INDEX IF NOT EXISTS dispatch_intents_change_idx ON dispatch_intents (change_id, status);

CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  change_id TEXT,
  event_type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  request_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  plan_id TEXT,
  actor TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_change_idx ON events (change_id, occurred_at);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS outbox (
  message_id TEXT PRIMARY KEY,
  change_id TEXT NOT NULL REFERENCES change_requests (change_id),
  topic TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  CHECK (status IN ('PENDING','DELIVERED'))
);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox (status, created_at);

CREATE TABLE IF NOT EXISTS fence_counters (
  exclusion_key TEXT PRIMARY KEY,
  last_token INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS environment_locks (
  exclusion_key TEXT PRIMARY KEY,
  holder TEXT NOT NULL,
  fence_token INTEGER NOT NULL,
  purpose TEXT NOT NULL,
  change_id TEXT,
  run_ref TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
  run_id TEXT PRIMARY KEY,
  environment TEXT NOT NULL,
  source_sha TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  mutation_lock_held TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL,
  CHECK (status IN ('RUNNING','IN_SYNC','DRIFT_DETECTED','INCONSISTENT','FAILED'))
);

CREATE TABLE IF NOT EXISTS drift_findings (
  finding_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES reconciliation_runs (run_id),
  resource_kind TEXT NOT NULL,
  resource_name TEXT NOT NULL,
  classification TEXT NOT NULL,
  severity TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  CHECK (classification IN ('IN_SYNC','MISSING','DRIFTED','UNMANAGED','CONFLICT','DISABLED','SECURITY_CRITICAL')),
  CHECK (severity IN ('info','warning','critical'))
);

CREATE TABLE IF NOT EXISTS recovery_evidence (
  evidence_id TEXT PRIMARY KEY,
  change_id TEXT,
  kind TEXT NOT NULL,
  environment TEXT NOT NULL,
  source_sha TEXT NOT NULL,
  digest TEXT NOT NULL,
  reference TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (kind IN ('plan','readback','runtime_deploy','rollback','recovery','backup','restore','staging_certification','topology','ci','image'))
);
