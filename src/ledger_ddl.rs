pub(crate) const SCHEMA: &str = "
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS resource_epochs (
  resource TEXT PRIMARY KEY,
  isolation_epoch INTEGER NOT NULL CHECK(isolation_epoch >= 0)
) STRICT;
CREATE TABLE IF NOT EXISTS subject_revocation_epochs (
  issuer TEXT NOT NULL,
  pairwise_subject TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch >= 0),
  PRIMARY KEY(issuer, pairwise_subject)
) STRICT;
CREATE TABLE IF NOT EXISTS trusted_clock_watermark (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  observed_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS enforcement_reservations (
  command_jti TEXT PRIMARY KEY,
  grant_jti TEXT NOT NULL UNIQUE,
  recovery_jti TEXT UNIQUE,
  resource TEXT NOT NULL,
  audience TEXT NOT NULL,
  action TEXT NOT NULL,
  purpose TEXT NOT NULL,
  channel TEXT NOT NULL,
  command_digest TEXT NOT NULL,
  policy_snapshot_id TEXT NOT NULL,
  policy_snapshot_digest TEXT NOT NULL,
  isolation_epoch INTEGER NOT NULL CHECK(isolation_epoch > 0),
  reserved_at TEXT NOT NULL,
  command_issued_at TEXT NOT NULL,
  command_expires_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN (
    'reserved', 'applied', 'rejected', 'failed', 'partial'
  )),
  outcome TEXT,
  receipt_id TEXT UNIQUE,
  receipt_digest TEXT
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS one_receipt_per_command
  ON enforcement_reservations(command_jti)
  WHERE receipt_digest IS NOT NULL;
CREATE TABLE IF NOT EXISTS v2_enforcement_reservations (
  command_jti TEXT PRIMARY KEY,
  grant_jti TEXT NOT NULL UNIQUE,
  release_id TEXT NOT NULL UNIQUE,
  release_digest TEXT NOT NULL UNIQUE,
  release_reservation_id TEXT NOT NULL UNIQUE,
  checkpoint_id TEXT NOT NULL,
  checkpoint_digest TEXT NOT NULL,
  checkpoint_sequence INTEGER NOT NULL CHECK(checkpoint_sequence > 0),
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  audience TEXT NOT NULL,
  action TEXT NOT NULL,
  purpose TEXT NOT NULL,
  channel TEXT NOT NULL,
  command_digest TEXT NOT NULL UNIQUE,
  command_json TEXT NOT NULL,
  previous_fence_epoch INTEGER NOT NULL CHECK(previous_fence_epoch >= 0),
  fence_epoch INTEGER NOT NULL CHECK(fence_epoch > 0),
  expected_resource_version TEXT NOT NULL,
  policy_snapshot_id TEXT NOT NULL,
  policy_snapshot_digest TEXT NOT NULL,
  reserved_at TEXT NOT NULL,
  command_issued_at TEXT NOT NULL,
  command_expires_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN (
    'reserved', 'executing', 'result-unknown',
    'applied', 'rejected', 'failed', 'partial'
  )),
  unknown_evidence_digest TEXT,
  outcome TEXT,
  receipt_id TEXT UNIQUE,
  receipt_digest TEXT,
  UNIQUE(security_domain, deployment_id, provider, target_id, fence_epoch)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS v2_one_receipt_per_command
  ON v2_enforcement_reservations(command_jti)
  WHERE receipt_digest IS NOT NULL;
CREATE TABLE IF NOT EXISTS v2_resource_fences (
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  target_id TEXT NOT NULL,
  fence_epoch INTEGER NOT NULL CHECK(fence_epoch >= 0),
  PRIMARY KEY(security_domain, deployment_id, provider, target_id)
) STRICT;
CREATE TABLE IF NOT EXISTS v2_signed_receipts (
  command_jti TEXT PRIMARY KEY
    REFERENCES v2_enforcement_reservations(command_jti),
  receipt_id TEXT NOT NULL UNIQUE,
  receipt_digest TEXT NOT NULL UNIQUE,
  receipt_json TEXT NOT NULL
) STRICT;
PRAGMA application_id = 1129467969;
PRAGMA user_version = 4;
COMMIT;
";
