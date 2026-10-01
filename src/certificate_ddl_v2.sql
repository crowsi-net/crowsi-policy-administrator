BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS certificate_v2_reservations (
  authorization_jti TEXT PRIMARY KEY,
  authorization_id TEXT NOT NULL UNIQUE,
  pa_reservation_id TEXT NOT NULL UNIQUE,
  operation_id TEXT NOT NULL UNIQUE,
  grant_jti TEXT NOT NULL UNIQUE,
  grant_id TEXT NOT NULL UNIQUE,
  decision_id TEXT NOT NULL UNIQUE,
  approval_id TEXT UNIQUE,
  request_digest_sha256 TEXT NOT NULL,
  authorization_command_digest_sha256 TEXT NOT NULL UNIQUE,
  lease_digest_sha256 TEXT UNIQUE,
  related_authorization_jti TEXT
    REFERENCES certificate_v2_reservations(authorization_jti),
  action TEXT NOT NULL,
  fence_scope TEXT NOT NULL,
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  release_digest_sha256 TEXT NOT NULL,
  deployment_provenance_ref TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_digest_sha256 TEXT NOT NULL,
  pairwise_subject TEXT NOT NULL,
  service_id TEXT NOT NULL,
  workload TEXT NOT NULL,
  profile TEXT NOT NULL,
  requester_pairwise_subject TEXT NOT NULL,
  approver_pairwise_subject TEXT,
  identity_revocation_epoch INTEGER NOT NULL CHECK(identity_revocation_epoch >= 0),
  previous_identity_revocation_epoch INTEGER NOT NULL
    CHECK(previous_identity_revocation_epoch >= 0),
  target_resource_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  previous_fence INTEGER NOT NULL CHECK(previous_fence >= 0),
  current_fence INTEGER NOT NULL CHECK(current_fence >= 0),
  expected_resource_version INTEGER NOT NULL CHECK(expected_resource_version >= 0),
  command_json TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  grant_json TEXT NOT NULL,
  reserved_at_epoch_s INTEGER NOT NULL CHECK(reserved_at_epoch_s >= 0),
  issued_at_epoch_s INTEGER NOT NULL CHECK(issued_at_epoch_s >= 0),
  expires_at_epoch_s INTEGER NOT NULL CHECK(expires_at_epoch_s > issued_at_epoch_s),
  state TEXT NOT NULL CHECK(state IN (
    'reserved', 'executing', 'result-unknown', 'consumed', 'reconciled', 'abandoned'
  )),
  previous_lifecycle_revocation_epoch INTEGER NOT NULL
    CHECK(previous_lifecycle_revocation_epoch >= 0),
  lifecycle_revocation_epoch INTEGER NOT NULL
    CHECK(lifecycle_revocation_epoch >= 0),
  unknown_evidence_digest_sha256 TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_resource_fences (
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  target_resource_id TEXT NOT NULL,
  fence_scope TEXT NOT NULL,
  fence INTEGER NOT NULL CHECK(fence >= 0),
  PRIMARY KEY(
    security_domain, deployment_id, provider, target_resource_id, fence_scope
  )
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_fence_reservations (
  pa_reservation_id TEXT PRIMARY KEY
    REFERENCES certificate_v2_reservations(pa_reservation_id),
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  target_resource_id TEXT NOT NULL,
  fence_scope TEXT NOT NULL,
  previous_fence INTEGER NOT NULL CHECK(previous_fence >= 0),
  proposed_fence INTEGER NOT NULL CHECK(proposed_fence > previous_fence),
  UNIQUE(
    security_domain, deployment_id, provider, target_resource_id, fence_scope
  )
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_revocation_epochs (
  revocation_issuer TEXT NOT NULL,
  security_domain TEXT NOT NULL,
  pairwise_subject TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  PRIMARY KEY(revocation_issuer, security_domain, pairwise_subject)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_ledger_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  authorization_issuer TEXT NOT NULL,
  authorization_audience TEXT NOT NULL,
  authorization_provider TEXT NOT NULL,
  authorization_policy_id TEXT NOT NULL,
  authorization_policy_digest_sha256 TEXT NOT NULL,
  authorization_verifier_key_id TEXT NOT NULL,
  revocation_issuer TEXT NOT NULL,
  revocation_audience TEXT NOT NULL,
  trust_revision INTEGER NOT NULL CHECK(trust_revision > 0)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_lifecycle_epochs (
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  target_resource_id TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  PRIMARY KEY(security_domain, deployment_id, provider, target_resource_id)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_lifecycle_epoch_reservations (
  pa_reservation_id TEXT PRIMARY KEY
    REFERENCES certificate_v2_reservations(pa_reservation_id),
  security_domain TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  target_resource_id TEXT NOT NULL,
  previous_epoch INTEGER NOT NULL CHECK(previous_epoch >= 0),
  proposed_epoch INTEGER NOT NULL CHECK(proposed_epoch > previous_epoch),
  UNIQUE(security_domain, deployment_id, provider, target_resource_id)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_approval_authority_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  relying_party_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  challenge_authority_ref TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_approval_uses (
  approval_id TEXT PRIMARY KEY,
  approval_evidence_digest_sha256 TEXT NOT NULL UNIQUE,
  challenge_id TEXT NOT NULL UNIQUE,
  challenge_nonce_base64 TEXT NOT NULL UNIQUE,
  pa_reservation_id TEXT NOT NULL UNIQUE
    REFERENCES certificate_v2_reservations(pa_reservation_id)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_outcome_authority_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  receipt_key_id TEXT NOT NULL,
  receipt_key_version TEXT NOT NULL,
  receipt_public_key_spki_sha256 TEXT NOT NULL,
  receipt_key_purpose TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_manager_commit_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  workload TEXT NOT NULL,
  commit_key_id TEXT NOT NULL,
  commit_key_version TEXT NOT NULL,
  commit_public_key_spki_sha256 TEXT NOT NULL,
  commit_key_purpose TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_manager_handoff_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  workload TEXT NOT NULL,
  receipt_key_id TEXT NOT NULL,
  receipt_key_version TEXT NOT NULL,
  receipt_public_key_spki_sha256 TEXT NOT NULL,
  receipt_key_purpose TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_completion_evidence (
  commit_id TEXT PRIMARY KEY,
  authority_evidence_id TEXT NOT NULL UNIQUE,
  authority_nonce_base64 TEXT NOT NULL UNIQUE,
  manager_nonce_base64 TEXT NOT NULL UNIQUE,
  authorization_jti TEXT NOT NULL UNIQUE
    REFERENCES certificate_v2_reservations(authorization_jti),
  authority_evidence_digest_sha256 TEXT NOT NULL UNIQUE,
  manager_commit_digest_sha256 TEXT NOT NULL UNIQUE,
  authority_evidence_json TEXT NOT NULL,
  manager_commit_json TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN (
    'completed', 'not-executed', 'still-unknown'
  )),
  recorded_at_epoch_s INTEGER NOT NULL CHECK(recorded_at_epoch_s >= 0)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_completion_inbox (
  authorization_jti TEXT PRIMARY KEY
    REFERENCES certificate_v2_reservations(authorization_jti),
  commit_id TEXT NOT NULL UNIQUE,
  authority_evidence_id TEXT NOT NULL UNIQUE,
  authority_evidence_digest_sha256 TEXT NOT NULL UNIQUE,
  manager_commit_digest_sha256 TEXT NOT NULL UNIQUE,
  authority_evidence_json TEXT NOT NULL,
  manager_commit_json TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN (
    'completed', 'not-executed', 'still-unknown'
  )),
  received_at_epoch_s INTEGER NOT NULL CHECK(received_at_epoch_s >= 0),
  recovery_deadline_epoch_s INTEGER NOT NULL
    CHECK(recovery_deadline_epoch_s >= received_at_epoch_s),
  state TEXT NOT NULL CHECK(state IN ('prepared', 'completed')),
  completed_at_epoch_s INTEGER,
  CHECK(
    (state = 'prepared' AND completed_at_epoch_s IS NULL) OR
    (state = 'completed' AND completed_at_epoch_s IS NOT NULL)
  )
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_authenticator_counters (
  issuer TEXT NOT NULL,
  relying_party_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  sign_count INTEGER NOT NULL CHECK(sign_count >= 0),
  backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN (0, 1)),
  backup_state INTEGER NOT NULL CHECK(backup_state IN (0, 1)),
  PRIMARY KEY(issuer, relying_party_id, credential_id)
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_signer_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  key_id TEXT NOT NULL,
  key_version TEXT NOT NULL,
  public_key_base64 TEXT NOT NULL,
  public_key_digest_sha256 TEXT NOT NULL,
  public_key_spki_sha256 TEXT NOT NULL,
  workload TEXT NOT NULL,
  purpose TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_target_normalizer_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  normalizer_id TEXT NOT NULL,
  normalizer_version TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_signing_handoffs (
  pa_reservation_id TEXT PRIMARY KEY
    REFERENCES certificate_v2_reservations(pa_reservation_id),
  authorization_jti TEXT NOT NULL UNIQUE,
  attempt_id TEXT NOT NULL UNIQUE,
  lease_digest_sha256 TEXT NOT NULL UNIQUE,
  lease_json TEXT NOT NULL,
  signer_key_id TEXT NOT NULL,
  signer_key_version TEXT NOT NULL,
  signer_public_key_digest_sha256 TEXT NOT NULL,
  signer_public_key_spki_sha256 TEXT NOT NULL,
  signer_workload TEXT NOT NULL,
  signer_purpose TEXT NOT NULL,
  signature_base64 TEXT,
  signed_authorization_json TEXT,
  state TEXT NOT NULL CHECK(state IN (
    'prepared', 'signature-unknown', 'ready', 'released-pending-accept',
    'accepted', 'not-accepted', 'expired-unreleased'
  )),
  prepared_at_epoch_s INTEGER NOT NULL CHECK(prepared_at_epoch_s >= 0),
  signed_at_epoch_s INTEGER,
  released_at_epoch_s INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS certificate_v2_handoff_receipts (
  authorization_jti TEXT PRIMARY KEY
    REFERENCES certificate_v2_reservations(authorization_jti),
  receipt_id TEXT NOT NULL UNIQUE,
  nonce_base64 TEXT NOT NULL UNIQUE,
  evidence_digest_sha256 TEXT NOT NULL UNIQUE,
  evidence_json TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN ('accepted', 'not-accepted')),
  recorded_at_epoch_s INTEGER NOT NULL CHECK(recorded_at_epoch_s >= 0),
  resulting_state TEXT NOT NULL CHECK(resulting_state IN ('executing', 'abandoned'))
) STRICT;
PRAGMA application_id = 1129467969;
PRAGMA user_version = 7;
COMMIT;
