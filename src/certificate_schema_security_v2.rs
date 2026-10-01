pub(super) const EXPECTED: [(&str, &str); 7] = [
    (
        "certificate_v2_signing_handoffs",
        "CREATE TABLE certificate_v2_signing_handoffs (
          pa_reservation_id TEXT PRIMARY KEY
            REFERENCES certificate_v2_reservations(pa_reservation_id),
          authorization_jti TEXT NOT NULL UNIQUE,
          attempt_id TEXT NOT NULL UNIQUE,
          lease_digest_sha256 TEXT NOT NULL UNIQUE,
          lease_json TEXT NOT NULL, signer_key_id TEXT NOT NULL,
          signer_key_version TEXT NOT NULL,
          signer_public_key_digest_sha256 TEXT NOT NULL,
          signer_public_key_spki_sha256 TEXT NOT NULL,
          signer_workload TEXT NOT NULL, signer_purpose TEXT NOT NULL,
          signature_base64 TEXT, signed_authorization_json TEXT,
          state TEXT NOT NULL CHECK(state IN (
            'prepared', 'signature-unknown', 'ready', 'released-pending-accept',
            'accepted', 'not-accepted', 'expired-unreleased'
          )),
          prepared_at_epoch_s INTEGER NOT NULL CHECK(prepared_at_epoch_s >= 0),
          signed_at_epoch_s INTEGER, released_at_epoch_s INTEGER
        ) STRICT",
    ),
    (
        "certificate_v2_target_normalizer_binding",
        "CREATE TABLE certificate_v2_target_normalizer_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          normalizer_id TEXT NOT NULL, normalizer_version TEXT NOT NULL
        ) STRICT",
    ),
    (
        "certificate_v2_reservations",
        "CREATE TABLE certificate_v2_reservations (
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
          action TEXT NOT NULL, fence_scope TEXT NOT NULL,
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          release_id TEXT NOT NULL,
          release_digest_sha256 TEXT NOT NULL,
          deployment_provenance_ref TEXT NOT NULL,
          policy_id TEXT NOT NULL, policy_digest_sha256 TEXT NOT NULL,
          pairwise_subject TEXT NOT NULL,
          service_id TEXT NOT NULL, workload TEXT NOT NULL, profile TEXT NOT NULL,
          requester_pairwise_subject TEXT NOT NULL,
          approver_pairwise_subject TEXT,
          identity_revocation_epoch INTEGER NOT NULL
            CHECK(identity_revocation_epoch >= 0),
          previous_identity_revocation_epoch INTEGER NOT NULL
            CHECK(previous_identity_revocation_epoch >= 0),
          target_resource_id TEXT NOT NULL, provider TEXT NOT NULL,
          previous_fence INTEGER NOT NULL CHECK(previous_fence >= 0),
          current_fence INTEGER NOT NULL CHECK(current_fence >= 0),
          expected_resource_version INTEGER NOT NULL
            CHECK(expected_resource_version >= 0),
          command_json TEXT NOT NULL, decision_json TEXT NOT NULL,
          grant_json TEXT NOT NULL,
          reserved_at_epoch_s INTEGER NOT NULL CHECK(reserved_at_epoch_s >= 0),
          issued_at_epoch_s INTEGER NOT NULL CHECK(issued_at_epoch_s >= 0),
          expires_at_epoch_s INTEGER NOT NULL
            CHECK(expires_at_epoch_s > issued_at_epoch_s),
          state TEXT NOT NULL CHECK(state IN (
            'reserved', 'executing', 'result-unknown', 'consumed', 'reconciled', 'abandoned'
          )),
          previous_lifecycle_revocation_epoch INTEGER NOT NULL
            CHECK(previous_lifecycle_revocation_epoch >= 0),
          lifecycle_revocation_epoch INTEGER NOT NULL
            CHECK(lifecycle_revocation_epoch >= 0),
          unknown_evidence_digest_sha256 TEXT
        ) STRICT",
    ),
    (
        "certificate_v2_ledger_binding",
        "CREATE TABLE certificate_v2_ledger_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          authorization_issuer TEXT NOT NULL,
          authorization_audience TEXT NOT NULL,
          authorization_provider TEXT NOT NULL,
          authorization_policy_id TEXT NOT NULL,
          authorization_policy_digest_sha256 TEXT NOT NULL,
          authorization_verifier_key_id TEXT NOT NULL,
          revocation_issuer TEXT NOT NULL, revocation_audience TEXT NOT NULL,
          trust_revision INTEGER NOT NULL CHECK(trust_revision > 0)
        ) STRICT",
    ),
    (
        "certificate_v2_resource_fences",
        "CREATE TABLE certificate_v2_resource_fences (
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          provider TEXT NOT NULL, target_resource_id TEXT NOT NULL,
          fence_scope TEXT NOT NULL,
          fence INTEGER NOT NULL CHECK(fence >= 0),
          PRIMARY KEY(
            security_domain, deployment_id, provider, target_resource_id, fence_scope
          )
        ) STRICT",
    ),
    (
        "certificate_v2_revocation_epochs",
        "CREATE TABLE certificate_v2_revocation_epochs (
          revocation_issuer TEXT NOT NULL, security_domain TEXT NOT NULL,
          pairwise_subject TEXT NOT NULL,
          epoch INTEGER NOT NULL CHECK(epoch >= 0),
          PRIMARY KEY(revocation_issuer, security_domain, pairwise_subject)
        ) STRICT",
    ),
    (
        "certificate_v2_handoff_receipts",
        "CREATE TABLE certificate_v2_handoff_receipts (
          authorization_jti TEXT PRIMARY KEY
            REFERENCES certificate_v2_reservations(authorization_jti),
          receipt_id TEXT NOT NULL UNIQUE,
          nonce_base64 TEXT NOT NULL UNIQUE,
          evidence_digest_sha256 TEXT NOT NULL UNIQUE,
          evidence_json TEXT NOT NULL,
          disposition TEXT NOT NULL CHECK(disposition IN ('accepted', 'not-accepted')),
          recorded_at_epoch_s INTEGER NOT NULL CHECK(recorded_at_epoch_s >= 0),
          resulting_state TEXT NOT NULL CHECK(resulting_state IN ('executing', 'abandoned'))
        ) STRICT",
    ),
];
