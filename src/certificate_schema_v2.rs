pub(super) const EXPECTED: [(&str, &str); 7] = [
    (
        "certificate_v2_approval_authority_binding",
        "CREATE TABLE certificate_v2_approval_authority_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          issuer TEXT NOT NULL, audience TEXT NOT NULL,
          relying_party_id TEXT NOT NULL, origin TEXT NOT NULL,
          challenge_authority_ref TEXT NOT NULL
        ) STRICT",
    ),
    (
        "certificate_v2_approval_uses",
        "CREATE TABLE certificate_v2_approval_uses (
          approval_id TEXT PRIMARY KEY,
          approval_evidence_digest_sha256 TEXT NOT NULL UNIQUE,
          challenge_id TEXT NOT NULL UNIQUE,
          challenge_nonce_base64 TEXT NOT NULL UNIQUE,
          pa_reservation_id TEXT NOT NULL UNIQUE
            REFERENCES certificate_v2_reservations(pa_reservation_id)
        ) STRICT",
    ),
    (
        "certificate_v2_authenticator_counters",
        "CREATE TABLE certificate_v2_authenticator_counters (
          issuer TEXT NOT NULL, relying_party_id TEXT NOT NULL,
          credential_id TEXT NOT NULL,
          sign_count INTEGER NOT NULL CHECK(sign_count >= 0),
          backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN (0, 1)),
          backup_state INTEGER NOT NULL CHECK(backup_state IN (0, 1)),
          PRIMARY KEY(issuer, relying_party_id, credential_id)
        ) STRICT",
    ),
    (
        "certificate_v2_fence_reservations",
        "CREATE TABLE certificate_v2_fence_reservations (
          pa_reservation_id TEXT PRIMARY KEY
            REFERENCES certificate_v2_reservations(pa_reservation_id),
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          provider TEXT NOT NULL, target_resource_id TEXT NOT NULL,
          fence_scope TEXT NOT NULL,
          previous_fence INTEGER NOT NULL CHECK(previous_fence >= 0),
          proposed_fence INTEGER NOT NULL CHECK(proposed_fence > previous_fence),
          UNIQUE(
            security_domain, deployment_id, provider, target_resource_id, fence_scope
          )
        ) STRICT",
    ),
    (
        "certificate_v2_lifecycle_epoch_reservations",
        "CREATE TABLE certificate_v2_lifecycle_epoch_reservations (
          pa_reservation_id TEXT PRIMARY KEY
            REFERENCES certificate_v2_reservations(pa_reservation_id),
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          provider TEXT NOT NULL, target_resource_id TEXT NOT NULL,
          previous_epoch INTEGER NOT NULL CHECK(previous_epoch >= 0),
          proposed_epoch INTEGER NOT NULL CHECK(proposed_epoch > previous_epoch),
          UNIQUE(security_domain, deployment_id, provider, target_resource_id)
        ) STRICT",
    ),
    (
        "certificate_v2_lifecycle_epochs",
        "CREATE TABLE certificate_v2_lifecycle_epochs (
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          provider TEXT NOT NULL, target_resource_id TEXT NOT NULL,
          epoch INTEGER NOT NULL CHECK(epoch >= 0),
          PRIMARY KEY(security_domain, deployment_id, provider, target_resource_id)
        ) STRICT",
    ),
    (
        "certificate_v2_signer_binding",
        "CREATE TABLE certificate_v2_signer_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          key_id TEXT NOT NULL,
          key_version TEXT NOT NULL,
          public_key_base64 TEXT NOT NULL,
          public_key_digest_sha256 TEXT NOT NULL,
          public_key_spki_sha256 TEXT NOT NULL,
          workload TEXT NOT NULL, purpose TEXT NOT NULL
        ) STRICT",
    ),
];
