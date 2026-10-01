pub(super) const EXPECTED: [(&str, &str); 5] = [
    (
        "certificate_v2_outcome_authority_binding",
        "CREATE TABLE certificate_v2_outcome_authority_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          issuer TEXT NOT NULL, audience TEXT NOT NULL, authority_id TEXT NOT NULL,
          receipt_key_id TEXT NOT NULL, receipt_key_version TEXT NOT NULL,
          receipt_public_key_spki_sha256 TEXT NOT NULL,
          receipt_key_purpose TEXT NOT NULL
        ) STRICT",
    ),
    (
        "certificate_v2_manager_commit_binding",
        "CREATE TABLE certificate_v2_manager_commit_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          issuer TEXT NOT NULL, audience TEXT NOT NULL, workload TEXT NOT NULL,
          commit_key_id TEXT NOT NULL, commit_key_version TEXT NOT NULL,
          commit_public_key_spki_sha256 TEXT NOT NULL,
          commit_key_purpose TEXT NOT NULL
        ) STRICT",
    ),
    (
        "certificate_v2_manager_handoff_binding",
        "CREATE TABLE certificate_v2_manager_handoff_binding (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          issuer TEXT NOT NULL, audience TEXT NOT NULL, workload TEXT NOT NULL,
          receipt_key_id TEXT NOT NULL, receipt_key_version TEXT NOT NULL,
          receipt_public_key_spki_sha256 TEXT NOT NULL,
          receipt_key_purpose TEXT NOT NULL
        ) STRICT",
    ),
    (
        "certificate_v2_completion_evidence",
        "CREATE TABLE certificate_v2_completion_evidence (
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
        ) STRICT",
    ),
    (
        "certificate_v2_completion_inbox",
        "CREATE TABLE certificate_v2_completion_inbox (
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
        ) STRICT",
    ),
];
