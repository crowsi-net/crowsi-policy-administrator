pub(super) const EXPECTED: [(&str, &str); 4] = [
    (
        "v2_enforcement_reservations",
        "CREATE TABLE v2_enforcement_reservations (
          command_jti TEXT PRIMARY KEY, grant_jti TEXT NOT NULL UNIQUE,
          release_id TEXT NOT NULL UNIQUE, release_digest TEXT NOT NULL UNIQUE,
          release_reservation_id TEXT NOT NULL UNIQUE, checkpoint_id TEXT NOT NULL,
          checkpoint_digest TEXT NOT NULL,
          checkpoint_sequence INTEGER NOT NULL CHECK(checkpoint_sequence > 0),
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          incident_id TEXT NOT NULL, target_id TEXT NOT NULL, provider TEXT NOT NULL,
          audience TEXT NOT NULL, action TEXT NOT NULL, purpose TEXT NOT NULL,
          channel TEXT NOT NULL, command_digest TEXT NOT NULL UNIQUE,
          command_json TEXT NOT NULL,
          previous_fence_epoch INTEGER NOT NULL CHECK(previous_fence_epoch >= 0),
          fence_epoch INTEGER NOT NULL CHECK(fence_epoch > 0),
          expected_resource_version TEXT NOT NULL, policy_snapshot_id TEXT NOT NULL,
          policy_snapshot_digest TEXT NOT NULL, reserved_at TEXT NOT NULL,
          command_issued_at TEXT NOT NULL, command_expires_at TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN (
            'reserved', 'executing', 'result-unknown',
            'applied', 'rejected', 'failed', 'partial'
          )), unknown_evidence_digest TEXT, outcome TEXT,
          receipt_id TEXT UNIQUE, receipt_digest TEXT,
          UNIQUE(security_domain, deployment_id, provider, target_id, fence_epoch)
        ) STRICT",
    ),
    (
        "v2_one_receipt_per_command",
        "CREATE UNIQUE INDEX v2_one_receipt_per_command
         ON v2_enforcement_reservations(command_jti)
         WHERE receipt_digest IS NOT NULL",
    ),
    (
        "v2_resource_fences",
        "CREATE TABLE v2_resource_fences (
          security_domain TEXT NOT NULL, deployment_id TEXT NOT NULL,
          provider TEXT NOT NULL, target_id TEXT NOT NULL,
          fence_epoch INTEGER NOT NULL CHECK(fence_epoch >= 0),
          PRIMARY KEY(security_domain, deployment_id, provider, target_id)
        ) STRICT",
    ),
    (
        "v2_signed_receipts",
        "CREATE TABLE v2_signed_receipts (
          command_jti TEXT PRIMARY KEY
            REFERENCES v2_enforcement_reservations(command_jti),
          receipt_id TEXT NOT NULL UNIQUE,
          receipt_digest TEXT NOT NULL UNIQUE,
          receipt_json TEXT NOT NULL
        ) STRICT",
    ),
];
