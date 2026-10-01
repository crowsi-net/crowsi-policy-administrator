use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;

use crate::{
    ArtifactRole, KeyScope, P256TrustAnchorV2, TrustedKeys,
    certificate_test_key_material_v2::spki_digest,
    certificate_test_keys_v2::*,
};

pub(crate) fn trusted_keys() -> TrustedKeys {
    let mut keys = TrustedKeys::default();
    for (key, role) in [
        (DECISION_KEY, ArtifactRole::CertificatePolicyDecision),
        (GRANT_KEY, ArtifactRole::CertificateExecutionGrant),
    ] {
        keys.insert_ed25519(
            key.0,
            role,
            KeyScope::Policy(POLICY_ID.into()),
            Ed25519SigningKey::from_bytes(&[key.1; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
    }
    insert_external(
        &mut keys,
        APPROVAL_KEY,
        ArtifactRole::CertificateApprovalEvidence,
        KeyScope::Approval {
            issuer: APPROVAL_ISSUER.into(),
            audience: APPROVAL_AUDIENCE.into(),
        },
    );
    insert_external(
        &mut keys,
        REVOCATION_KEY,
        ArtifactRole::CertificateRevocationEvidence,
        KeyScope::Revocation {
            issuer: REVOCATION_ISSUER.into(),
            audience: REVOCATION_AUDIENCE.into(),
        },
    );
    insert_p256(
        &mut keys,
        AUTHORITY_RECEIPT_KEY,
        "certificate-authority-receipt",
        ArtifactRole::CertificateAuthorityOutcomeEvidence,
        KeyScope::AuthorityOutcome {
            issuer: OUTCOME_ISSUER.into(),
            audience: OUTCOME_AUDIENCE.into(),
            authority_id: "authority.crowsi.local".into(),
            security_domain: "security.crowsi".into(),
            deployment_id: "deployment.local".into(),
        },
    );
    insert_p256(
        &mut keys,
        MANAGER_COMMIT_KEY,
        "certificate-manager-commit-receipt",
        ArtifactRole::CertificateManagerCommitEvidence,
        KeyScope::ManagerCommit {
            issuer: COMMIT_ISSUER.into(),
            audience: COMMIT_AUDIENCE.into(),
            workload: "spiffe://crowsi.test/certificate-manager".into(),
            security_domain: "security.crowsi".into(),
            deployment_id: "deployment.local".into(),
        },
    );
    insert_p256(
        &mut keys,
        MANAGER_HANDOFF_KEY,
        "certificate-manager-handoff-receipt",
        ArtifactRole::CertificateManagerHandoffEvidence,
        KeyScope::ManagerHandoff {
            issuer: HANDOFF_ISSUER.into(),
            audience: HANDOFF_AUDIENCE.into(),
            workload: "spiffe://crowsi.test/certificate-manager".into(),
            security_domain: "security.crowsi".into(),
            deployment_id: "deployment.local".into(),
        },
    );
    keys
}

fn insert_external(keys: &mut TrustedKeys, key: (&str, u8), role: ArtifactRole, scope: KeyScope) {
    keys.insert_ed25519(
        key.0,
        role,
        scope,
        Ed25519SigningKey::from_bytes(&[key.1; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
}

fn insert_p256(
    keys: &mut TrustedKeys,
    key: (&str, u8),
    purpose: &str,
    role: ArtifactRole,
    scope: KeyScope,
) {
    let signing = P256SigningKey::from_slice(&[key.1; 32]).unwrap();
    keys.insert_p256_sec1(P256TrustAnchorV2 {
        key_id: key.0,
        key_version: "version.0001",
        spki_digest_sha256: &spki_digest(key.1),
        purpose,
        role,
        scope,
        sec1: signing.verifying_key().to_encoded_point(false).as_bytes(),
    })
    .unwrap();
}
