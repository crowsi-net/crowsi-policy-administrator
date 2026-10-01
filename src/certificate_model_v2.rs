use crowsi_control_contracts::{
    CertificateActionV2, CertificateApprovalEvidenceV2, CertificateAuthorityOutcomeEvidenceV2,
    CertificateExecutionCommandV2, CertificateExecutionGrantV2, CertificateManagerCommitEvidenceV2,
    CertificateManagerHandoffEvidenceV2, CertificatePolicyDecisionV2,
    CertificateRevocationEvidenceV2, CertificateSignatureAlgorithmV2,
};

/// Proof that a local, mutually authenticated certificate-manager channel was
/// established by an adapter inside this crate.
///
/// No production constructor exists yet, so provider-affecting certificate
/// handoff remains fail-closed until that adapter is implemented.
pub struct AuthenticatedCertificateManagerChannelV2 {
    _sealed: (),
}

#[cfg(test)]
impl AuthenticatedCertificateManagerChannelV2 {
    pub(crate) const fn for_simulation() -> Self {
        Self { _sealed: () }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateAdministratorPolicyV2 {
    pub security_domain: String,
    pub deployment_id: String,
    pub authorization_issuer: String,
    pub authorization_audience: String,
    pub authorization_provider: String,
    pub authorization_policy_id: String,
    pub authorization_policy_digest_sha256: String,
    pub authorization_verifier_key_id: String,
    pub authorization_signer_key_version: String,
    pub authorization_signer_public_key_base64: String,
    pub authorization_signer_public_key_digest_sha256: String,
    pub authorization_signer_public_key_spki_sha256: String,
    pub authorization_signer_workload: String,
    pub authorization_signer_purpose: String,
    pub authorization_signature_algorithm: CertificateSignatureAlgorithmV2,
    pub authorization_channel: String,
    pub target_resource_normalizer_id: String,
    pub target_resource_normalizer_version: String,
    pub approval_issuer: String,
    pub approval_audience: String,
    pub approval_relying_party_id: String,
    pub approval_origin: String,
    pub approval_challenge_authority_ref: String,
    pub authority_outcome_issuer: String,
    pub authority_outcome_audience: String,
    pub certificate_authority_id: String,
    pub authority_receipt_key_id: String,
    pub authority_receipt_key_version: String,
    pub authority_receipt_public_key_spki_sha256: String,
    pub authority_receipt_key_purpose: String,
    pub manager_commit_issuer: String,
    pub manager_commit_audience: String,
    pub manager_commit_workload: String,
    pub manager_commit_key_id: String,
    pub manager_commit_key_version: String,
    pub manager_commit_public_key_spki_sha256: String,
    pub manager_commit_key_purpose: String,
    pub manager_handoff_issuer: String,
    pub manager_handoff_audience: String,
    pub manager_handoff_workload: String,
    pub manager_handoff_key_id: String,
    pub manager_handoff_key_version: String,
    pub manager_handoff_public_key_spki_sha256: String,
    pub manager_handoff_key_purpose: String,
    pub revocation_issuer: String,
    pub revocation_audience: String,
    pub trust_revision: u64,
    pub max_authorization_ttl_seconds: u64,
    pub max_revocation_snapshot_age_seconds: u64,
    pub max_completion_recovery_seconds: u64,
}

pub struct CertificateReservationInputV2<'a> {
    pub decision: &'a CertificatePolicyDecisionV2,
    pub grant: &'a CertificateExecutionGrantV2,
    pub command: &'a CertificateExecutionCommandV2,
    pub approval_evidence: Option<&'a CertificateApprovalEvidenceV2>,
    pub revocation_evidence: &'a CertificateRevocationEvidenceV2,
    pub target_resource_raw_input: &'a str,
}

pub struct CertificateCompletionInputV2<'a> {
    pub authority_evidence: &'a CertificateAuthorityOutcomeEvidenceV2,
    pub manager_commit_evidence: &'a CertificateManagerCommitEvidenceV2,
}

pub struct CertificateHandoffInputV2<'a> {
    pub evidence: &'a CertificateManagerHandoffEvidenceV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateHandoffReceiptAckV2 {
    pub authorization_jti: String,
    pub receipt_id: String,
    pub evidence_digest_sha256: String,
    pub disposition: String,
    pub resulting_state: String,
    pub recorded_at_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateCompletionReceiptV2 {
    pub authorization_jti: String,
    pub commit_id: String,
    pub authority_evidence_digest_sha256: String,
    pub manager_commit_digest_sha256: String,
    pub disposition: String,
    pub received_at_epoch_s: u64,
    pub completed_at_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateExecutionReservationV2 {
    pub authorization_jti: String,
    pub pa_reservation_id: String,
    pub action: CertificateActionV2,
    pub security_domain: String,
    pub deployment_id: String,
    pub target_resource_id: String,
    pub current_fence: u64,
    pub request_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub expected_resource_version: u64,
    pub expires_at_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateExecutionStatusV2 {
    pub authorization_jti: String,
    pub action: CertificateActionV2,
    pub target_resource_id: String,
    pub current_fence: u64,
    pub state: String,
    pub lease_digest_sha256: Option<String>,
    pub unknown_evidence_digest_sha256: Option<String>,
}
