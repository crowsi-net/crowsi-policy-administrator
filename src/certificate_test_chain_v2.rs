use crowsi_control_contracts::{
    CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2, CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2,
    CERTIFICATE_POLICY_DECISION_SCHEMA_V2, CertificateActionV2, CertificateDecisionEffectV2,
    CertificateExecutionCommandV2, CertificateExecutionGrantV2, CertificateOperationBindingV2,
    CertificatePayloadV2, CertificatePolicyDecisionV2, CertificateSignatureAlgorithmV2,
};

use crate::{
    CertificatePolicyAdministratorV2, CertificateReservationInputV2, SimulationFixedClock,
    certificate_test_binding_v2::{BindingFixture, binding},
    certificate_test_keys_v2::{
        NOW, NOW_TEXT, decision_signature, grant_signature, placeholder, policy, trusted_keys,
    },
};

pub(crate) struct ChainFixture {
    pub(crate) decision: CertificatePolicyDecisionV2,
    pub(crate) grant: CertificateExecutionGrantV2,
    pub(crate) command: CertificateExecutionCommandV2,
    pub(crate) parts: BindingFixture,
}

impl ChainFixture {
    pub(crate) fn input(&self) -> CertificateReservationInputV2<'_> {
        CertificateReservationInputV2 {
            decision: &self.decision,
            grant: &self.grant,
            command: &self.command,
            approval_evidence: self.parts.approval.as_ref(),
            revocation_evidence: &self.parts.revocation,
            target_resource_raw_input: &self.parts.binding.target.target_resource_id,
        }
    }
}

pub(crate) fn chain(
    action: CertificateActionV2,
    serial: u64,
    previous_fence: u64,
    operation: Option<CertificateOperationBindingV2>,
) -> ChainFixture {
    let parts = binding(action, serial, previous_fence, operation);
    let mut decision = CertificatePolicyDecisionV2 {
        schema: CERTIFICATE_POLICY_DECISION_SCHEMA_V2.into(),
        decision_id: format!("decision.certificate.{serial:04}"),
        request_digest_sha256: "10".repeat(32),
        action,
        binding: parts.binding.clone(),
        effect: CertificateDecisionEffectV2::Permit,
        issued_at_epoch_s: NOW - 20,
        expires_at_epoch_s: NOW + 280,
        signed: placeholder("decision.certificate.key"),
    };
    decision.signed = decision_signature(&decision);
    let mut grant = CertificateExecutionGrantV2 {
        schema: CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2.into(),
        grant_id: format!("grant.certificate.{serial:04}"),
        jti: format!("grant.jti.certificate.{serial:04}"),
        decision_id: decision.decision_id.clone(),
        decision_digest_sha256: decision.certificate_digest_sha256(),
        request_digest_sha256: decision.request_digest_sha256.clone(),
        action,
        binding: parts.binding.clone(),
        issued_at_epoch_s: NOW - 10,
        expires_at_epoch_s: NOW + 110,
        use_limit: 1,
        signed: placeholder("grant.certificate.key"),
    };
    grant.signed = grant_signature(&grant);
    let command = CertificateExecutionCommandV2 {
        schema: CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2.into(),
        authorization_id: format!("authorization.certificate.{serial:04}"),
        jti: format!("authorization.jti.{serial:04}"),
        pa_reservation_id: format!("pa.reservation.certificate.{serial:04}"),
        operation_id: format!("operation.certificate.{serial:04}"),
        request_digest_sha256: decision.request_digest_sha256.clone(),
        action,
        binding: parts.binding.clone(),
        decision_id: decision.decision_id.clone(),
        decision_digest_sha256: decision.certificate_digest_sha256(),
        grant_id: grant.grant_id.clone(),
        grant_digest_sha256: grant.certificate_digest_sha256(),
        signature_key_id: "key.policy.administrator".into(),
        signature_key_version: policy().authorization_signer_key_version,
        signature_public_key_spki_sha256: policy().authorization_signer_public_key_spki_sha256,
        signature_key_purpose: policy().authorization_signer_purpose,
        signature_algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        related_authorization_jti: None,
        issued_at_epoch_s: NOW - 5,
        expires_at_epoch_s: NOW + 25,
        one_use: true,
    };
    ChainFixture {
        decision,
        grant,
        command,
        parts,
    }
}

pub(crate) fn administrator() -> CertificatePolicyAdministratorV2 {
    CertificatePolicyAdministratorV2::in_memory_for_simulation(
        policy(),
        trusted_keys(),
        SimulationFixedClock::new(NOW_TEXT).unwrap(),
    )
    .unwrap()
}

pub(crate) fn rebind(fixture: &mut ChainFixture) {
    fixture.decision.binding = fixture.parts.binding.clone();
    fixture.decision.signed = decision_signature(&fixture.decision);
    fixture.grant.binding = fixture.parts.binding.clone();
    fixture.grant.decision_digest_sha256 = fixture.decision.certificate_digest_sha256();
    fixture.grant.signed = grant_signature(&fixture.grant);
    fixture.command.binding = fixture.parts.binding.clone();
    fixture.command.decision_digest_sha256 = fixture.decision.certificate_digest_sha256();
    fixture.command.grant_digest_sha256 = fixture.grant.certificate_digest_sha256();
}

pub(crate) fn fence(administrator: &CertificatePolicyAdministratorV2, scope: &str) -> i64 {
    administrator
        .connection
        .query_row(
            "SELECT fence FROM certificate_v2_resource_fences WHERE fence_scope = ?",
            [scope],
            |row| row.get(0),
        )
        .unwrap()
}

pub(crate) fn pending(administrator: &CertificatePolicyAdministratorV2) -> i64 {
    administrator
        .connection
        .query_row(
            "SELECT COUNT(*) FROM certificate_v2_fence_reservations",
            [],
            |row| row.get(0),
        )
        .unwrap()
}
