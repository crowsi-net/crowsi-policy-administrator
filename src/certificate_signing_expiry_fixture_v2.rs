use crowsi_control_contracts::{CertificatePayloadV2, certificate_target_normalization_digest_v2};

use crate::{
    AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2,
    SimulationFixedClock,
    certificate_test_chain_v2::{ChainFixture, rebind},
    certificate_test_keys_v2::{
        SUBJECT, approval_signature, decision_signature, grant_signature, revocation_signature,
    },
    certificate_test_signer_v2::TestSigner,
    clock::AdministratorClock,
};

pub(crate) fn ready(administrator: &mut CertificatePolicyAdministratorV2, fixture: &ChainFixture) {
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    administrator
        .sign_certificate_execution_v2(
            &AuthenticatedCertificateManagerChannelV2::for_simulation(),
            &fixture.command.jti,
            &mut TestSigner::signed(),
        )
        .unwrap();
}

pub(crate) fn retarget(fixture: &mut ChainFixture, target: &str) {
    let binding = &mut fixture.parts.binding;
    binding.target.target_resource_id = target.into();
    binding.target.target_resource_normalization_digest_sha256 =
        certificate_target_normalization_digest_v2(
            &binding.target.provider,
            target,
            target,
            &binding.target.target_resource_normalizer_id,
            &binding.target.target_resource_normalizer_version,
        );
    let approval = fixture.parts.approval.as_mut().unwrap();
    approval.target_resource_id = target.into();
    approval.signed = approval_signature(approval);
    binding.approval_evidence_digest_sha256 = Some(approval.certificate_digest_sha256());
    rebind(fixture);
}

pub(crate) fn shift_validity(fixture: &mut ChainFixture, seconds: u64) {
    let approval = fixture.parts.approval.as_mut().unwrap();
    approval.issued_at_epoch_s += seconds;
    approval.expires_at_epoch_s += seconds;
    approval.signed = approval_signature(approval);
    let revocation = &mut fixture.parts.revocation;
    revocation.verified_at_epoch_s += seconds;
    revocation.signed = revocation_signature(revocation);
    let binding = &mut fixture.parts.binding;
    binding.approval_issued_at_epoch_s = Some(approval.issued_at_epoch_s);
    binding.approval_expires_at_epoch_s = Some(approval.expires_at_epoch_s);
    binding.approval_verified_at_epoch_s = Some(approval.issued_at_epoch_s);
    binding.approval_evidence_digest_sha256 = Some(approval.certificate_digest_sha256());
    binding.revocation.snapshot_digest_sha256 = revocation.certificate_digest_sha256();
    binding.revocation.snapshot_verified_at_epoch_s = revocation.verified_at_epoch_s;
    fixture.decision.issued_at_epoch_s += seconds;
    fixture.decision.expires_at_epoch_s += seconds;
    fixture.grant.issued_at_epoch_s += seconds;
    fixture.grant.expires_at_epoch_s += seconds;
    fixture.command.issued_at_epoch_s += seconds;
    fixture.command.expires_at_epoch_s += seconds;
    rebind(fixture);
    fixture.decision.signed = decision_signature(&fixture.decision);
    fixture.grant.signed = grant_signature(&fixture.grant);
}

pub(crate) fn expire_clock(administrator: &mut CertificatePolicyAdministratorV2) {
    administrator.clock = AdministratorClock::simulation(
        SimulationFixedClock::new("2026-07-29T00:01:00.000Z").unwrap(),
    );
}

pub(crate) fn states(
    administrator: &CertificatePolicyAdministratorV2,
    jti: &str,
) -> (String, String, i64) {
    administrator
        .connection
        .query_row(
            "SELECT h.state, r.state, h.signed_authorization_json IS NOT NULL
               FROM certificate_v2_signing_handoffs h
               JOIN certificate_v2_reservations r USING(pa_reservation_id)
              WHERE h.authorization_jti = ?",
            [jti],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

pub(crate) fn bootstrap(administrator: &mut CertificatePolicyAdministratorV2) {
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
}
