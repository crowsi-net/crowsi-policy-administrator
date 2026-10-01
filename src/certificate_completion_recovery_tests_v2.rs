use crowsi_control_contracts::{CertificateActionV2, CertificateExecutionDispositionV2};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2,
    SimulationFixedClock,
    certificate_test_chain_v2::chain,
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::{SUBJECT, manager_commit_signature, policy, trusted_keys},
    certificate_test_signer_v2::sign_and_release,
};

#[test]
fn prepared_completion_survives_ttl_restart_and_ack_replay_is_exact() {
    let root = private_root();
    let ledger = root.join("certificate-ledger.sqlite3");
    let mut administrator = CertificatePolicyAdministratorV2::open_with_fixed_clock_for_simulation(
        &ledger,
        policy(),
        trusted_keys(),
        SimulationFixedClock::new("2026-07-29T00:00:00.000Z").unwrap(),
    )
    .unwrap();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let fixture = chain(CertificateActionV2::Issue, 52, 0, None);
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
    let evidence = completion(
        &fixture,
        &signed,
        52,
        CertificateExecutionDispositionV2::Completed,
    );
    assert!(
        administrator
            .prepare_certificate_completion_v2(&evidence.input())
            .unwrap()
            .is_none()
    );
    drop(administrator);

    let mut recovered = CertificatePolicyAdministratorV2::open_with_fixed_clock_for_simulation(
        &ledger,
        policy(),
        trusted_keys(),
        SimulationFixedClock::new("2026-07-29T00:02:00.000Z").unwrap(),
    )
    .unwrap();
    let first = recovered
        .complete_certificate_execution_v2(&channel, &evidence.input())
        .unwrap();
    let replay = recovered
        .complete_certificate_execution_v2(&channel, &evidence.input())
        .unwrap();
    assert_eq!(first, replay);
    let mut altered = evidence;
    altered.manager.state_revision += 1;
    altered.manager.signed = manager_commit_signature(&altered.manager);
    assert!(matches!(
        recovered.complete_certificate_execution_v2(&channel, &altered.input()),
        Err(AdministratorError::Replay)
    ));
    drop(recovered);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_completion_delivery_after_evidence_ttl_uses_signed_recovery_deadline() {
    let root = private_root();
    let ledger = root.join("certificate-late-delivery.sqlite3");
    let mut administrator = CertificatePolicyAdministratorV2::open_with_fixed_clock_for_simulation(
        &ledger,
        policy(),
        trusted_keys(),
        SimulationFixedClock::new("2026-07-29T00:00:00.000Z").unwrap(),
    )
    .unwrap();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let fixture = chain(CertificateActionV2::Issue, 53, 0, None);
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
    let durable_outbox = completion(
        &fixture,
        &signed,
        53,
        CertificateExecutionDispositionV2::Completed,
    );
    drop(administrator);

    let mut restarted = CertificatePolicyAdministratorV2::open_with_fixed_clock_for_simulation(
        &ledger,
        policy(),
        trusted_keys(),
        SimulationFixedClock::new("2026-07-29T00:02:00.000Z").unwrap(),
    )
    .unwrap();
    let receipt = restarted
        .complete_certificate_execution_v2(&channel, &durable_outbox.input())
        .unwrap();
    assert_eq!(receipt.authorization_jti, fixture.command.jti);
    assert_eq!(state(&restarted, &receipt.authorization_jti), "consumed");
    drop(restarted);
    std::fs::remove_dir_all(root).unwrap();
}

fn state(administrator: &CertificatePolicyAdministratorV2, jti: &str) -> String {
    administrator
        .certificate_execution_status_v2(jti)
        .unwrap()
        .state
}

fn private_root() -> std::path::PathBuf {
    use std::{
        fs::DirBuilder,
        os::unix::fs::DirBuilderExt,
        time::{SystemTime, UNIX_EPOCH},
    };
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("crowsi-pa-completion-{suffix}"));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}
