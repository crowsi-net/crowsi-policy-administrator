use crowsi_control_contracts::{CertificateActionV2, CertificateManagerHandoffDispositionV2};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificateHandoffInputV2,
    CertificatePolicyAdministratorV2, SimulationFixedClock,
    certificate_test_chain_v2::{administrator, chain, fence, pending},
    certificate_test_handoff_v2::{accepted, evidence},
    certificate_test_keys_v2::{NOW, SUBJECT, manager_handoff_signature, policy, trusted_keys},
    certificate_test_signer_v2::TestSigner,
    clock::AdministratorClock,
};

#[test]
fn manager_acceptance_and_pa_ack_loss_recover_exactly_across_restarts() {
    let root = private_root();
    let ledger = root.join("certificate-ledger.sqlite3");
    let mut administrator = open(&ledger, "2026-07-29T00:00:00.000Z");
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let fixture = chain(CertificateActionV2::Issue, 71, 0, None);
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    administrator
        .sign_certificate_execution_v2(&channel, &fixture.command.jti, &mut TestSigner::signed())
        .unwrap();
    let signed = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    let durable_manager_receipt = accepted(&signed);
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 1);
    assert_eq!(
        administrator
            .certificate_execution_status_v2(&fixture.command.jti)
            .unwrap()
            .state,
        "reserved"
    );
    drop(administrator);

    let mut restarted = open(&ledger, "2026-07-29T00:00:10.000Z");
    let input = CertificateHandoffInputV2 {
        evidence: &durable_manager_receipt,
    };
    let first = restarted
        .accept_released_certificate_execution_v2(&channel, &input)
        .unwrap();
    assert_eq!(first.resulting_state, "executing");
    assert_eq!(fence(&restarted, "lifecycle-mutation"), 1);
    assert_eq!(pending(&restarted), 0);
    drop(restarted);

    let mut ack_lost = open(&ledger, "2026-07-29T00:02:00.000Z");
    let replay = ack_lost
        .accept_released_certificate_execution_v2(&channel, &input)
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(
        ack_lost
            .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
            .unwrap(),
        signed
    );
    let mut altered = durable_manager_receipt;
    altered.receipt_id.push_str(".altered");
    altered.signed = manager_handoff_signature(&altered);
    assert!(matches!(
        ack_lost.accept_released_certificate_execution_v2(
            &channel,
            &CertificateHandoffInputV2 { evidence: &altered }
        ),
        Err(AdministratorError::Replay)
    ));
    drop(ack_lost);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn expired_provisional_accept_is_rejected_then_not_accepted_unlocks() {
    let fixture = chain(CertificateActionV2::Issue, 72, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    administrator
        .sign_certificate_execution_v2(&channel, &fixture.command.jti, &mut TestSigner::signed())
        .unwrap();
    let signed = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    let provisional = accepted(&signed);
    administrator.clock = AdministratorClock::simulation(
        SimulationFixedClock::new("2026-07-29T00:01:00.000Z").unwrap(),
    );
    assert!(matches!(
        administrator.accept_released_certificate_execution_v2(
            &channel,
            &CertificateHandoffInputV2 {
                evidence: &provisional
            }
        ),
        Err(AdministratorError::Time)
    ));
    assert_eq!(pending(&administrator), 1);
    let aborted = evidence(
        &signed,
        CertificateManagerHandoffDispositionV2::NotAccepted,
        NOW + 60,
    );
    let ack = administrator
        .accept_released_certificate_execution_v2(
            &channel,
            &CertificateHandoffInputV2 { evidence: &aborted },
        )
        .unwrap();
    assert_eq!(ack.resulting_state, "abandoned");
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 0);
}

fn open(path: &std::path::Path, now: &str) -> CertificatePolicyAdministratorV2 {
    CertificatePolicyAdministratorV2::open_with_fixed_clock_for_simulation(
        path,
        policy(),
        trusted_keys(),
        SimulationFixedClock::new(now).unwrap(),
    )
    .unwrap()
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
    let path = std::env::temp_dir().join(format!("crowsi-pa-handoff-{suffix}"));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}
