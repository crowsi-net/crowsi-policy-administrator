use crate::support;

use crowsi_control_contracts::{
    CanonicalPayloadV1, EnforcementOutcome, EnforcementReceiptV2, PEP_EXECUTION_LEASE_SCHEMA_V2,
};
use crowsi_policy_administrator::{
    EnforcementPointV2, PepExecutionLeaseV2, PepExecutionUncertainV2,
};
use support::V2Fixture;

struct InMemoryCasPep {
    target_id: String,
    resource_version: String,
    fence_epoch: u64,
    applied: Option<EnforcementReceiptV2>,
    rejected: EnforcementReceiptV2,
}

impl EnforcementPointV2 for InMemoryCasPep {
    fn compare_and_swap(
        &mut self,
        lease: &PepExecutionLeaseV2,
    ) -> Result<EnforcementReceiptV2, PepExecutionUncertainV2> {
        let command = &lease.command;
        let fresh_fence =
            command.target_id == self.target_id && command.fence_epoch > self.fence_epoch;
        if !fresh_fence {
            return Ok(self.rejected.clone());
        }
        self.fence_epoch = command.fence_epoch;
        if command.expected_resource_version != self.resource_version {
            return Ok(self.rejected.clone());
        }
        self.resource_version = format!("incus-etag-{}", 7 + self.fence_epoch);
        Ok(self.applied.take().expect("one application"))
    }
}

#[test]
fn provider_port_applies_only_the_expected_version_and_next_fence() {
    let first = V2Fixture::new().expect("first fixture");
    let second = V2Fixture::version(2, 1, 2).expect("second fixture");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve_v2(&first.reservation())
        .expect("reservation");
    let lease = administrator
        .begin_execution_v2(&first.command.jti)
        .expect("lease");
    let mut rejected = first.receipt().expect("rejected receipt");
    rejected.outcome = EnforcementOutcome::Rejected;
    rejected.resulting_resource_version = Some("incus-etag-8".into());
    rejected.signed = first
        .base
        .authorities
        .receipt
        .sign(&rejected)
        .expect("sign");
    let mut pep = InMemoryCasPep {
        target_id: first.command.target_id.clone(),
        resource_version: "incus-etag-8".into(),
        fence_epoch: 0,
        applied: Some(second.receipt().expect("applied receipt")),
        rejected,
    };
    let rejected = pep.compare_and_swap(&lease).expect("known rejection");
    assert_eq!(rejected.outcome, EnforcementOutcome::Rejected);
    assert_eq!(pep.fence_epoch, 1);
    let replay = pep.compare_and_swap(&lease).expect("known stale fence");
    assert_eq!(replay.outcome, EnforcementOutcome::Rejected);
    assert_eq!(pep.resource_version, "incus-etag-8");
    let second_lease = PepExecutionLeaseV2 {
        schema: PEP_EXECUTION_LEASE_SCHEMA_V2.into(),
        reservation_id: second.command.release_reservation_id.clone(),
        command_digest: second.command.payload_digest(),
        command: second.command.clone(),
        reserved_at: "2026-07-29T00:02:00.000Z".into(),
    };
    let applied = pep.compare_and_swap(&second_lease).expect("next CAS");
    assert_eq!(applied.outcome, EnforcementOutcome::Applied);
    assert_eq!(pep.fence_epoch, 2);
    assert_eq!(pep.resource_version, "incus-etag-9");
}
