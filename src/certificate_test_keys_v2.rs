pub(crate) use crate::certificate_test_policy_v2::policy;
pub(crate) use crate::certificate_test_signatures_v2::{
    approval_signature, authority_outcome_signature, decision_signature, grant_signature,
    manager_commit_signature, manager_handoff_signature, placeholder, revocation_signature,
};
pub(crate) use crate::certificate_test_trust_v2::trusted_keys;

pub(crate) const NOW: u64 = 1_785_283_200;
pub(crate) const NOW_TEXT: &str = "2026-07-29T00:00:00.000Z";
pub(crate) const SUBJECT: &str = "subject.pairwise.nerp";
pub(crate) const POLICY_ID: &str = "policy.certificate.lifecycle";
pub(crate) const APPROVAL_ISSUER: &str = "https://ihat.online/approval";
pub(crate) const APPROVAL_AUDIENCE: &str = "service://crowsi/policy-administrator";
pub(crate) const REVOCATION_ISSUER: &str = "https://ihat.online/revocation";
pub(crate) const REVOCATION_AUDIENCE: &str = "service://crowsi/revocation";
pub(crate) const OUTCOME_ISSUER: &str = "authority://crowsi/certificate";
pub(crate) const OUTCOME_AUDIENCE: &str = "service://crowsi/policy-administrator";
pub(crate) const COMMIT_ISSUER: &str = "service://crowsi/certificate-manager";
pub(crate) const COMMIT_AUDIENCE: &str = "service://crowsi/policy-administrator";
pub(crate) const HANDOFF_ISSUER: &str = "service://crowsi/certificate-manager";
pub(crate) const HANDOFF_AUDIENCE: &str = "service://crowsi/policy-administrator";
pub(crate) const LEASE_SIGNER_SEED: u8 = 55;

pub(crate) const DECISION_KEY: (&str, u8) = ("decision.certificate.key", 11);
pub(crate) const GRANT_KEY: (&str, u8) = ("grant.certificate.key", 22);
pub(crate) const APPROVAL_KEY: (&str, u8) = ("approval.certificate.key", 33);
pub(crate) const REVOCATION_KEY: (&str, u8) = ("revocation.certificate.key", 44);
pub(crate) const AUTHORITY_RECEIPT_KEY: (&str, u8) = ("authority.receipt.key", 66);
pub(crate) const MANAGER_COMMIT_KEY: (&str, u8) = ("manager.commit.key", 77);
pub(crate) const MANAGER_HANDOFF_KEY: (&str, u8) = ("manager.handoff.key", 88);
