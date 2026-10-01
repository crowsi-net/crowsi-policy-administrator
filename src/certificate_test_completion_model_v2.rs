use base64::{Engine, engine::general_purpose::STANDARD};
use crowsi_control_contracts::{
    CertificateAuthorityOutcomeEvidenceV2, CertificateManagerCommitEvidenceV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
};

use crate::CertificateCompletionInputV2;

pub(crate) struct CompletionFixture {
    pub(crate) authority: CertificateAuthorityOutcomeEvidenceV2,
    pub(crate) manager: CertificateManagerCommitEvidenceV2,
}

impl CompletionFixture {
    pub(crate) fn input(&self) -> CertificateCompletionInputV2<'_> {
        CertificateCompletionInputV2 {
            authority_evidence: &self.authority,
            manager_commit_evidence: &self.manager,
        }
    }
}

pub(crate) fn placeholder_receipt(
    key_id: &str,
    version: &str,
    spki: &str,
    purpose: &str,
) -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: key_id.into(),
        key_version: version.into(),
        public_key_spki_sha256: spki.into(),
        key_purpose: purpose.into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([0_u8; 64]),
    }
}
