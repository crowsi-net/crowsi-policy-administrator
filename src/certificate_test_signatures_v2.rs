use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crowsi_control_contracts::{
    CertificateDetachedSignatureV2, CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2,
    CertificateReceiptSignatureV2, CertificateSignatureAlgorithmV2,
};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner,
};

use crate::{
    certificate_test_key_material_v2::spki_digest, certificate_test_keys_v2::*,
    crypto::bare_digest_bytes,
};

pub(crate) fn decision_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateDetachedSignatureV2 {
    signature(value, DECISION_KEY)
}

pub(crate) fn grant_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateDetachedSignatureV2 {
    signature(value, GRANT_KEY)
}

pub(crate) fn approval_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateDetachedSignatureV2 {
    signature(value, APPROVAL_KEY)
}

pub(crate) fn revocation_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateDetachedSignatureV2 {
    signature(value, REVOCATION_KEY)
}

pub(crate) fn authority_outcome_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateReceiptSignatureV2 {
    receipt_signature(
        value,
        AUTHORITY_RECEIPT_KEY,
        "certificate-authority-receipt",
    )
}

pub(crate) fn manager_commit_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateReceiptSignatureV2 {
    receipt_signature(
        value,
        MANAGER_COMMIT_KEY,
        "certificate-manager-commit-receipt",
    )
}

pub(crate) fn manager_handoff_signature<T: CertificatePayloadV2>(
    value: &T,
) -> CertificateReceiptSignatureV2 {
    receipt_signature(
        value,
        MANAGER_HANDOFF_KEY,
        "certificate-manager-handoff-receipt",
    )
}

pub(crate) fn placeholder(key_id: &str) -> CertificateDetachedSignatureV2 {
    CertificateDetachedSignatureV2 {
        key_id: key_id.into(),
        algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        digest_sha256: "00".repeat(32),
        signature_base64: "c2lnbmF0dXJl".into(),
    }
}

fn signature<T: CertificatePayloadV2>(
    value: &T,
    key: (&str, u8),
) -> CertificateDetachedSignatureV2 {
    let digest = value.certificate_digest_sha256();
    let bytes = bare_digest_bytes(&digest).unwrap();
    let signature = Ed25519SigningKey::from_bytes(&[key.1; 32]).sign(&bytes);
    CertificateDetachedSignatureV2 {
        key_id: key.0.into(),
        algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        digest_sha256: digest,
        signature_base64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }
}

fn receipt_signature<T: CertificatePayloadV2>(
    value: &T,
    key: (&str, u8),
    purpose: &str,
) -> CertificateReceiptSignatureV2 {
    let digest = value.certificate_digest_sha256();
    let signing = P256SigningKey::from_slice(&[key.1; 32]).unwrap();
    let signature: P256Signature = signing
        .sign_prehash(&bare_digest_bytes(&digest).unwrap())
        .unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    CertificateReceiptSignatureV2 {
        key_id: key.0.into(),
        key_version: "version.0001".into(),
        public_key_spki_sha256: spki_digest(key.1),
        key_purpose: purpose.into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: digest,
        signature_base64: STANDARD.encode(signature.to_bytes()),
    }
}
