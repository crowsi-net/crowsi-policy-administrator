use crate::support;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{CanonicalPayloadV1, PepExecutionLeaseV2};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeSet;
use support::V2Fixture;

const LEASE_FIXTURE: &str = include_str!("../fixtures/conformance/v1/pep-execution-lease-v2.json");
const TRUST_MANIFEST: &str =
    include_str!("../fixtures/conformance/v1/pep-command-trust-manifest-v1.json");
const TRUST_MANIFEST_SCHEMA: &str =
    include_str!("../schemas/pep-command-trust-manifest-v1.schema.json");

#[test]
fn pa_issued_lease_matches_the_versioned_fixture_exactly() {
    let fixture = V2Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve_v2(&fixture.reservation())
        .expect("reservation");
    let lease = administrator
        .begin_execution_v2(&fixture.command.jti)
        .expect("lease");
    let actual = format!("{}\n", serde_json::to_string_pretty(&lease).expect("JSON"));
    assert_eq!(actual, LEASE_FIXTURE);
}

#[test]
fn public_manifest_verifies_the_embedded_command_without_a_private_key() {
    let lease: PepExecutionLeaseV2 = serde_json::from_str(LEASE_FIXTURE).expect("lease fixture");
    let manifest: serde_json::Value = serde_json::from_str(TRUST_MANIFEST).expect("trust manifest");
    assert_manifest_binding(&manifest, &lease);
    assert_eq!(lease.command.payload_digest(), lease.command.signed.digest);
    let verifier = &manifest["command_verifier"];
    let fixture = V2Fixture::new().expect("deterministic authority");
    assert_eq!(
        verifier["public_key"],
        URL_SAFE_NO_PAD.encode(fixture.base.authorities.command.verifying_key())
    );
    let key_bytes: [u8; 32] = decode(&verifier["public_key"])
        .try_into()
        .expect("public key");
    let signature_bytes: [u8; 64] = decode(&serde_json::Value::String(
        lease.command.signed.signature.clone(),
    ))
    .try_into()
    .expect("signature");
    let digest = decode_hex(&lease.command.signed.digest);
    VerifyingKey::from_bytes(&key_bytes)
        .expect("verifying key")
        .verify_strict(&digest, &Signature::from_bytes(&signature_bytes))
        .expect("command signature");
    assert!(!TRUST_MANIFEST.contains("private_key"));
    assert!(!TRUST_MANIFEST.contains("seed"));
}

#[test]
fn trust_manifest_is_closed_and_versioned() {
    let manifest: serde_json::Value = serde_json::from_str(TRUST_MANIFEST).expect("trust manifest");
    let schema: serde_json::Value =
        serde_json::from_str(TRUST_MANIFEST_SCHEMA).expect("manifest schema");
    assert_eq!(schema["$id"], manifest["schema"]);
    assert_closed(&schema, &manifest);
    assert_closed(
        &schema["properties"]["accepted_schemas"],
        &manifest["accepted_schemas"],
    );
    assert_closed(
        &schema["properties"]["command_verifier"],
        &manifest["command_verifier"],
    );
}

fn assert_manifest_binding(manifest: &serde_json::Value, lease: &PepExecutionLeaseV2) {
    assert_eq!(
        manifest["schema"],
        "crowsi://policy-administrator/pep-command-trust-manifest/v1"
    );
    assert_eq!(manifest["manifest_id"], "crowsi-pa-pep-conformance.1");
    assert_eq!(manifest["intended_use"], "conformance-only");
    assert_eq!(manifest["canonical_profile"], "crowsi-control-canonical-v1");
    assert_eq!(manifest["security_domain"], lease.command.security_domain);
    assert_eq!(manifest["deployment_id"], lease.command.deployment_id);
    assert_eq!(manifest["provider"], lease.command.provider);
    assert_eq!(manifest["accepted_schemas"]["lease"], lease.schema);
    assert_eq!(
        manifest["accepted_schemas"]["command"],
        lease.command.schema
    );
    assert_eq!(
        manifest["accepted_schemas"]["receipt"],
        "crowsi://control/enforcement-receipt/v2"
    );
    let verifier = &manifest["command_verifier"];
    assert_eq!(verifier["key_id"], lease.command.signed.key_id);
    assert_eq!(verifier["algorithm"], "ed25519");
    assert_eq!(verifier["role"], "isolation-command");
    assert_eq!(verifier["scope_type"], "audience");
    assert_eq!(verifier["scope_value"], lease.command.provider);
    assert_eq!(verifier["public_key_encoding"], "base64url-no-pad");
}

fn decode(value: &serde_json::Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64url string"))
        .expect("base64url")
}

fn decode_hex(value: &str) -> [u8; 32] {
    let hex = value.strip_prefix("sha256:").expect("SHA-256");
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
    }
    bytes
}

fn assert_closed(schema: &serde_json::Value, value: &serde_json::Value) {
    assert_eq!(schema["additionalProperties"], false);
    let keys = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|field| field.as_str().expect("field"))
        .collect::<BTreeSet<_>>();
    assert_eq!(keys, required);
    let properties = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(keys, properties);
}
