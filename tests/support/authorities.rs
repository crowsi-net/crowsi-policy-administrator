use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{CanonicalPayloadV1, SignatureAlgorithm, SignedDigestV1};
use crowsi_policy_administrator::{AdministratorError, Result};
use ed25519_dalek::{Signer, SigningKey};

pub struct SimulationEd25519Authority {
    key_id: String,
    key: SigningKey,
}

impl SimulationEd25519Authority {
    fn from_seed(key_id: &str, seed: [u8; 32]) -> Result<Self> {
        if key_id.is_empty() {
            return Err(AdministratorError::Trust);
        }
        Ok(Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign<T: CanonicalPayloadV1>(&self, artifact: &T) -> Result<SignedDigestV1> {
        let digest = artifact.payload_digest();
        let bytes = digest
            .strip_prefix("sha256:")
            .and_then(|hex| hex_to_bytes(hex).ok())
            .ok_or(AdministratorError::Signature)?;
        Ok(SignedDigestV1 {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: self.key_id.clone(),
            digest,
            signature: URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).to_bytes()),
        })
    }
}

pub struct Authorities {
    pub identity: SimulationEd25519Authority,
    pub intent: SimulationEd25519Authority,
    pub decision: SimulationEd25519Authority,
    pub grant: SimulationEd25519Authority,
    pub command: SimulationEd25519Authority,
    pub coverage: SimulationEd25519Authority,
    pub policy_information: SimulationEd25519Authority,
    pub recovery: SimulationEd25519Authority,
    pub receipt: SimulationEd25519Authority,
}

impl Authorities {
    pub fn new() -> Result<Self> {
        Ok(Self {
            identity: authority("identity.control.1", 1)?,
            intent: authority("intent.control.1", 2)?,
            decision: authority("decision.control.1", 3)?,
            grant: authority("grant.control.1", 4)?,
            command: authority("command.control.1", 5)?,
            coverage: authority("coverage.control.1", 6)?,
            policy_information: authority("policy-information.control.1", 7)?,
            recovery: authority("recovery.control.1", 8)?,
            receipt: authority("receipt.control.1", 9)?,
        })
    }
}

fn authority(key_id: &str, seed: u8) -> Result<SimulationEd25519Authority> {
    SimulationEd25519Authority::from_seed(key_id, [seed; 32])
}

fn hex_to_bytes(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(AdministratorError::Signature);
    }
    let mut bytes = [0_u8; 32];
    for (index, target) in bytes.iter_mut().enumerate() {
        *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| AdministratorError::Signature)?;
    }
    Ok(bytes)
}
