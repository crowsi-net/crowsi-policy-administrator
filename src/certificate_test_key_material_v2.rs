use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};

pub(crate) fn spki_digest(seed: u8) -> String {
    let key = P256SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(point.as_bytes());
    format!("{:x}", Sha256::digest(spki))
}
