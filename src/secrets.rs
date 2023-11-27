use aes::Aes256;
use ctr::Ctr64BE;
use ethereum_types::H256;
use sha2::Digest;
use sha3::Keccak256;

use crate::mac::Mac;

pub struct Secrets {
    pub aes_secret: H256,
    pub mac_secret: H256,
    pub shared_secret: H256,
    pub ingress_mac: Mac,
    pub egress_mac: Mac,
    pub ingress_aes: Ctr64BE<Aes256>,
    pub egress_aes: Ctr64BE<Aes256>,
}

/// shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
pub(crate) fn shared_secret(recipient_nonce: H256, ecies_nonce: H256, ephemeral_key: H256) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(recipient_nonce);
    hasher.update(ecies_nonce);
    let keccak_nonce = H256::from(hasher.finalize().as_ref());
    let mut hasher = Keccak256::new();
    hasher.update(ephemeral_key);
    hasher.update(keccak_nonce.as_ref());
    H256::from(hasher.finalize().as_ref())
}

/// aes-secret = keccak256(ephemeral-key || shared-secret)
pub(crate) fn aes_secret(ephemeral_key: &[u8], shared_secret: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(ephemeral_key.as_ref());
    hasher.update(shared_secret.as_ref());
    H256::from(hasher.finalize().as_ref())
}

/// mac-secret = keccak256(ephemeral-key || aes-secret)
pub(crate) fn mac_secret(ephemeral_key: &[u8], aes_secret: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(ephemeral_key);
    hasher.update(aes_secret);
    H256::from(hasher.finalize().as_ref())
}
