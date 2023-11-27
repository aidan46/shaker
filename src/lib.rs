use ethereum_types::H256;
use hmac::{Hmac, Mac};
use secp256k1::ecdh::shared_secret_point;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

pub mod ecies;
pub mod enode;
pub mod error;
pub mod mac;
pub mod messages;
pub mod secrets;
pub mod shaker;
pub mod stream;

pub use error::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;
pub type Signature = [u8; 65];

// The version of the protocol being used
pub const PROTOCOL_VERSION: usize = 5;

// The header used to indicate a zero-length payload
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];

// KDF from https://github.com/ethereum/devp2p/blob/master/rlpx.md#ecies-encryption
pub(crate) fn kdf(secret: H256, s1: &[u8], dest: &mut [u8]) {
    // SEC/ISO/Shoup specify counter size SHOULD be equivalent
    // to size of hash output, however, it also notes that
    // the 4 bytes is okay. NIST specifies 4 bytes.
    let mut ctr = 1_u32;
    let mut written = 0_usize;
    while written < dest.len() {
        let mut hasher = Sha256::default();
        let ctrs = [
            (ctr >> 24) as u8,
            (ctr >> 16) as u8,
            (ctr >> 8) as u8,
            ctr as u8,
        ];
        hasher.update(ctrs);
        hasher.update(secret.as_bytes());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}

pub(crate) fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    H256::from_slice(&shared_secret_point(public_key, secret_key)[..32])
}

pub(crate) fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

pub(crate) fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    H256::from_slice(&hmac.finalize().into_bytes())
}

pub(crate) fn id2pubkey(id: &[u8]) -> Result<PublicKey> {
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L211
    let mut buf = [0u8; 65];
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L211
    buf[0] = 4;
    buf[1..].copy_from_slice(id);
    PublicKey::from_slice(&buf).map_err(|_| Error::IdToPublicKey)
}
