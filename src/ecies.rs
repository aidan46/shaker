use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use bytes::{Bytes, BytesMut};
use ctr::Ctr64BE;
use ethereum_types::{H128, H256};
use secp256k1::rand::thread_rng;
use secp256k1::{PublicKey, SecretKey, SECP256K1};

use crate::error::EciesError;
use crate::{ecdh_x, hmac_sha256, kdf, sha256, Result};

pub struct Ecies {
    pub(crate) private_key: SecretKey,
    pub(crate) private_ephemeral_key: SecretKey,
    pub(crate) public_key: PublicKey,
    remote_public_key: PublicKey,
    pub(crate) shared_key: H256,
    pub(crate) nonce: H256,
    pub(crate) auth: Option<Bytes>,
    pub(crate) ack: Option<Bytes>,
}

impl Ecies {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        let private_ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let shared_key = ecdh_x(&remote_public_key, &private_key);

        Self {
            private_key,
            private_ephemeral_key,
            public_key,
            remote_public_key,
            shared_key,
            nonce: H256::random(),
            auth: None,
            ack: None,
        }
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<(&'a mut [u8], u16)> {
        let payload_size = u16::from_be_bytes([data_in[0], data_in[1]]);
        let ack_len = payload_size + 2;

        self.ack = Some(Bytes::copy_from_slice(&data_in[..ack_len as usize]));

        let (_size, rest) = data_in.split_at_mut(2);
        let (pub_data, rest) = rest.split_at_mut(65);
        let remote_emphmeral_pub_key =
            PublicKey::from_slice(pub_data).map_err(EciesError::InvalidPublicKey)?;

        let (iv, rest) = rest.split_at_mut(16); //
        let (encrypted_data, tag) = rest.split_at_mut(payload_size as usize - (65 + 16 + 32));

        let tag = H256::from_slice(&tag[..32]);
        let shared_key = ecdh_x(&remote_emphmeral_pub_key, &self.private_key);

        let mut key = [0u8; 32];
        kdf(shared_key, &[], &mut key);

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let iv = H128::from_slice(iv);

        let remote_tag = hmac_sha256(
            mac_key.as_ref(),
            &[iv.as_bytes(), encrypted_data],
            &payload_size.to_be_bytes(),
        );

        if tag != remote_tag {
            return Err(EciesError::InvalidTag.into());
        }

        let mut decryptor =
            Ctr64BE::<Aes128>::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        Ok((encrypted_data, ack_len))
    }

    pub fn encrypt(&self, data_in: BytesMut) -> Result<BytesMut> {
        let mut out = BytesMut::default();
        let random_secret_key = SecretKey::new(&mut thread_rng());

        let shared_key = ecdh_x(&self.remote_public_key, &random_secret_key);

        let mut key = [0u8; 32];
        kdf(shared_key, &[], &mut key);
        let iv = H128::random();

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..]);

        let mut encryptor =
            Ctr64BE::<Aes128>::new(encrypted_key.as_ref().into(), iv.as_ref().into());

        let total_size: u16 = u16::try_from(65 + 16 + data_in.len() + 32).unwrap();

        let mut encrypted = data_in;
        encryptor.apply_keystream(&mut encrypted);

        let d = hmac_sha256(
            mac_key.as_ref(),
            &[iv.as_bytes(), &encrypted],
            &total_size.to_be_bytes(),
        );

        out.extend_from_slice(&total_size.to_be_bytes());
        out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &random_secret_key).serialize_uncompressed(),
        );
        out.extend_from_slice(iv.as_bytes());
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(d.as_bytes());

        Ok(out)
    }
}
