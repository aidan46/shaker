use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ethereum_types::{H128, H256};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub struct Mac {
    hasher: Keccak256,
    secret: H256,
}

impl Mac {
    pub fn new(secret: H256) -> Self {
        Self {
            hasher: Keccak256::new(),
            secret,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[..16])
    }

    pub fn update_header(&mut self, header_cipher_text: &[u8]) {
        let mut seed = self.digest().to_fixed_bytes();

        self.compute(&mut seed, header_cipher_text);
    }

    pub fn compute_frame(&mut self, data: &[u8]) {
        self.update(data);

        let seed = self.digest();
        self.compute(&mut seed.to_fixed_bytes(), seed.as_ref());
    }

    fn compute(&mut self, seed: &mut [u8], cipher_text: &[u8]) {
        self.encrypt(seed);

        for i in 0..cipher_text.len() {
            seed[i] ^= cipher_text[i];
        }

        self.update(seed);
    }

    fn encrypt(&self, data: &mut [u8]) {
        let cipher = Aes256::new(self.secret.as_ref().into());
        cipher.encrypt_block(GenericArray::from_mut_slice(data));
    }
}

/// egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
pub(crate) fn egress_mac(mac_secret: H256, recipient_nonce: H256, auth: &[u8]) -> Mac {
    let mut egress_mac = Mac::new(mac_secret);
    egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
    egress_mac.update(auth);
    egress_mac
}

/// ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
pub(crate) fn ingress_mac(mac_secret: H256, initiator_nonce: H256, ack: &[u8]) -> Mac {
    let mut ingress_mac = Mac::new(mac_secret);
    ingress_mac.update((mac_secret ^ initiator_nonce).as_bytes());
    ingress_mac.update(ack);
    ingress_mac
}
