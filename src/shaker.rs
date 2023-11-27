use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use ctr::Ctr64BE;
use ethereum_types::{H128, H256};
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use tracing::{debug, info, warn};

use crate::ecies::Ecies;
use crate::error::{EciesError, HandshakeError, SecretError};
use crate::mac::{egress_mac, ingress_mac};
use crate::messages::{Capability, HelloMessage};
use crate::secrets::{aes_secret, mac_secret, shared_secret, Secrets};
use crate::{ecdh_x, id2pubkey, Result, Signature, PROTOCOL_VERSION, ZERO_HEADER};

pub struct Handshake {
    ecies: Ecies,
    secrets: Option<Secrets>,
    capabilities: Vec<Capability>,
}

impl Handshake {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        Handshake {
            ecies: Ecies::new(private_key, remote_public_key),
            secrets: None,
            capabilities: vec![],
        }
    }

    pub fn with_capabilities(self, capabilities: Vec<Capability>) -> Self {
        Self {
            ecies: self.ecies,
            secrets: self.secrets,
            capabilities,
        }
    }

    pub fn auth(&mut self) -> Result<BytesMut> {
        let signature = self.signature()?;

        let full_pub_key = self.ecies.public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.ecies.nonce.as_bytes());
        stream.append(&PROTOCOL_VERSION);

        let auth_body = stream.out();

        let encrypted = self.encrypt(auth_body)?;

        self.ecies.auth = Some(Bytes::copy_from_slice(&encrypted[..]));

        Ok(encrypted)
    }

    pub(crate) fn check_shared_capabilities(
        &self,
        hello_message: HelloMessage,
    ) -> Result<Vec<Capability>> {
        let shared: Vec<Capability> = hello_message
            .capabilities
            .into_iter()
            .filter(|c| self.capabilities.contains(c))
            .collect();
        if shared.is_empty() {
            warn!("No shared capabilities with recipient");
            Err(HandshakeError::NoSharedCapabilities.into())
        } else {
            debug!("Found {} shared capabilities", shared.len());
            Ok(shared)
        }
    }

    fn signature(&self) -> Result<Signature> {
        let msg = self.ecies.shared_key ^ self.ecies.nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes())
                    .map_err(HandshakeError::Secp256k1Error)?,
                &self.ecies.private_ephemeral_key,
            )
            .serialize_compact();

        let mut signature: Signature = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        Ok(signature)
    }

    pub fn encrypt(&self, data: BytesMut) -> Result<BytesMut> {
        self.ecies.encrypt(data)
    }

    pub fn decrypt<'a>(&mut self, data: &'a mut [u8]) -> Result<(&'a mut [u8], u16)> {
        self.ecies.decrypt(data)
    }

    pub fn derive_secrets(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = Rlp::new(ack_body);
        // recipien public key
        let raw_pub_key: Vec<u8> = rlp.val_at(0)?;
        let recipient_pub_key = id2pubkey(&raw_pub_key)?;
        // recipient nonce
        let recipient_nonce_raw: Vec<u8> = rlp.val_at(1)?;
        let recipient_nonce = H256::from_slice(&recipient_nonce_raw);
        // ack-version
        let _ack_version: usize = rlp.val_at(2)?;
        // ephemeral-key
        let ephemeral_key = ecdh_x(&recipient_pub_key, &self.ecies.private_ephemeral_key);
        // shared-secret
        let shared_secret = shared_secret(recipient_nonce, self.ecies.nonce, ephemeral_key);
        // aes-secret
        let aes_secret = aes_secret(ephemeral_key.as_ref(), shared_secret.as_ref());
        // mac-secret
        let mac_secret = mac_secret(ephemeral_key.as_ref(), aes_secret.as_ref());
        // egress-mac
        let auth = self.ecies.auth.as_ref().ok_or(EciesError::AuthNotSet)?;
        let egress_mac = egress_mac(mac_secret, recipient_nonce, auth);
        // ingress-mac
        let ack = self.ecies.ack.as_ref().ok_or(EciesError::AckNotSet)?;
        let ingress_mac = ingress_mac(mac_secret, self.ecies.nonce, ack);

        let iv = H128::default();

        self.secrets = Some(Secrets {
            aes_secret,
            mac_secret,
            shared_secret,
            egress_mac,
            ingress_mac,
            ingress_aes: Ctr64BE::<Aes256>::new(aes_secret.as_ref().into(), iv.as_ref().into()),
            egress_aes: Ctr64BE::<Aes256>::new(aes_secret.as_ref().into(), iv.as_ref().into()),
        });

        Ok(())
    }

    pub fn hello_message(&mut self, out: &mut BytesMut) -> Result<()> {
        let msg = HelloMessage {
            protocol_version: PROTOCOL_VERSION,
            client_version: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            capabilities: vec![],
            port: 0,
            id: self.ecies.public_key,
        };

        let mut encoded_hello = BytesMut::default();
        encoded_hello.extend_from_slice(&rlp::encode(&0u8));
        encoded_hello.extend_from_slice(&rlp::encode(&msg));

        self.write_frame(&encoded_hello, out)
    }

    pub fn read_frame<'a>(&mut self, bytes: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let (header_bytes, body_bytes) = bytes.split_at_mut(32);
        let frame_size = self.read_header(header_bytes)?;
        self.read_body(frame_size, body_bytes)
    }

    fn write_header(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        let mut buf = [0u8; 8];
        let n_bytes = 3; // 3 * 8 = 24;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);

        let mut header_buf = [0u8; 16];
        header_buf[..3].copy_from_slice(&buf[..3]);
        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        let secrets = self.secrets.as_mut().ok_or(SecretError::SecretNotSet)?;
        secrets.egress_aes.apply_keystream(&mut header_buf);
        secrets.egress_mac.update_header(&header_buf);

        let mac = secrets.egress_mac.digest();

        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(mac.as_bytes());

        Ok(())
    }

    fn write_body(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        let secrets = self.secrets.as_mut().ok_or(SecretError::SecretNotSet)?;
        secrets.egress_aes.apply_keystream(encrypted);
        secrets.egress_mac.compute_frame(encrypted);
        let mac = secrets.egress_mac.digest();

        out.extend_from_slice(mac.as_bytes());

        Ok(())
    }

    fn write_frame(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        self.write_header(data, out)?;
        self.write_body(data, out)
    }

    fn read_header(&mut self, header_bytes: &mut [u8]) -> Result<usize> {
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        let secrets = self.secrets.as_mut().ok_or(SecretError::SecretNotSet)?;

        secrets.ingress_mac.update_header(header);
        if mac != secrets.ingress_mac.digest() {
            return Err(HandshakeError::InvalidMac(mac).into());
        }
        secrets.ingress_aes.apply_keystream(header);
        let mut frame_size = BigEndian::read_uint(header, 3) + 16;
        if frame_size % 16 > 0 {
            frame_size += 16 - (frame_size % 16);
        }
        Ok(frame_size as usize)
    }

    fn read_body<'a>(
        &mut self,
        frame_size: usize,
        body_bytes: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let (body, _) = body_bytes.split_at_mut(frame_size);
        let (body_data, body_mac) = body.split_at_mut(body.len() - 16);
        let body_mac = H128::from_slice(body_mac);

        let secrets = self.secrets.as_mut().ok_or(SecretError::SecretNotSet)?;

        secrets.ingress_mac.compute_frame(body_data);

        if body_mac == secrets.ingress_mac.digest() {
            info!("✅Connection successful");
        } else {
            return Err(HandshakeError::InvalidMac(body_mac).into());
        }

        secrets.ingress_aes.apply_keystream(body_data);
        Ok(body_data)
    }
}
