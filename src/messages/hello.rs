use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use secp256k1::PublicKey;

#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}

impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;
        let id: Vec<u8> = rlp.val_at(4)?;

        let mut s = [0u8; 65];
        s[0] = 4;
        s[1..].copy_from_slice(&id);
        let id =
            PublicKey::from_slice(&s).map_err(|_| DecoderError::Custom("Invalid public key"))?;

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);

        let id = &self.id.serialize_uncompressed()[1..65];
        s.append(&id);
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl Encodable for Capability {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for Capability {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let name: String = rlp.val_at(0)?;
        let ver: usize = rlp.val_at(1)?;

        Ok(Self { name, version: ver })
    }
}
