use std::net::SocketAddr;

use secp256k1::PublicKey;

use crate::error::{EnodeError, Error};
use crate::id2pubkey;

const ENODE_PREFIX: &str = "enode://";

#[derive(Clone, Debug)]
pub struct Enode {
    /// Address of the Ethereum node
    addr: SocketAddr,
    /// Public key of the Ethereum node
    pub_key: PublicKey,
}

impl TryFrom<String> for Enode {
    type Error = Error;

    fn try_from(uri: String) -> Result<Self, Self::Error> {
        if !uri.to_string().starts_with(ENODE_PREFIX) {
            return Err(EnodeError::InvalidPrefix.into());
        }
        let (_prefix, node_data) = uri.split_at(ENODE_PREFIX.len());

        let mut parts = node_data.split('@');
        let id = hex::decode(parts.next().ok_or(EnodeError::InvalidNodeID)?)
            .map_err(|_| EnodeError::InvalidNodeID)?;
        let pub_key = Enode::public_key(&id)?;
        let addr: SocketAddr = parts
            .next()
            .ok_or(EnodeError::AddressMissing)?
            .parse()
            .map_err(|_| EnodeError::InvalidAddress)?;

        Ok(Self { addr, pub_key })
    }
}

impl Enode {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn pub_key(&self) -> PublicKey {
        self.pub_key
    }

    pub fn public_key(id: &[u8]) -> Result<PublicKey, Error> {
        id2pubkey(id)
    }
}

#[cfg(test)]
mod tests {
    use crate::enode::{Enode, EnodeError};
    use crate::error::Error;

    #[test]
    fn invalid_prefix() {
        let uri = "ennode://ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b@146.190.13.128:30303";
        let enode: Result<Enode, Error> = uri.to_string().try_into();
        assert!(matches!(
            enode,
            Err(Error::EnodeError(EnodeError::InvalidPrefix))
        ));
    }

    #[test]
    fn invalid_node_id() {
        let uri = "enode://node_id@address";
        let enode: Result<Enode, Error> = uri.to_string().try_into();
        assert!(matches!(
            enode,
            Err(Error::EnodeError(EnodeError::InvalidNodeID))
        ));
    }

    #[test]
    fn address_missing_ip() {
        let uri = "enode://ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b";
        let enode: Result<Enode, Error> = uri.to_string().try_into();
        assert!(matches!(
            enode,
            Err(Error::EnodeError(EnodeError::AddressMissing))
        ));
    }

    #[test]
    fn address_missing_port() {
        let uri = "enode://ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b@146.190.13.128";
        let enode: Result<Enode, Error> = uri.to_string().try_into();
        assert!(matches!(
            enode,
            Err(Error::EnodeError(EnodeError::InvalidAddress))
        ));
    }

    #[test]
    fn valid_uri() {
        let uri = "enode://ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b@146.190.13.128:30303";
        let enode: Result<Enode, Error> = uri.to_string().try_into();
        assert!(enode.is_ok());
    }
}
