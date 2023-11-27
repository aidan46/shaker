use ethereum_types::H128;
use rlp::DecoderError;
use secp256k1::Error as SecpError;
use thiserror::Error;

use crate::messages::DisconnectReason;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Could not convert ID to Public Key")]
    IdToPublicKey,
    #[error("EciesError: {0}")]
    EciesError(#[from] EciesError),
    #[error("SecretError: {0}")]
    SecretError(#[from] SecretError),
    #[error("EnodeError: {0}")]
    EnodeError(#[from] EnodeError),
    #[error("DecoderError: {0}")]
    DecoderError(#[from] DecoderError),
    #[error("Node disconnect: {0:?}")]
    NodeDisconnect(DisconnectReason),
    #[error("StreamError: {0}")]
    StreamError(#[from] StreamError),
    #[error("HandshakeError: {0}")]
    HandshakeError(#[from] HandshakeError),
}

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("Auth is not set")]
    AuthNotSet,
    #[error("Ack is not set")]
    AckNotSet,
    #[error("Public key is not valid")]
    InvalidPublicKey(#[from] SecpError),
    #[error("Tag is invalid")]
    InvalidTag,
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Secret is not set")]
    SecretNotSet,
}

#[derive(Debug, Error)]
pub enum EnodeError {
    #[error("Public key is not valid")]
    InvalidPublicKey(#[from] SecpError),
    #[error("Invalid prefix")]
    InvalidPrefix,
    #[error("Enode node ID is invalid")]
    InvalidNodeID,
    #[error("Enode address is missing")]
    AddressMissing,
    #[error("Enode address is invalid")]
    InvalidAddress,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("Failed to connect to enode")]
    EnodeConnectionFailure,
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("HelloMessage failed")]
    HelloMessageFailed,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Ack message failed")]
    AckMessageFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Did not receive authentication response")]
    AutheticationNotReceived,
    #[error("Invalid MAC received: {0}")]
    InvalidMac(H128),
    #[error("secp256k1 error")]
    Secp256k1Error(#[from] SecpError),
    #[error("No shared capabilities with recipient")]
    NoSharedCapabilities,
}
