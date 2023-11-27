use rlp::{DecoderError, Encodable, RlpStream};

#[repr(u8)]
/// RPLx disconnect reason. It's using a byte (u8) representation to match the protocol
#[derive(Clone, Copy, Debug)]
pub enum DisconnectReason {
    /// Disconnect requested by the local node or remote peer.
    DisconnectRequested = 0x00,
    /// TCP related error
    TcpSubsystemError = 0x01,
    /// Breach of protocol at the transport or p2p level
    ProtocolBreach = 0x02,
    /// Node has no matching protocols.
    UselessPeer = 0x03,
    /// Either the remote or local node has too many peers.
    TooManyPeers = 0x04,
    /// Already connected to the peer.
    AlreadyConnected = 0x05,
    /// `p2p` protocol version is incompatible
    IncompatibleP2PProtocolVersion = 0x06,
    /// Received a null node identity.
    NullNodeIdentity = 0x07,
    /// Reason when the client is shutting down.
    ClientQuitting = 0x08,
    /// When the received handshake's identify is different from what is expected.
    UnexpectedHandshakeIdentity = 0x09,
    /// The node is connected to itself
    ConnectedToSelf = 0x0a,
    /// Peer or local node did not respond to a ping in time.
    PingTimeout = 0x0b,
    /// Peer or local node violated a subprotocol-specific rule.
    SubprotocolSpecific = 0x10,
}

/// RPLx encodable trait for disconnect reason
impl Encodable for DisconnectReason {
    fn rlp_append(&self, s: &mut RlpStream) {
        let reason: u8 = *self as u8;
        s.append(&reason);
    }
}

/// Implementation of the [`TryInto`] trait to transform a [`u8`] into an [`DisconnectReason`] handling the possible decode error
impl TryFrom<u8> for DisconnectReason {
    type Error = DecoderError;
    fn try_from(value: u8) -> Result<Self, DecoderError> {
        match value {
            0x00 => Ok(DisconnectReason::DisconnectRequested),
            0x01 => Ok(DisconnectReason::TcpSubsystemError),
            0x02 => Ok(DisconnectReason::ProtocolBreach),
            0x03 => Ok(DisconnectReason::UselessPeer),
            0x04 => Ok(DisconnectReason::TooManyPeers),
            0x05 => Ok(DisconnectReason::AlreadyConnected),
            0x06 => Ok(DisconnectReason::IncompatibleP2PProtocolVersion),
            0x07 => Ok(DisconnectReason::NullNodeIdentity),
            0x08 => Ok(DisconnectReason::ClientQuitting),
            0x09 => Ok(DisconnectReason::UnexpectedHandshakeIdentity),
            0x0a => Ok(DisconnectReason::ConnectedToSelf),
            0x0b => Ok(DisconnectReason::PingTimeout),
            0x10 => Ok(DisconnectReason::SubprotocolSpecific),
            _ => Err(DecoderError::Custom("Unknown Disconnect reason")),
        }
    }
}
