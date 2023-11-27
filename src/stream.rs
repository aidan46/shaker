use bytes::BytesMut;
use rlp::{DecoderError, Rlp};
use secp256k1::rand::thread_rng;
use secp256k1::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::{debug, error, info};

use crate::enode::Enode;
use crate::error::{Error, HandshakeError, StreamError};
use crate::messages::{Capability, DisconnectReason, HelloMessage};
use crate::shaker::Handshake;
use crate::Result;

const DEFAULT_TIMEOUT: u64 = 3;

pub struct Stream {
    stream: TcpStream,
    handshake: Handshake,
}

impl Stream {
    pub async fn connect(enode: Enode) -> Result<Self> {
        debug!("⌛️Attempting to connect to node: {}", enode.addr());
        match TcpStream::connect(enode.addr()).await {
            Ok(stream) => {
                debug!("✅ Succesfully connected to enode");
                let private_key = SecretKey::new(&mut thread_rng());
                let handshake =
                    Handshake::new(private_key, enode.pub_key()).with_capabilities(vec![
                        Capability {
                            name: "eth".to_string(),
                            version: 68,
                        },
                    ]);
                Ok(Self { stream, handshake })
            }
            Err(e) => {
                error!("❌{e}");
                Err(StreamError::EnodeConnectionFailure.into())
            }
        }
    }

    pub async fn connect_with_timeout(enode: Enode, timeout: Option<u64>) -> Result<Self> {
        let timeout = match timeout {
            Some(timeout) => timeout,
            None => DEFAULT_TIMEOUT,
        };

        debug!("⌛️Attempting to connect to node: {}", enode.addr());
        match tokio::time::timeout(
            Duration::from_secs(timeout),
            TcpStream::connect(enode.addr()),
        )
        .await
        {
            Ok(stream) => {
                match stream {
                    Ok(stream) => {
                        debug!("✅ Succesfully connected to enode");
                        let private_key = SecretKey::new(&mut thread_rng());
                        let handshake = Handshake::new(private_key, enode.pub_key())
                            .with_capabilities(vec![Capability {
                                name: "eth".to_string(),
                                version: 68,
                            }]);
                        Ok(Self { stream, handshake })
                    }
                    Err(e) => {
                        error!("❌{e}");
                        Err(StreamError::IOError(e).into())
                    }
                }
            }
            Err(e) => {
                error!("❌{e}");
                Err(StreamError::EnodeConnectionFailure.into())
            }
        }
    }

    pub async fn initiate_handshake(&mut self) -> Result<HelloMessage> {
        self.send_auth_message().await?;
        self.handle_response().await
    }

    pub fn check_shared_capabilities(
        &self,
        recieved_hello_message: HelloMessage,
    ) -> Result<Vec<Capability>> {
        self.handshake
            .check_shared_capabilities(recieved_hello_message)
    }

    async fn send_auth_message(&mut self) -> Result<()> {
        let auth_encrypted = self.handshake.auth()?;

        if self
            .stream
            .write(&auth_encrypted)
            .await
            .map_err(StreamError::IOError)?
            == 0
        {
            return Err(StreamError::ConnectionClosed.into());
        }

        info!("📨Sent auth message to recipient node");
        Ok(())
    }

    async fn handle_response(&mut self) -> Result<HelloMessage> {
        let mut buffer = [0u8; 1024];
        let response_len = self
            .stream
            .read(&mut buffer)
            .await
            .map_err(StreamError::IOError)?;

        if response_len == 0 {
            return Err(HandshakeError::AutheticationNotReceived.into());
        }

        let (decrypted, ack_len) = self.handshake.decrypt(&mut buffer)?;

        if ack_len == response_len as u16 {
            return Err(StreamError::AckMessageFailed.into());
        }

        self.handshake.derive_secrets(decrypted)?;
        self.send_hello_message(&mut buffer, ack_len.into(), response_len)
            .await
    }

    async fn send_hello_message(
        &mut self,
        buffer: &mut [u8; 1024],
        ack_len: usize,
        response_len: usize,
    ) -> Result<HelloMessage> {
        let mut hello_bytes = BytesMut::default();
        self.handshake.hello_message(&mut hello_bytes)?;
        if self
            .stream
            .write(&hello_bytes)
            .await
            .map_err(StreamError::IOError)?
            == 0
        {
            return Err(HandshakeError::AutheticationNotReceived.into());
        }

        let frame = self
            .handshake
            .read_frame(&mut buffer[ack_len..response_len])?;
        decode_message(frame)
    }
}

fn decode_message(message: &[u8]) -> Result<HelloMessage> {
    let rlp_message = Rlp::new(&message[0..1]);
    let message_id = rlp_message.as_val::<usize>()?;

    match message_id {
        0 => {
            let hello = Rlp::new(&message[1..]).as_val::<HelloMessage>()?;
            Ok(hello)
        }
        1 => {
            let reason = Rlp::new(&message[1..]).val_at::<u8>(0)?;
            let reason = DisconnectReason::try_from(reason)?;
            Err(Error::NodeDisconnect(reason))
        }
        _ => Err(DecoderError::Custom("Invalid message ID").into()),
    }
}
