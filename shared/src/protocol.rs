use anyhow::{Context, Result};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum frame payload size (1 MB).
const MAX_PAYLOAD_SIZE: u32 = 1_048_576;

/// Stream ID 0 is reserved for control messages.
pub const CONTROL_STREAM: u64 = 0;

/// A multiplexed frame: either a control message or data for a specific stream.
#[derive(Debug, Clone)]
pub enum Frame {
    /// Control message (stream_id = 0).
    Control(Message),
    /// Data payload for a specific player connection.
    Data { stream_id: u64, payload: Vec<u8> },
    /// Signal that a stream has been closed.
    StreamClose { stream_id: u64 },
}

/// Control message types exchanged over stream 0.
#[derive(Debug, Clone)]
pub enum Message {
    /// Client authenticates with the server.
    /// `client_uuid` is the UUID assigned in the client's config. When present
    /// the server checks its pre-auth cache (populated by the manager) before
    /// accepting the connection.
    Auth { secret: String, client_uuid: Option<String> },
    /// Server acknowledges successful authentication.
    AuthOk,
    /// Server rejects authentication.
    AuthFailed { reason: String },
    /// Client requests a tunnel to be opened.
    OpenTunnel {
        tunnel_id: u32,
        remote_port: u16,
        protocol: TunnelProtocol,
    },
    /// Server confirms tunnel is open.
    TunnelOpened { tunnel_id: u32 },
    /// Server or client requests tunnel closure.
    CloseTunnel { tunnel_id: u32 },
    /// Server notifies client of a new incoming connection (stream allocated).
    /// is_udp differenziert TCP- von UDP-Verbindungen bei "both"-Tunneln.
    NewConnection { tunnel_id: u32, stream_id: u64, is_udp: bool },
    /// Heartbeat ping.
    Ping,
    /// Heartbeat pong.
    Pong,
}

/// Protocol type in wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelProtocol {
    Tcp = 1,
    Udp = 2,
    Both = 3,
}

impl From<crate::config::Protocol> for TunnelProtocol {
    fn from(p: crate::config::Protocol) -> Self {
        match p {
            crate::config::Protocol::Tcp => TunnelProtocol::Tcp,
            crate::config::Protocol::Udp => TunnelProtocol::Udp,
            crate::config::Protocol::Both => TunnelProtocol::Both,
        }
    }
}

// Control message type IDs.
const MSG_AUTH: u8 = 1;
const MSG_AUTH_OK: u8 = 2;
const MSG_AUTH_FAILED: u8 = 3;
const MSG_OPEN_TUNNEL: u8 = 4;
const MSG_TUNNEL_OPENED: u8 = 5;
const MSG_CLOSE_TUNNEL: u8 = 6;
const MSG_NEW_CONNECTION: u8 = 7;
const MSG_PING: u8 = 9;
const MSG_PONG: u8 = 10;

// Special frame type marker for stream close.
const FRAME_TYPE_STREAM_CLOSE: u32 = 0xFFFFFFFF;

impl Message {
    /// Encode a control message to payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let (msg_type, payload) = match self {
            Message::Auth { secret, client_uuid } => {
                // Wire format: [uuid_len: u16 BE][uuid_bytes][secret_bytes]
                // uuid_len == 0 means no UUID.
                let uuid_bytes = client_uuid.as_deref().unwrap_or("").as_bytes();
                let uuid_len = uuid_bytes.len() as u16;
                let mut buf = Vec::with_capacity(2 + uuid_bytes.len() + secret.len());
                buf.extend_from_slice(&uuid_len.to_be_bytes());
                buf.extend_from_slice(uuid_bytes);
                buf.extend_from_slice(secret.as_bytes());
                (MSG_AUTH, buf)
            }
            Message::AuthOk => (MSG_AUTH_OK, vec![]),
            Message::AuthFailed { reason } => (MSG_AUTH_FAILED, reason.as_bytes().to_vec()),
            Message::OpenTunnel {
                tunnel_id,
                remote_port,
                protocol,
            } => {
                let mut buf = Vec::with_capacity(7);
                buf.extend_from_slice(&tunnel_id.to_be_bytes());
                buf.extend_from_slice(&remote_port.to_be_bytes());
                buf.push(*protocol as u8);
                (MSG_OPEN_TUNNEL, buf)
            }
            Message::TunnelOpened { tunnel_id } => {
                (MSG_TUNNEL_OPENED, tunnel_id.to_be_bytes().to_vec())
            }
            Message::CloseTunnel { tunnel_id } => {
                (MSG_CLOSE_TUNNEL, tunnel_id.to_be_bytes().to_vec())
            }
            Message::NewConnection { tunnel_id, stream_id, is_udp } => {
                // Wire format: tunnel_id(4) + stream_id(8) + is_udp(1) = 13 bytes
                let mut buf = Vec::with_capacity(13);
                buf.extend_from_slice(&tunnel_id.to_be_bytes());
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf.push(*is_udp as u8);
                (MSG_NEW_CONNECTION, buf)
            }
            Message::Ping => (MSG_PING, vec![]),
            Message::Pong => (MSG_PONG, vec![]),
        };

        let mut result = Vec::with_capacity(1 + payload.len());
        result.push(msg_type);
        result.extend_from_slice(&payload);
        result
    }

    /// Decode a control message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty control message");
        }
        let msg_type = data[0];
        let payload = &data[1..];

        match msg_type {
            MSG_AUTH => {
                // Wire format: [uuid_len: u16 BE][uuid_bytes][secret_bytes]
                if payload.len() < 2 {
                    anyhow::bail!("Auth payload too short");
                }
                let uuid_len = u16::from_be_bytes(payload[0..2].try_into()?) as usize;
                if payload.len() < 2 + uuid_len {
                    anyhow::bail!("Auth payload too short for UUID");
                }
                let client_uuid = if uuid_len > 0 {
                    Some(
                        String::from_utf8(payload[2..2 + uuid_len].to_vec())
                            .context("invalid UTF-8 in client_uuid")?,
                    )
                } else {
                    None
                };
                let secret =
                    String::from_utf8(payload[2 + uuid_len..].to_vec())
                        .context("invalid UTF-8 in secret")?;
                Ok(Message::Auth { secret, client_uuid })
            }
            MSG_AUTH_OK => Ok(Message::AuthOk),
            MSG_AUTH_FAILED => {
                let reason =
                    String::from_utf8(payload.to_vec()).context("invalid UTF-8 in auth fail")?;
                Ok(Message::AuthFailed { reason })
            }
            MSG_OPEN_TUNNEL => {
                if payload.len() < 7 {
                    anyhow::bail!("OpenTunnel too short");
                }
                let tunnel_id = u32::from_be_bytes(payload[0..4].try_into()?);
                let remote_port = u16::from_be_bytes(payload[4..6].try_into()?);
                let protocol = match payload[6] {
                    1 => TunnelProtocol::Tcp,
                    2 => TunnelProtocol::Udp,
                    3 => TunnelProtocol::Both,
                    other => anyhow::bail!("unknown protocol: {}", other),
                };
                Ok(Message::OpenTunnel {
                    tunnel_id,
                    remote_port,
                    protocol,
                })
            }
            MSG_TUNNEL_OPENED => {
                if payload.len() < 4 {
                    anyhow::bail!("TunnelOpened too short");
                }
                let tunnel_id = u32::from_be_bytes(payload[0..4].try_into()?);
                Ok(Message::TunnelOpened { tunnel_id })
            }
            MSG_CLOSE_TUNNEL => {
                if payload.len() < 4 {
                    anyhow::bail!("CloseTunnel too short");
                }
                let tunnel_id = u32::from_be_bytes(payload[0..4].try_into()?);
                Ok(Message::CloseTunnel { tunnel_id })
            }
            MSG_NEW_CONNECTION => {
                if payload.len() < 12 {
                    anyhow::bail!("NewConnection too short");
                }
                let tunnel_id = u32::from_be_bytes(payload[0..4].try_into()?);
                let stream_id = u64::from_be_bytes(payload[4..12].try_into()?);
                // is_udp ist das 13. Byte — defaultet auf false für ältere Nachrichten.
                let is_udp = payload.get(12).map(|&b| b != 0).unwrap_or(false);
                Ok(Message::NewConnection { tunnel_id, stream_id, is_udp })
            }
            MSG_PING => Ok(Message::Ping),
            MSG_PONG => Ok(Message::Pong),
            other => anyhow::bail!("unknown control message type: {}", other),
        }
    }
}

/// Read a single multiplexed frame from the tunnel connection.
///
/// Wire format:
/// - [4 bytes] payload length (big-endian)
/// - [8 bytes] stream_id (big-endian), 0 = control
/// - [payload_length bytes] payload
///
/// Special case: if length == 0xFFFFFFFF, it's a StreamClose frame
/// and the next 8 bytes are the stream_id being closed.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Frame> {
    let len = reader
        .read_u32()
        .await
        .context("failed to read frame length")?;

    let stream_id = reader
        .read_u64()
        .await
        .context("failed to read stream_id")?;

    if len == FRAME_TYPE_STREAM_CLOSE {
        return Ok(Frame::StreamClose { stream_id });
    }

    if len > MAX_PAYLOAD_SIZE {
        anyhow::bail!("frame too large: {} bytes", len);
    }

    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("failed to read frame payload")?;
    }

    if stream_id == CONTROL_STREAM {
        let msg = Message::decode(&payload)?;
        Ok(Frame::Control(msg))
    } else {
        Ok(Frame::Data { stream_id, payload })
    }
}

/// Write a control message as a frame (stream_id = 0).
pub async fn write_control<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<()> {
    let payload = msg.encode();
    let len = payload.len() as u32;
    writer.write_u32(len).await?;
    writer.write_u64(CONTROL_STREAM).await?;
    if !payload.is_empty() {
        writer.write_all(&payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Write a data frame for a specific stream.
pub async fn write_data<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    stream_id: u64,
    data: &[u8],
) -> Result<()> {
    let len = data.len() as u32;
    writer.write_u32(len).await?;
    writer.write_u64(stream_id).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Write a stream close frame.
pub async fn write_stream_close<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    stream_id: u64,
) -> Result<()> {
    writer.write_u32(FRAME_TYPE_STREAM_CLOSE).await?;
    writer.write_u64(stream_id).await?;
    writer.flush().await?;
    Ok(())
}