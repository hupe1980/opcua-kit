use super::DiscoveryError;
use std::net::{IpAddr, Ipv6Addr};
pub(crate) fn address(endpoint: &str) -> Result<(&str, u16), DiscoveryError> {
    let invalid = || DiscoveryError::InvalidEndpoint;
    if endpoint.len() > 2048
        || endpoint.bytes().any(|b| !b.is_ascii_graphic())
        || endpoint.contains(['?', '#', '\\'])
    {
        return Err(invalid());
    }
    let authority = endpoint
        .strip_prefix("opc.tcp://")
        .ok_or_else(invalid)?
        .split('/')
        .next()
        .ok_or_else(invalid)?;
    let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0 && port.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(invalid)?;
    if host.is_empty() {
        return Err(invalid());
    }
    if let Some(ipv6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        ipv6.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        return Ok((ipv6, port));
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.len() > 253
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid());
    }
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.') && name.parse::<IpAddr>().is_err() {
        return Err(invalid());
    }
    Ok((name, port))
}

use super::{
    POLICY_NONE,
    binary::{Decoder, Encoder},
};
use DiscoveryError::Protocol;
use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

const CHUNK: usize = 65_536;
const MESSAGE: usize = 1024 * 1024;
const MAX_CHUNKS: usize = 64;

pub(super) struct Connection {
    stream: TcpStream,
    deadline: Instant,
    receive_limit: usize,
    send_limit: usize,
    peer_message: usize,
    peer_chunks: usize,
    pub channel: u32,
    pub token: u32,
    sequence: Option<u32>,
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|t| !t.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "discovery deadline expired"))
}

impl Connection {
    pub fn connect(endpoint: &str, timeout: Duration) -> Result<Self, DiscoveryError> {
        Self::handshake(endpoint, timeout, MESSAGE, MAX_CHUNKS)
    }

    fn handshake(
        endpoint: &str,
        timeout: Duration,
        max_message: usize,
        max_chunks: usize,
    ) -> Result<Self, DiscoveryError> {
        let addr = address(endpoint)?;
        let addresses = addr.to_socket_addrs()?;
        let deadline = Instant::now() + timeout;
        let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no address for endpoint");
        for addr in addresses {
            let stream = match TcpStream::connect_timeout(&addr, remaining(deadline)?) {
                Ok(stream) => stream,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let mut conn = Self {
                stream,
                deadline,
                receive_limit: CHUNK,
                send_limit: CHUNK,
                peer_message: 0,
                peer_chunks: 0,
                channel: 0,
                token: 0,
                sequence: None,
            };
            let mut hello = Encoder::default();
            for n in [0, CHUNK, CHUNK, max_message, max_chunks] {
                hello.u32(n as u32);
            }
            hello.blob(endpoint.as_bytes());
            conn.write_frame(b"HEL", &hello.0)?;
            let (header, body) = conn.read_frame()?;
            if &header != b"ACKF" {
                return Err(Protocol("expected Acknowledge"));
            }
            let mut ack = Decoder::new(&body);
            if ack.u32()? != 0 {
                return Err(Protocol("unsupported protocol version"));
            }
            let send = ack.u32()? as usize;
            let receive = ack.u32()? as usize;
            if !(8192..=CHUNK).contains(&send) || !(8192..=CHUNK).contains(&receive) {
                return Err(Protocol("invalid negotiated chunk size"));
            }
            let max_request = ack.u32()? as usize;
            conn.peer_message = max_request;
            conn.peer_chunks = ack.u32()? as usize;
            ack.finish()?;
            conn.send_limit = if max_request == 0 {
                send
            } else {
                send.min(max_request)
            };
            conn.receive_limit = receive;
            return Ok(conn);
        }
        Err(last.into())
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<(), DiscoveryError> {
        while !bytes.is_empty() {
            self.stream
                .set_read_timeout(Some(remaining(self.deadline)?))?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => bytes = &mut bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn read_frame(&mut self) -> Result<([u8; 4], Vec<u8>), DiscoveryError> {
        let mut header = [0; 8];
        self.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if !(8..=self.receive_limit).contains(&len) {
            return Err(Protocol("invalid UA TCP frame length"));
        }
        let mut body = vec![0; len - 8];
        self.read_exact(&mut body)?;
        if &header[..4] == b"ERRF" {
            let mut r = Decoder::new(&body);
            let status = r.u32()?;
            r.text()?;
            r.finish()?;
            return Err(DiscoveryError::Status(status));
        }
        Ok((header[..4].try_into().unwrap(), body))
    }

    fn write_frame(&mut self, kind: &[u8; 3], body: &[u8]) -> Result<(), DiscoveryError> {
        let size = 8 + body.len();
        if size > self.send_limit {
            return Err(Protocol("request exceeds negotiated limit"));
        }
        let mut data = Vec::with_capacity(size);
        data.extend_from_slice(kind);
        data.push(b'F');
        data.extend_from_slice(&(size as u32).to_le_bytes());
        data.extend_from_slice(body);
        let mut bytes = data.as_slice();
        while !bytes.is_empty() {
            self.stream
                .set_write_timeout(Some(remaining(self.deadline)?))?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub fn send(
        &mut self,
        kind: &[u8; 3],
        id: u32,
        service: &Encoder,
    ) -> Result<(), DiscoveryError> {
        let mut chunk = Encoder::default();
        chunk.u32(self.channel);
        if kind == b"OPN" {
            chunk.blob(POLICY_NONE.as_bytes());
            chunk.null(); // SenderCertificate.
            chunk.null(); // ReceiverCertificateThumbprint.
        } else {
            chunk.u32(self.token);
        }
        chunk.u32(id); // One outgoing chunk per request.
        chunk.u32(id);
        chunk.0.extend_from_slice(&service.0);
        self.write_frame(kind, &chunk.0)
    }

    pub fn receive(&mut self, kind: &[u8; 3], id: u32) -> Result<Vec<u8>, DiscoveryError> {
        let mut service = Vec::new();
        let mut wire_bytes = 0;
        for _ in 0..MAX_CHUNKS {
            let (header, body) = self.read_frame()?;
            wire_bytes += 8 + body.len();
            if wire_bytes > MESSAGE {
                return Err(Protocol("discovery message exceeds limit"));
            }
            if &header[..3] != kind {
                return Err(Protocol("unexpected message type"));
            }
            let mut r = Decoder::new(&body);
            let channel = r.u32()?;
            if kind == b"OPN" {
                if channel == 0 || header[3] != b'F' || r.text()? != POLICY_NONE {
                    return Err(Protocol("invalid discovery channel header"));
                }
                r.blob(0)?; // No sender certificate for SecurityPolicy None.
                r.blob(0)?; // No receiver thumbprint.
                self.channel = channel;
            } else if channel != self.channel || r.u32()? != self.token {
                return Err(Protocol("unexpected channel or token"));
            }
            let seq = r.u32()?;
            if let Some(previous) = self.sequence {
                let rollover = previous > u32::MAX - 1024 && seq < 1024;
                if seq != previous.wrapping_add(1) && !rollover {
                    return Err(Protocol("nonconsecutive chunk sequence"));
                }
            }
            self.sequence = Some(seq);
            if r.u32()? != id {
                return Err(Protocol("unexpected request identifier"));
            }
            match header[3] {
                b'A' => return Err(DiscoveryError::Status(r.u32()?)),
                b'C' | b'F' => service.extend_from_slice(r.remaining()),
                _ => return Err(Protocol("invalid message chunk type")),
            }
            if header[3] == b'F' {
                return Ok(service);
            }
        }
        Err(Protocol("discovery chunk limit exceeded"))
    }
}

#[cfg(feature = "client")]
pub(crate) fn secure_socket(
    endpoint: &str,
    timeout: Duration,
    max_message: usize,
    max_chunks: usize,
) -> Result<(TcpStream, usize, usize, usize, usize), DiscoveryError> {
    let conn = Connection::handshake(endpoint, timeout, max_message, max_chunks)?;
    conn.stream.set_write_timeout(Some(timeout))?;
    Ok((
        conn.stream,
        conn.receive_limit,
        conn.send_limit,
        conn.peer_message,
        conn.peer_chunks,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (Connection, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let conn = Connection {
            stream,
            deadline: Instant::now() + Duration::from_secs(2),
            receive_limit: CHUNK,
            send_limit: CHUNK,
            peer_message: 0,
            peer_chunks: 0,
            channel: 10,
            token: 20,
            sequence: Some(1),
        };
        (conn, peer)
    }

    fn chunk(peer: &mut TcpStream, last: u8, sequence: u32, request: u32, payload: &[u8]) {
        peer.write_all(b"MSG").unwrap();
        peer.write_all(&[last]).unwrap();
        for n in [24 + payload.len() as u32, 10, 20, sequence, request] {
            peer.write_all(&n.to_le_bytes()).unwrap();
        }
        peer.write_all(payload).unwrap();
    }

    #[test]
    fn response_chunks_belong_to_one_request() {
        let (mut conn, mut peer) = pair();
        chunk(&mut peer, b'C', 2, 2, b"one");
        chunk(&mut peer, b'F', 3, 2, b"two");
        assert_eq!(conn.receive(b"MSG", 2).unwrap(), b"onetwo");
        chunk(&mut peer, b'C', 4, 3, b"part");
        chunk(&mut peer, b'F', 5, 4, b"other request");
        assert!(conn.receive(b"MSG", 3).is_err());
    }

    #[test]
    fn mismatched_sequence_and_excessive_frame_length_fail() {
        let (mut conn, mut peer) = pair();
        chunk(&mut peer, b'F', 7, 2, b"");
        assert!(conn.receive(b"MSG", 2).is_err());
        peer.write_all(b"MSGF").unwrap();
        peer.write_all(&(CHUNK as u32 + 1).to_le_bytes()).unwrap();
        assert!(conn.read_frame().is_err());
    }
}
