use super::{
    Host, NONE,
    services::{Envelope, Sessions, decode, encode},
};
use crate::secure_channel::{self as crypto, Keys, nonce};
use crate::ua::{BinaryEncodable, *};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

pub(super) const MESSAGE_LIMIT: usize = 4 * 1024 * 1024;
const CHUNK_LIMIT: usize = 64 * 1024;
const MAX_CHUNKS: usize = 64;
const SECURITY: StatusCode = StatusCode::BadSecurityChecksFailed;
type Result<T> = std::result::Result<T, StatusCode>;

pub(super) fn run(
    listener: TcpListener,
    host: Arc<Host>,
    mut shutdown: impl FnMut() -> bool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let mut workers: Vec<(TcpStream, JoinHandle<()>)> = Vec::new();
    let result = (|| {
        while !shutdown() {
            workers.retain(|(_, worker)| !worker.is_finished());
            match listener.accept() {
                Ok((mut stream, _)) if workers.len() < 16 => {
                    stream.set_nonblocking(false)?;
                    stream.set_write_timeout(Some(StdDuration::from_secs(5)))?;
                    stream.set_nodelay(true)?;
                    let socket = stream.try_clone()?;
                    let host = host.clone();
                    let worker = thread::Builder::new()
                        .name("opcua-connection".into())
                        .spawn(move || {
                            if let Err(status) = serve(&mut stream, &host) {
                                let mut error = status.bits().to_le_bytes().to_vec();
                                error.extend((-1_i32).to_le_bytes());
                                let _ = stream.write_all(&frame(*b"ERRF", &error));
                            }
                        })?;
                    workers.push((socket, worker));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(StdDuration::from_millis(10))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    for (stream, _) in &workers {
        let _ = stream.shutdown(Shutdown::Both);
    }
    for (_, worker) in workers {
        let _ = worker.join();
    }
    result
}

fn frame(kind: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(payload.len() + 8);
    result.extend(kind);
    result.extend(((payload.len() + 8) as u32).to_le_bytes());
    result.extend(payload);
    result
}

fn read_until(stream: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> Result<()> {
    while !buf.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|t| !t.is_zero())
            .ok_or(StatusCode::BadTimeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| StatusCode::BadConnectionClosed)?;
        let n = stream
            .read(buf)
            .map_err(|_| StatusCode::BadConnectionClosed)?;
        if n == 0 {
            return Err(StatusCode::BadConnectionClosed);
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

fn receive(stream: &mut TcpStream, limit: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0; 8];
    read_until(stream, &mut header, deadline)?;
    let size = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
    if !(8..=limit).contains(&size) {
        return Err(StatusCode::BadTcpMessageTooLarge);
    }
    let mut data = vec![0; size];
    data[..8].copy_from_slice(&header);
    read_until(stream, &mut data[8..], deadline)?;
    Ok(data)
}

fn send(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream
        .write_all(data)
        .map_err(|_| StatusCode::BadConnectionClosed)
}

fn integer(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .ok_or(StatusCode::BadDecodingError)?
            .try_into()
            .unwrap(),
    ))
}

struct Limits {
    send: usize,
    receive: usize,
    message: usize,
    chunks: usize,
}

fn hello(stream: &mut TcpStream, ctx: &Context<'_>) -> Result<Limits> {
    let hello = receive(stream, 8192, Instant::now() + StdDuration::from_secs(5))?;
    if &hello[..4] != b"HELF" || hello.len() < 32 {
        return Err(StatusCode::BadTcpMessageTypeInvalid);
    }
    let send_limit = (integer(&hello, 12)? as usize).min(CHUNK_LIMIT);
    let receive_limit = (integer(&hello, 16)? as usize).min(CHUNK_LIMIT);
    if send_limit < 8192 || receive_limit < 8192 {
        return Err(StatusCode::BadTcpNotEnoughResources);
    }
    let mut url = &hello[28..];
    let endpoint: UAString = decode(&mut url, ctx)?;
    if !url.is_empty()
        || endpoint.as_ref().len() > 4096
        || !endpoint.as_ref().starts_with("opc.tcp://")
    {
        return Err(StatusCode::BadTcpEndpointUrlInvalid);
    }
    let mut ack = Vec::new();
    for v in [
        0,
        receive_limit as u32,
        send_limit as u32,
        MESSAGE_LIMIT as u32,
        MAX_CHUNKS as u32,
    ] {
        ack.extend(v.to_le_bytes());
    }
    send(stream, &frame(*b"ACKF", &ack))?;
    let maximum = |offset, local| {
        Ok::<usize, StatusCode>(match integer(&hello, offset)? as usize {
            0 => local,
            n => n.min(local),
        })
    };
    Ok(Limits {
        send: send_limit,
        receive: receive_limit,
        message: maximum(20, MESSAGE_LIMIT)?,
        chunks: maximum(24, MAX_CHUNKS)?,
    })
}

struct Token {
    id: u32,
    expires: Instant,
    rx: Option<Keys>,
    tx: Option<Keys>,
}

#[derive(Default)]
struct Channel {
    id: u32,
    current: Option<Token>,
    previous: Option<Token>,
    client_sequence: Option<u32>,
    sequence: u32,
    last_nonce: Vec<u8>,
}

impl Channel {
    fn next(&mut self) -> u32 {
        self.sequence = self.sequence.checked_add(1).unwrap_or(1);
        self.sequence
    }

    fn validate_sequence(&mut self, seq: u32) -> Result<()> {
        if self.client_sequence.is_some_and(|prev| {
            seq != prev.wrapping_add(1) && !(prev > u32::MAX - 1024 && seq < 1024)
        }) {
            return Err(StatusCode::BadSequenceNumberInvalid);
        }
        self.client_sequence = Some(seq);
        Ok(())
    }

    fn open(&mut self, host: &Host, incoming: &[u8], ctx: &Context<'_>) -> Result<Vec<u8>> {
        let mut payload = incoming.get(12..).ok_or(StatusCode::BadDecodingError)?;
        let policy: UAString = decode(&mut payload, ctx)?;
        let credentials = if policy.as_ref() == NONE {
            None
        } else {
            Some(
                host.credentials
                    .as_ref()
                    .filter(|c| c.policy.uri() == policy.as_ref())
                    .ok_or(StatusCode::BadSecurityPolicyRejected)?,
            )
        };
        let (channel_id, seq, request_id, body) = if let Some(c) = credentials {
            crate::certificate::application_certificate(
                &c.server.der,
                &host.application_uri,
                Some(&host.bind.ip().to_string()),
                true,
            )
            .map_err(|_| StatusCode::BadCertificateInvalid)?;
            crate::certificate::application_certificate(&c.client.der, &c.client_uri, None, true)
                .map_err(|_| StatusCode::BadCertificateInvalid)?;
            crypto::unprotect_open(c.policy, &c.server, &c.client, incoming)?
        } else {
            let sender_certificate: ByteString = decode(&mut payload, ctx)?;
            let receiver_thumbprint: ByteString = decode(&mut payload, ctx)?;
            if !sender_certificate.is_null_or_empty() || !receiver_thumbprint.is_null_or_empty() {
                return Err(SECURITY);
            }
            let seq = decode(&mut payload, ctx)?;
            let req = decode(&mut payload, ctx)?;
            (integer(incoming, 8)?, seq, req, payload.to_vec())
        };
        if channel_id != self.id {
            return Err(StatusCode::BadSecureChannelIdInvalid);
        }
        self.validate_sequence(seq)?;
        let env = Envelope::parse(&body, ctx)?;
        if env.id != Some(ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary) {
            return Err(StatusCode::BadTcpMessageTypeInvalid);
        }
        let request: OpenSecureChannelRequest = env.request(ctx)?;
        let secure = credentials.is_some();
        if request.security_mode
            != if secure {
                MessageSecurityMode::SignAndEncrypt
            } else {
                MessageSecurityMode::None
            }
        {
            return Err(StatusCode::BadSecurityModeRejected);
        }
        let token_id = if let Some(old) = &self.current {
            if old.expires <= Instant::now()
                || request.request_type != SecurityTokenRequestType::Renew
                || old.rx.is_some() != secure
            {
                return Err(SECURITY);
            }
            old.id.checked_add(1).unwrap_or(1)
        } else {
            if request.request_type != SecurityTokenRequestType::Issue {
                return Err(SECURITY);
            }
            self.id = u32::from_le_bytes(nonce()?[..4].try_into().unwrap()).max(1);
            1
        };
        let lifetime = match request.requested_lifetime {
            0 => 600_000,
            n => n.clamp(1_000, 600_000),
        };
        let mut token = Token {
            id: token_id,
            expires: Instant::now() + StdDuration::from_millis(lifetime.into()),
            rx: None,
            tx: None,
        };
        let mut server_nonce = ByteString::null();
        if let Some(c) = credentials {
            let client = request.client_nonce.as_ref();
            if client.len() != 32 || client == self.last_nonce {
                return Err(StatusCode::BadNonceInvalid);
            }
            self.last_nonce = client.to_vec();
            let server = nonce()?;
            token.rx = Some(Keys::derive(c.policy, &server, client)?);
            token.tx = Some(Keys::derive(c.policy, client, &server)?);
            server_nonce = server.to_vec().into();
        }
        let response = encode(
            OpenSecureChannelResponse {
                response_header: ResponseHeader::new_good(env.handle),
                server_protocol_version: 0,
                security_token: ChannelSecurityToken {
                    channel_id: self.id,
                    token_id,
                    created_at: DateTime::now(),
                    revised_lifetime: lifetime,
                },
                server_nonce,
            },
            ctx,
        )?;
        self.previous = self.current.replace(token);
        let seq = self.next();
        if let Some(c) = credentials {
            crypto::protect_open(
                c.policy, &c.server, &c.client, self.id, seq, request_id, &response,
            )
        } else {
            let mut out = self.id.to_le_bytes().to_vec();
            BinaryEncodable::encode(&UAString::from(NONE), &mut out, ctx)?;
            out.extend((-1_i32).to_le_bytes());
            out.extend((-1_i32).to_le_bytes());
            out.extend(seq.to_le_bytes());
            out.extend(request_id.to_le_bytes());
            out.extend(response);
            Ok(frame(*b"OPNF", &out))
        }
    }

    fn unwrap(&mut self, incoming: &[u8]) -> Result<(u32, Vec<u8>)> {
        if integer(incoming, 8)? != self.id {
            return Err(StatusCode::BadSecureChannelIdInvalid);
        }
        let token_id = integer(incoming, 12)?;
        let token = self
            .current
            .iter()
            .chain(self.previous.iter())
            .find(|t| t.id == token_id && t.expires > Instant::now())
            .ok_or(StatusCode::BadSecureChannelTokenUnknown)?;
        let (seq, req, body) = if let Some(keys) = &token.rx {
            let (_, _, seq, req, body) = crypto::unprotect_message(keys, incoming)?;
            (seq, req, body)
        } else {
            (
                integer(incoming, 16)?,
                integer(incoming, 20)?,
                incoming[24..].to_vec(),
            )
        };
        self.validate_sequence(seq)?;
        if self.current.as_ref().is_some_and(|t| t.id == token_id) {
            self.previous = None;
        }
        Ok((req, body))
    }

    fn respond(
        &mut self,
        stream: &mut TcpStream,
        limits: &Limits,
        req: u32,
        body: &[u8],
    ) -> Result<()> {
        let capacity = limits.send - 80;
        let count = body.len().div_ceil(capacity);
        if body.len() > limits.message || count > limits.chunks {
            return Err(StatusCode::BadResponseTooLarge);
        }
        for (i, part) in body.chunks(capacity).enumerate() {
            let kind = if i + 1 == count { *b"MSGF" } else { *b"MSGC" };
            let seq = self.next();
            // A peer may continue using the old token until it sends its first
            // message protected by the renewed token (Part 6, §6.7.6).
            let now = Instant::now();
            let token = self
                .previous
                .iter()
                .chain(self.current.iter())
                .find(|t| t.expires > now)
                .ok_or(StatusCode::BadSecureChannelTokenUnknown)?;
            let packet = if let Some(keys) = &token.tx {
                crypto::protect_message(keys, kind, self.id, token.id, seq, req, part)?
            } else {
                let mut payload = Vec::new();
                for n in [self.id, token.id, seq, req] {
                    payload.extend(n.to_le_bytes());
                }
                payload.extend(part);
                frame(kind, &payload)
            };
            send(stream, &packet)?;
        }
        Ok(())
    }
}

fn serve(stream: &mut TcpStream, host: &Host) -> Result<()> {
    let context = ContextOwned(DecodingOptions {
        max_allocation_bytes: MESSAGE_LIMIT,
        max_array_length: 1024,
        max_string_length: 65535,
        max_byte_string_length: 65535,
        ..Default::default()
    });
    let limits = hello(stream, &context.context())?;
    let mut channel = Channel::default();
    let mut sessions = Sessions::default();
    let mut assembly = Vec::new();
    let mut chunks = 0;
    let mut active_request = None;
    let mut deadline = Instant::now() + StdDuration::from_secs(5);
    loop {
        let ctx = context.context();
        if let Some((request, response)) = sessions.poll(host, &ctx)? {
            channel.respond(stream, &limits, request, &response)?;
        }
        let wake = sessions.next_wake().unwrap_or(deadline).min(deadline);
        let wait = wake
            .saturating_duration_since(Instant::now())
            .max(StdDuration::from_millis(1));
        stream
            .set_read_timeout(Some(wait))
            .map_err(|_| StatusCode::BadConnectionClosed)?;
        match stream.peek(&mut [0]) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) && Instant::now() < deadline =>
            {
                continue;
            }
            Err(_) => return Err(StatusCode::BadConnectionClosed),
        }
        let incoming = receive(
            stream,
            limits.receive,
            deadline.min(Instant::now() + StdDuration::from_secs(5)),
        )?;
        match &incoming[..4] {
            b"OPNF" if active_request.is_none() => {
                let response = channel.open(host, &incoming, &ctx)?;
                if response.len() > limits.send {
                    return Err(StatusCode::BadResponseTooLarge);
                }
                send(stream, &response)?;
            }
            b"MSGF" | b"MSGC" | b"MSGA" | b"CLOF" if channel.current.is_some() => {
                let (request, part) = channel.unwrap(&incoming)?;
                if active_request.is_some_and(|id| id != request) {
                    return Err(SECURITY);
                }
                if &incoming[..4] == b"CLOF" {
                    return Ok(());
                }
                if &incoming[..4] == b"MSGA" {
                    assembly.clear();
                    active_request = None;
                    chunks = 0;
                    continue;
                }
                chunks += 1;
                if chunks > MAX_CHUNKS || assembly.len() + part.len() > MESSAGE_LIMIT {
                    return Err(StatusCode::BadRequestTooLarge);
                }
                assembly.extend(part);
                if &incoming[..4] == b"MSGC" {
                    if active_request.is_none() {
                        deadline = Instant::now() + StdDuration::from_secs(5);
                    }
                    active_request = Some(request);
                    continue;
                }
                let env = Envelope::parse(&assembly, &ctx)?;
                let handle = env.handle;
                let secure = channel.current.as_ref().is_some_and(|t| t.rx.is_some());
                let result = if env.id == Some(ObjectId::PublishRequest_Encoding_DefaultBinary) {
                    sessions.enqueue_publish(request, env, &ctx).map(|()| None)
                } else {
                    sessions.dispatch(host, secure, env, &ctx).map(Some)
                };
                let body = match result {
                    Ok(body) => body,
                    Err(status) => Some(super::subscriptions::fault(handle, status, &ctx)?),
                };
                if let Some(body) = body {
                    channel.respond(stream, &limits, request, &body)?;
                }
                assembly.clear();
                active_request = None;
                chunks = 0;
            }
            _ => return Err(StatusCode::BadTcpMessageTypeInvalid),
        }
        deadline = sessions.idle_deadline();
    }
}
