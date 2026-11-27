//! A session owns one authenticated TCP connection. Every service result is
//! correlated to a request on that connection, including concurrent Publish calls.

use super::{ConnectionConfig, ConnectionOptions, LeafPin, UserIdentity};
use crate::ua::{
    self, BinaryDecodable, BinaryEncodable, MessageInfo, NodeId, RequestHeader, ResponseHeader,
    StatusCode,
};
use crate::{
    discovery::DiscoveryError,
    secure_channel::{
        Identity, Keys, Peer, SecurityPolicy, nonce, protect_message, protect_open,
        unprotect_message, unprotect_open,
    },
};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, StatusCode>;
const SECURITY: StatusCode = StatusCode::BadSecurityChecksFailed;
const DECODING: StatusCode = StatusCode::BadDecodingError;
const CLOSED: StatusCode = StatusCode::BadConnectionClosed;
const MESSAGE: usize = 16 * 1024 * 1024;
const CHUNKS: usize = 256;
const MAX_PENDING: usize = 128;
const TOKEN_LIFETIME: u32 = 3_600_000;
// A token must expire before any sequence number can be reused. Two adjacent
// token windows can overlap while a peer switches to its newly issued token.
const CHUNKS_PER_TOKEN: u32 = 1 << 30;
const NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

pub(super) fn discovery_error(error: DiscoveryError) -> StatusCode {
    match error {
        DiscoveryError::Io(e) => io_status(e),
        DiscoveryError::Status(n) => n.into(),
        _ => StatusCode::BadCommunicationError,
    }
}

fn io_status(error: io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => StatusCode::BadTimeout,
        _ => CLOSED,
    }
}

fn policy_from_uri(uri: &str) -> Option<SecurityPolicy> {
    [
        SecurityPolicy::Basic256Sha256,
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Aes256Sha256RsaPss,
    ]
    .into_iter()
    .find(|p| p.uri() == uri)
}

fn token_supported(token: &ua::UserTokenPolicy, options: ConnectionOptions<'_>) -> bool {
    let uri = token.security_policy_uri.as_ref();
    match options.user_identity {
        UserIdentity::Anonymous => token.token_type == ua::UserTokenType::Anonymous,
        UserIdentity::Username { .. } => {
            token.token_type == ua::UserTokenType::UserName
                && (uri.is_empty() || uri == NONE || policy_from_uri(uri).is_some())
        }
    }
}

pub(in crate::client) trait Service:
    BinaryEncodable + MessageInfo + Send + 'static
{
    type Response: BinaryDecodable + MessageInfo + Default;
    fn header(&mut self) -> &mut RequestHeader;

    fn response_header(response: &Self::Response) -> &ResponseHeader;
}

macro_rules! services {
    ($($request:ident => $response:ident),+ $(,)?) => {
        $(
            impl Service for ua::$request {
                type Response = ua::$response;

                fn header(&mut self) -> &mut RequestHeader {
                    &mut self.request_header
                }

                fn response_header(response: &Self::Response) -> &ResponseHeader {
                    &response.response_header
                }
            }
        )+
    };
}

services!(
    OpenSecureChannelRequest => OpenSecureChannelResponse,
    CreateSessionRequest => CreateSessionResponse,
    ActivateSessionRequest => ActivateSessionResponse,
    CloseSessionRequest => CloseSessionResponse,
    CloseSecureChannelRequest => CloseSecureChannelResponse,
    ReadRequest => ReadResponse,
    WriteRequest => WriteResponse,
    BrowseRequest => BrowseResponse,
    BrowseNextRequest => BrowseNextResponse,
    TranslateBrowsePathsToNodeIdsRequest => TranslateBrowsePathsToNodeIdsResponse,
    CallRequest => CallResponse,
    HistoryReadRequest => HistoryReadResponse,
    CreateSubscriptionRequest => CreateSubscriptionResponse,
    CreateMonitoredItemsRequest => CreateMonitoredItemsResponse,
    DeleteMonitoredItemsRequest => DeleteMonitoredItemsResponse,
    DeleteSubscriptionsRequest => DeleteSubscriptionsResponse,
    PublishRequest => PublishResponse,
    RepublishRequest => RepublishResponse,
);

fn context() -> ua::ContextOwned {
    ua::ContextOwned(ua::DecodingOptions {
        max_byte_string_length: MESSAGE,
        ..Default::default()
    })
}

fn encode<R: Service>(
    mut request: R,
    id: u32,
    token: &NodeId,
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    let hdr = request.header();
    hdr.authentication_token = token.clone();
    hdr.request_handle = id;
    hdr.timestamp = ua::DateTime::now();
    if hdr.timeout_hint == 0 {
        hdr.timeout_hint = timeout.as_millis() as u32;
    }
    let ctx = context();
    let ctx = ctx.context();
    let mut data = ua::BoundedBuffer::new(limit);
    let result = NodeId::from(request.type_id() as u32)
        .encode(&mut data, &ctx)
        .and_then(|()| request.encode(&mut data, &ctx));
    if data.overflowed() {
        return Err(StatusCode::BadRequestTooLarge);
    }
    result?;
    Ok(data.into_vec())
}

fn decode<R: Service>(data: &[u8], id: u32) -> Result<R::Response> {
    let ctx = context();
    let ctx = ctx.context();
    let mut cursor = data;
    let kind = NodeId::decode(&mut cursor, &ctx)?;
    if kind == NodeId::from(ua::ObjectId::ServiceFault_Encoding_DefaultBinary as u32) {
        let fault = ua::ServiceFault::decode(&mut cursor, &ctx)?;
        if !cursor.is_empty()
            || fault.response_header.request_handle != id
            || fault.response_header.service_result.is_good()
        {
            return Err(DECODING);
        }
        return Err(fault.response_header.service_result);
    }
    if kind != NodeId::from(R::Response::default().type_id() as u32) {
        return Err(DECODING);
    }
    let response = R::Response::decode(&mut cursor, &ctx)?;
    let header = R::response_header(&response);
    if !cursor.is_empty() || header.request_handle != id {
        return Err(DECODING);
    }
    if !header.service_result.is_good() {
        return Err(header.service_result);
    }
    Ok(response)
}

fn read_frame<F>(stream: &mut TcpStream, limit: usize, mut tick: F) -> Result<Vec<u8>>
where
    F: FnMut(&TcpStream) -> Result<()>,
{
    fn fill<F: FnMut(&TcpStream) -> Result<()>>(
        stream: &mut TcpStream,
        mut dest: &mut [u8],
        tick: &mut F,
    ) -> Result<()> {
        while !dest.is_empty() {
            tick(stream)?;
            match stream.read(dest) {
                Ok(0) => return Err(CLOSED),
                Ok(n) => dest = &mut dest[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(io_status(e)),
            }
        }
        Ok(())
    }
    let mut header = [0; 8];
    fill(stream, &mut header, &mut tick)?;
    let len = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
    if !(8..=limit).contains(&len) {
        return Err(StatusCode::BadTcpMessageTooLarge);
    }
    let mut frame = header.to_vec();
    frame.resize(len, 0);
    fill(stream, &mut frame[8..], &mut tick)?;
    if &header[..4] == b"ERRF" {
        return Err(frame
            .get(8..12)
            .map(|s| StatusCode::from(u32::from_le_bytes(s.try_into().unwrap())))
            .filter(|s| s.is_bad())
            .unwrap_or(CLOSED));
    }
    Ok(frame)
}

fn next_sequence(previous: u32) -> u32 {
    if previous > u32::MAX - 1024 {
        1
    } else {
        previous + 1
    }
}

fn check_sequence(previous: u32, next: u32) -> Result<()> {
    if next == previous.wrapping_add(1) || (previous > u32::MAX - 1024 && next < 1024) {
        Ok(())
    } else {
        Err(SECURITY)
    }
}

struct Writer {
    socket: TcpStream,
    send_limit: usize,
    max_message: usize,
    max_chunks: usize,
    id: u32,
    seq: u32,
    token_chunks: u32,
    token: u32,
    channel: u32,
    send_keys: Keys,
    received: Instant,
    server_nonce: [u8; 32],
    lifetime: Duration,
    renewing: Option<(u32, [u8; 32], Instant)>,
}

impl Writer {
    fn request_id(&mut self) -> Result<u32> {
        self.id = self.id.checked_add(1).ok_or(SECURITY)?;
        Ok(self.id)
    }

    fn write(&mut self, id: u32, kind: [u8; 3], body: &[u8]) -> Result<()> {
        // Eight-byte sequence header, 16-byte channel header, signature and up to
        // one full AES block of padding must fit in every negotiated chunk.
        let per_chunk = self
            .send_limit
            .checked_sub(72)
            .filter(|&x| x > 0)
            .ok_or(SECURITY)?;
        let chunks = body.len().div_ceil(per_chunk);
        if body.len() > self.max_message || chunks > self.max_chunks {
            return Err(StatusCode::BadRequestTooLarge);
        }
        if self.token_chunks + chunks as u32 >= CHUNKS_PER_TOKEN {
            return Err(StatusCode::BadSecureChannelClosed);
        }
        self.token_chunks += chunks as u32;
        for (index, part) in body.chunks(per_chunk).enumerate() {
            let header = [
                kind[0],
                kind[1],
                kind[2],
                if index + 1 == chunks { b'F' } else { b'C' },
            ];
            self.seq = next_sequence(self.seq);
            let frame = protect_message(
                &self.send_keys,
                header,
                self.channel,
                self.token,
                self.seq,
                id,
                part,
            )?;
            self.socket.write_all(&frame).map_err(io_status)?;
        }
        Ok(())
    }
}

struct Reader {
    socket: TcpStream,
    receive_limit: usize,
    seq: u32,
    token_chunks: u32,
    channel: u32,
    token: u32,
    keys: Keys,
    token_probe: Option<u32>,
    previous: Option<(u32, Keys, Instant)>,
}

impl Reader {
    fn receive<F, G>(&mut self, mut tick: F, mut renewal: G) -> Result<(u32, Result<Vec<u8>>)>
    where
        F: FnMut(&TcpStream) -> Result<()>,
        G: FnMut(&mut Reader, &[u8]) -> Result<()>,
    {
        let mut assembled = Vec::new();
        let mut chunks = 0;
        let mut request = None;
        loop {
            let frame = read_frame(&mut self.socket, self.receive_limit, &mut tick)?;
            if frame.starts_with(b"OPNF") && chunks == 0 {
                renewal(self, &frame)?;
                continue;
            }
            if &frame[..3] != b"MSG" {
                return Err(SECURITY);
            }
            let token = u32::from_le_bytes(frame.get(12..16).ok_or(SECURITY)?.try_into().unwrap());
            let keys = if token == self.token {
                &self.keys
            } else {
                &self
                    .previous
                    .as_ref()
                    .filter(|(id, _, expiry)| *id == token && *expiry > Instant::now())
                    .ok_or(SECURITY)?
                    .1
            };
            let (channel, _, seq, id, body) = unprotect_message(keys, &frame)?;
            if channel != self.channel || request.is_some_and(|bound| id != bound) {
                return Err(SECURITY);
            }
            self.token_chunks += 1;
            if self.token_chunks >= CHUNKS_PER_TOKEN {
                return Err(StatusCode::BadSecureChannelClosed);
            }
            check_sequence(self.seq, seq)?;
            self.seq = seq;
            request = Some(id);
            chunks += 1;
            if assembled.len() + body.len() > MESSAGE || chunks > CHUNKS {
                return Err(StatusCode::BadResponseTooLarge);
            }
            match frame[3] {
                b'A' => {
                    // An authenticated abort terminates only the current message.
                    let ctx = context();
                    let ctx = ctx.context();
                    let mut bytes = body.as_slice();
                    let status = StatusCode::decode(&mut bytes, &ctx)?;
                    ua::UAString::decode(&mut bytes, &ctx)?;
                    if !bytes.is_empty() || !status.is_bad() {
                        return Err(DECODING);
                    }
                    return Ok((id, Err(status)));
                }
                b'C' => assembled.extend(body),
                b'F' => {
                    assembled.extend(body);
                    return Ok((id, Ok(assembled)));
                }
                _ => return Err(SECURITY),
            }
        }
    }
}

struct Security {
    local: Identity,
    peer: Peer,
    policy: SecurityPolicy,
}

fn open_request(
    policy: &Security,
    channel: u32,
    seq: u32,
    id: u32,
    timeout: Duration,
    token: &NodeId,
) -> Result<([u8; 32], Vec<u8>)> {
    let random = nonce()?;
    let request = ua::OpenSecureChannelRequest {
        client_nonce: random.to_vec().into(),
        requested_lifetime: TOKEN_LIFETIME,
        request_type: if channel == 0 {
            ua::SecurityTokenRequestType::Issue
        } else {
            ua::SecurityTokenRequestType::Renew
        },
        security_mode: ua::MessageSecurityMode::SignAndEncrypt,
        ..Default::default()
    };
    let body = encode(request, id, token, timeout, MESSAGE)?;
    let frame = protect_open(
        policy.policy,
        &policy.local,
        &policy.peer,
        channel,
        seq,
        id,
        &body,
    )?;
    Ok((random, frame))
}

struct Opened {
    channel: u32,
    server_nonce: [u8; 32],
    token: u32,
    seq: u32,
    lifetime: Duration,
    send: Keys,
    receive: Keys,
}

fn opened(security: &Security, frame: &[u8], id: u32, client_nonce: &[u8]) -> Result<Opened> {
    let (channel, seq, request, body) =
        unprotect_open(security.policy, &security.local, &security.peer, frame)?;
    if id != request {
        return Err(SECURITY);
    }
    let reply = decode::<ua::OpenSecureChannelRequest>(&body, id)?;
    let token = reply.security_token;
    if reply.server_protocol_version != 0
        || channel == 0
        || channel != token.channel_id
        || token.token_id == 0
        || token.revised_lifetime == 0
    {
        return Err(SECURITY);
    }
    Ok(Opened {
        server_nonce: reply
            .server_nonce
            .as_ref()
            .try_into()
            .map_err(|_| SECURITY)?,
        channel,
        seq,
        token: token.token_id,
        lifetime: Duration::from_millis(u64::from(token.revised_lifetime)),
        send: Keys::derive(security.policy, reply.server_nonce.as_ref(), client_nonce)?,
        receive: Keys::derive(security.policy, client_nonce, reply.server_nonce.as_ref())?,
    })
}

fn before(deadline: Instant, socket: &TcpStream) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(StatusCode::BadTimeout)?;
    socket.set_read_timeout(Some(remaining)).map_err(io_status)
}

fn exchange<R: Service>(
    writer: &mut Writer,
    reader: &mut Reader,
    token: &NodeId,
    request: R,
    timeout: Duration,
) -> Result<R::Response> {
    let id = writer.request_id()?;
    let body = encode(request, id, token, timeout, writer.max_message)?;
    writer.write(id, *b"MSG", &body)?;
    let deadline = Instant::now() + timeout;
    let (reply, body) = reader.receive(|s| before(deadline, s), |_, _| Err(SECURITY))?;
    if reply != id {
        return Err(SECURITY);
    }
    decode::<R>(&body?, id)
}

fn identity_token(
    selected: &ua::UserTokenPolicy,
    options: ConnectionOptions<'_>,
    peer: &Peer,
    server_nonce: &[u8],
) -> Result<ua::ExtensionObject> {
    let policy_id = selected.policy_id.clone();
    let uri = selected.security_policy_uri.as_ref();
    Ok(match options.user_identity {
        UserIdentity::Anonymous => {
            ua::ExtensionObject::new(ua::AnonymousIdentityToken { policy_id })
        }
        UserIdentity::Username { username, password } => {
            let (bytes, algorithm) = if uri == NONE {
                (password.as_bytes().to_vec(), ua::UAString::null())
            } else {
                let policy = if uri.is_empty() {
                    options.security_policy
                } else {
                    policy_from_uri(uri).ok_or(SECURITY)?
                };
                let mut plaintext = Zeroizing::new(
                    ((password.len() + server_nonce.len()) as u32)
                        .to_le_bytes()
                        .to_vec(),
                );
                plaintext.extend(password.as_bytes());
                plaintext.extend(server_nonce);
                (
                    peer.encrypt(policy, &plaintext)?,
                    policy.encryption_uri().into(),
                )
            };
            ua::ExtensionObject::new(ua::UserNameIdentityToken {
                policy_id,
                user_name: username.into(),
                password: bytes.into(),
                encryption_algorithm: algorithm,
            })
        }
    })
}

fn validate_session_nonce(nonce: &[u8], previous: &[u8]) -> Result<()> {
    if !(32..=128).contains(&nonce.len()) || nonce == previous || nonce.iter().all(|&b| b == 0) {
        return Err(StatusCode::BadNonceInvalid);
    }
    Ok(())
}

fn activate(
    config: ConnectionConfig<'_>,
    options: ConnectionOptions<'_>,
    pin: &LeafPin,
    security: &Security,
    writer: &mut Writer,
    reader: &mut Reader,
) -> Result<NodeId> {
    let client_nonce = nonce()?;
    let request = ua::CreateSessionRequest {
        client_description: ua::ApplicationDescription {
            application_uri: config.client_application_uri.into(),
            product_uri: "urn:opcua-kit".into(),
            application_name: ua::LocalizedText::new("en", "opcua-kit"),
            application_type: ua::ApplicationType::Client,
            ..Default::default()
        },
        server_uri: config.server_application_uri.into(),
        endpoint_url: config.endpoint.into(),
        session_name: "opcua-kit".into(),
        client_nonce: client_nonce.to_vec().into(),
        client_certificate: security.local.der.clone().into(),
        requested_session_timeout: 600_000.0,
        max_response_message_size: MESSAGE as u32,
        ..Default::default()
    };
    let reply = exchange(writer, reader, &NodeId::null(), request, config.timeout)?;
    let server_nonce = reply.server_nonce.as_ref();
    validate_session_nonce(server_nonce, &client_nonce)?;
    if !reply
        .server_certificate
        .as_ref()
        .starts_with(&security.peer.der)
        || reply.server_signature.algorithm.as_ref() != security.policy.signature_uri()
        || reply.authentication_token.is_null()
        || reply.session_id.is_null()
        || !reply.revised_session_timeout.is_finite()
        || reply.revised_session_timeout <= 0.0
    {
        return Err(SECURITY);
    }
    let signed = [security.local.der.as_slice(), &client_nonce].concat();
    security.peer.verify(
        security.policy,
        &signed,
        reply.server_signature.signature.as_ref(),
    )?;
    let endpoints = reply
        .server_endpoints
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|ep| {
            ep.security_mode == ua::MessageSecurityMode::SignAndEncrypt
                && ep.security_policy_uri.as_ref() == security.policy.uri()
                && ep.transport_profile_uri.as_ref()
                    == "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
        });
    if endpoints.clone().next().is_none() {
        return Err(StatusCode::BadSecurityPolicyRejected);
    }
    let mut endpoints = endpoints
        .filter(|ep| ep.server.application_uri.as_ref() == config.server_application_uri)
        .peekable();
    if endpoints.peek().is_none() {
        return Err(StatusCode::BadCertificateUriInvalid);
    }
    let selected = endpoints
        .flat_map(|ep| ep.user_identity_tokens.as_deref().unwrap_or_default())
        .filter(|token| token_supported(token, options))
        .min_by_key(|token| token.security_policy_uri.as_ref() == NONE)
        .ok_or(StatusCode::BadIdentityTokenRejected)?;
    if !(pin.not_before..=pin.not_after).contains(&OffsetDateTime::now_utc().unix_timestamp()) {
        return Err(StatusCode::BadCertificateTimeInvalid);
    }
    if reply.max_request_message_size != 0 {
        writer.max_message = writer
            .max_message
            .min(reply.max_request_message_size as usize);
    }
    let signed = [reply.server_certificate.as_ref(), server_nonce].concat();
    let request = ua::ActivateSessionRequest {
        client_signature: ua::SignatureData {
            algorithm: security.policy.signature_uri().into(),
            signature: security.local.sign(security.policy, &signed)?.into(),
        },
        user_identity_token: identity_token(selected, options, &security.peer, server_nonce)?,
        ..Default::default()
    };
    let activated = exchange(
        writer,
        reader,
        &reply.authentication_token,
        request,
        config.timeout,
    )?;
    validate_session_nonce(activated.server_nonce.as_ref(), server_nonce)?;
    Ok(reply.authentication_token)
}

struct Pending {
    deadline: Instant,
    reply: oneshot::Sender<Result<Vec<u8>>>,
}
struct Shared {
    socket: TcpStream,
    writer: Mutex<Writer>,
    pending: Mutex<HashMap<u32, Pending>>,
    security: Security,
    token: NodeId,
    timeout: Duration,
    alive: AtomicBool,
}

impl Shared {
    fn close(&self, status: StatusCode) {
        self.alive.store(false, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
        for (_, pending) in self.pending.lock().unwrap().drain() {
            let _ = pending.reply.send(Err(status));
        }
    }

    fn tick(&self, socket: &TcpStream) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        let elapsed = writer.received.elapsed();
        if !self.alive.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        if elapsed >= writer.lifetime {
            return Err(StatusCode::BadSecureChannelClosed);
        }
        let renew = writer.lifetime.mul_f32(0.75);
        if elapsed >= renew && writer.renewing.is_none() {
            let id = writer.request_id()?;
            writer.seq = next_sequence(writer.seq);
            let (random, frame) = open_request(
                &self.security,
                writer.channel,
                writer.seq,
                id,
                self.timeout,
                &self.token,
            )?;
            if frame.len() > writer.send_limit {
                return Err(StatusCode::BadRequestTooLarge);
            }
            writer.socket.write_all(&frame).map_err(io_status)?;
            writer.renewing = Some((id, random, Instant::now()));
        }
        let wait = if let Some((_, _, started)) = writer.renewing {
            self.timeout
                .checked_sub(started.elapsed())
                .ok_or(StatusCode::BadTimeout)?
                .min(writer.lifetime - elapsed)
        } else {
            renew - elapsed
        };
        let pending_deadline = self
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|p| p.deadline)
            .min();
        let service_wait = match pending_deadline {
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .ok_or(StatusCode::BadTimeout)?,
            None => self.timeout,
        };
        // A new request may be queued while the socket sleeps. Its shortest
        // possible deadline is the configured timeout from registration.
        let wait = wait.min(service_wait).min(self.timeout);
        socket
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(io_status)
    }

    fn renewal(&self, reader: &mut Reader, frame: &[u8]) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        let (id, random, started) = writer.renewing.take().ok_or(SECURITY)?;
        let open = opened(&self.security, frame, id, &random)?;
        check_sequence(reader.seq, open.seq)?;
        if open.channel != writer.channel
            || open.token == writer.token
            || open.server_nonce == writer.server_nonce
            || reader.token_probe.is_some()
        {
            return Err(SECURITY);
        }
        reader.previous = Some((
            reader.token,
            std::mem::replace(&mut reader.keys, open.receive),
            writer.received + writer.lifetime,
        ));
        reader.seq = open.seq;
        reader.token_chunks = 0;
        writer.token_chunks = 0;
        reader.token = open.token;
        writer.received = started;
        writer.lifetime = open.lifetime;
        writer.token = open.token;
        writer.server_nonce = open.server_nonce;
        writer.send_keys = open.send;
        // The server switches to the renewed token on its first symmetric request.
        // An idle session must use it before negotiating its successor.
        let id = writer.request_id()?;
        let probe = ua::ReadRequest {
            timestamps_to_return: ua::TimestampsToReturn::Neither,
            nodes_to_read: Some(vec![ua::ReadValueId {
                // Confirm the token using metadata on the standard Server object.
                node_id: NodeId::from(2253u32),
                attribute_id: ua::AttributeId::NodeClass as u32,
                ..Default::default()
            }]),
            ..Default::default()
        };
        let body = encode(probe, id, &self.token, self.timeout, writer.max_message)?;
        writer.write(id, *b"MSG", &body)?;
        reader.token_probe = Some(id);
        Ok(())
    }

    fn dispatch<R: Service>(
        &self,
        request: R,
        deadline: Instant,
    ) -> Result<(u32, oneshot::Receiver<Result<Vec<u8>>>)> {
        let mut writer = self.writer.lock().unwrap();
        if !self.alive.load(Ordering::Acquire) || writer.received.elapsed() >= writer.lifetime {
            return Err(CLOSED);
        }
        if Instant::now() >= deadline {
            return Err(StatusCode::BadTimeout);
        }
        let id = writer.request_id()?;
        let body = encode(request, id, &self.token, self.timeout, writer.max_message)?;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= MAX_PENDING {
                return Err(StatusCode::BadTooManyOperations);
            }
            pending.insert(
                id,
                Pending {
                    deadline,
                    reply: tx,
                },
            );
        }
        if let Err(e) = writer.write(id, *b"MSG", &body) {
            self.pending.lock().unwrap().remove(&id);
            if e != StatusCode::BadRequestTooLarge {
                self.close(e);
            }
            return Err(e);
        }
        Ok((id, rx))
    }
}

/// Multiplexed service transport on one authenticated session.
pub(in crate::client) struct Session {
    shared: Arc<Shared>,
}

impl Session {
    pub(super) fn connect(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        local: Identity,
        pin: &LeafPin,
    ) -> Result<Self> {
        let security = Security {
            local,
            peer: Peer::new(&pin.der)?,
            policy: options.security_policy,
        };
        let (mut socket, receive_limit, send_limit, peer_message, peer_chunks) =
            crate::discovery::secure_socket(config.endpoint, config.timeout, MESSAGE, CHUNKS)
                .map_err(discovery_error)?;
        let start = Instant::now();
        let (random, frame) = open_request(&security, 0, 1, 1, config.timeout, &NodeId::null())?;
        if frame.len() > send_limit {
            return Err(StatusCode::BadRequestTooLarge);
        }
        socket.write_all(&frame).map_err(io_status)?;
        let deadline = Instant::now() + config.timeout;
        let frame = read_frame(&mut socket, receive_limit, |s| before(deadline, s))?;
        let open = opened(&security, &frame, 1, &random)?;
        let mut reader = Reader {
            socket: socket.try_clone().map_err(io_status)?,
            receive_limit,
            seq: open.seq,
            token_chunks: 0,
            channel: open.channel,
            token: open.token,
            keys: open.receive,
            token_probe: None,
            previous: None,
        };
        let mut writer = Writer {
            socket,
            send_limit,
            max_message: if peer_message == 0 {
                MESSAGE
            } else {
                MESSAGE.min(peer_message)
            },
            max_chunks: if peer_chunks == 0 {
                CHUNKS
            } else {
                CHUNKS.min(peer_chunks)
            },
            id: 1,
            seq: 1,
            token_chunks: 0,
            token: open.token,
            channel: open.channel,
            send_keys: open.send,
            received: start,
            server_nonce: open.server_nonce,
            lifetime: open.lifetime,
            renewing: None,
        };
        let token = activate(config, options, pin, &security, &mut writer, &mut reader)?;
        let shared = Arc::new(Shared {
            socket: writer.socket.try_clone().map_err(io_status)?,
            writer: Mutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            security,
            token,
            timeout: config.timeout,
            alive: AtomicBool::new(true),
        });
        let rx = shared.clone();
        std::thread::Builder::new()
            .name("opcua-session".into())
            .spawn(move || {
                let reason = loop {
                    match reader.receive(|s| rx.tick(s), |reader, frame| rx.renewal(reader, frame))
                    {
                        Ok((id, body)) if reader.token_probe == Some(id) => {
                            if let Err(e) = body.and_then(|b| decode::<ua::ReadRequest>(&b, id)) {
                                break e;
                            }
                            reader.token_probe = None;
                        }
                        Ok((id, body)) => {
                            let Some(waiter) = rx.pending.lock().unwrap().remove(&id) else {
                                break SECURITY;
                            };
                            let _ = waiter.reply.send(body);
                        }
                        Err(e) => break e,
                    }
                };
                rx.close(reason);
            })
            .map_err(io_status)?;
        Ok(Self { shared })
    }

    pub(in crate::client) fn is_alive(&self) -> bool {
        self.shared.alive.load(Ordering::Acquire)
    }

    pub(in crate::client) async fn request<R: Service>(
        &self,
        mut request: R,
    ) -> Result<R::Response> {
        let hint = request.header().timeout_hint;
        let deadline = if hint == 0 {
            self.shared.timeout
        } else {
            Duration::from_millis(u64::from(hint)) + self.shared.timeout
        };
        let deadline = Instant::now() + deadline;
        let shared = self.shared.clone();
        let (id, rx) = tokio::task::spawn_blocking(move || shared.dispatch(request, deadline))
            .await
            .map_err(|_| CLOSED)??;
        let reply = rx.await.map_err(|_| CLOSED)??;
        decode::<R>(&reply, id)
    }

    pub(super) async fn disconnect(&self) {
        let _ = self
            .request(ua::CloseSessionRequest {
                delete_subscriptions: true,
                ..Default::default()
            })
            .await;
        let shared = self.shared.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut writer = shared.writer.lock().unwrap();
            if let Ok(id) = writer.request_id()
                && let Ok(body) = encode(
                    ua::CloseSecureChannelRequest::default(),
                    id,
                    &shared.token,
                    shared.timeout,
                    writer.max_message,
                )
            {
                let _ = writer.write(id, *b"CLO", &body);
            }
            shared.close(CLOSED);
        })
        .await;
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.shared.close(CLOSED);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn session_nonce_length_and_freshness_follow_the_service_contract() {
        let previous = [11; 32];
        for nonce in [&[7; 32][..], &[9; 128]] {
            validate_session_nonce(nonce, &previous).unwrap();
        }
        for nonce in [&[7; 31][..], &[9; 129], &[0; 32], &previous] {
            assert_eq!(
                validate_session_nonce(nonce, &previous),
                Err(StatusCode::BadNonceInvalid)
            );
        }
    }

    #[test]
    fn aggregate_request_limit_applies_across_individually_small_operands() {
        let request = ua::ReadRequest {
            nodes_to_read: Some(vec![ua::ReadValueId::default(); 256]),
            ..Default::default()
        };
        assert_eq!(
            encode(request, 1, &NodeId::null(), Duration::from_secs(1), 1024),
            Err(StatusCode::BadRequestTooLarge)
        );
    }

    #[test]
    fn legacy_sequence_wrap_preserves_the_replay_boundary() {
        assert!(check_sequence(10, 10).is_err());
        assert!(check_sequence(10, 12).is_err());
        assert!(check_sequence(u32::MAX - 1024, 1).is_err());
        assert!(check_sequence(u32::MAX - 1023, 1023).is_ok());
        assert!(check_sequence(u32::MAX - 1, 1024).is_err());
        assert_eq!(next_sequence(u32::MAX - 1024), u32::MAX - 1023);
    }

    #[test]
    fn authenticated_abort_discards_only_its_partial_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let keys = Keys::derive(SecurityPolicy::Basic256Sha256, &[1; 32], &[2; 32]).unwrap();
        let status = StatusCode::BadRequestInterrupted;
        let ctx = context();
        let ctx = ctx.context();
        let mut reason = Vec::new();
        status.encode(&mut reason, &ctx).unwrap();
        ua::UAString::from("interrupted")
            .encode(&mut reason, &ctx)
            .unwrap();
        for (header, seq, id, body) in [
            (*b"MSGC", 1, 5, b"partial".as_slice()),
            (*b"MSGA", 2, 5, &reason),
            (*b"MSGF", 3, 6, b"next".as_slice()),
        ] {
            let frame = protect_message(&keys, header, 10, 20, seq, id, body).unwrap();
            peer.write_all(&frame).unwrap();
        }
        let mut reader = Reader {
            socket,
            receive_limit: 8192,
            seq: 0,
            token_chunks: 0,
            channel: 10,
            token: 20,
            keys,
            token_probe: None,
            previous: None,
        };
        let mut next = || reader.receive(|_| Ok(()), |_, _| Err(SECURITY)).unwrap();
        assert_eq!(next(), (5, Err(status)));
        assert_eq!(next(), (6, Ok(b"next".to_vec())));
    }
}
