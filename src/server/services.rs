use super::{Host, NONE, TRANSPORT, transport::MESSAGE_LIMIT};
use crate::secure_channel::nonce;
use crate::ua::{BinaryDecodable, BinaryEncodable, *};
use std::{
    collections::HashMap,
    time::{Duration as StdDuration, Instant},
};

type ServiceResult<T> = Result<T, StatusCode>;

pub(super) fn decode<T: BinaryDecodable>(bytes: &mut &[u8], ctx: &Context<'_>) -> ServiceResult<T> {
    T::decode(bytes, ctx)
}

fn exact<T: BinaryDecodable>(mut bytes: &[u8], ctx: &Context<'_>) -> ServiceResult<T> {
    let value = decode(&mut bytes, ctx)?;
    if !bytes.is_empty() {
        return Err(StatusCode::BadDecodingError);
    }
    Ok(value)
}

pub(super) fn encode<T: BinaryEncodable + MessageInfo>(
    value: T,
    ctx: &Context<'_>,
) -> ServiceResult<Vec<u8>> {
    let mut buffer = BoundedBuffer::new(MESSAGE_LIMIT);
    NodeId::from(value.type_id()).encode(&mut buffer, ctx)?;
    let result = value.encode(&mut buffer, ctx);
    if buffer.overflowed() {
        return Err(StatusCode::BadResponseTooLarge);
    }
    result?;
    Ok(buffer.into_vec())
}

pub(super) struct Envelope<'a> {
    pub id: Option<ObjectId>,
    pub handle: u32,
    token: NodeId,
    full_request: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub fn parse(mut bytes: &'a [u8], ctx: &Context<'_>) -> ServiceResult<Self> {
        let ty: NodeId = decode(&mut bytes, ctx)?;
        let id = ty.as_object_id().ok();
        let full_request = bytes;
        let header: RequestHeader = decode(&mut bytes, ctx)?;
        Ok(Self {
            id,
            handle: header.request_handle,
            token: header.authentication_token,
            full_request,
        })
    }

    pub fn request<T: BinaryDecodable>(&self, ctx: &Context<'_>) -> ServiceResult<T> {
        exact(self.full_request, ctx)
    }
}

impl Host {
    fn endpoint(&self) -> EndpointDescription {
        let secure = self.credentials.as_ref();
        let url = format!("opc.tcp://{}", self.bind);
        EndpointDescription {
            endpoint_url: url.clone().into(),
            server: ApplicationDescription {
                application_uri: self.application_uri.clone().into(),
                product_uri: "urn:opcua-kit".into(),
                application_name: LocalizedText::new("", "opcua-kit"),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: Some(vec![url.into()]),
            },
            server_certificate: secure
                .map(|c| c.server.der.clone().into())
                .unwrap_or_default(),
            security_mode: if secure.is_some() {
                MessageSecurityMode::SignAndEncrypt
            } else {
                MessageSecurityMode::None
            },
            security_policy_uri: secure.map_or(NONE, |c| c.policy.uri()).into(),
            user_identity_tokens: Some(vec![UserTokenPolicy {
                policy_id: "anonymous".into(),
                token_type: UserTokenType::Anonymous,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::null(),
            }]),
            transport_profile_uri: TRANSPORT.into(),
            security_level: u8::from(secure.is_some()),
        }
    }
}

struct Session {
    token: NodeId,
    challenge: [u8; 32],
    active: bool,
    touched: Instant,
    timeout: StdDuration,
    response_limit: usize,
    subscriptions: super::subscriptions::Subscriptions,
    cursors: HashMap<Vec<u8>, (usize, BrowseDescription, NodeId)>,
}

/// Session state and continuation points belong to the connection that authenticated them.
#[derive(Default)]
pub(super) struct Sessions(Option<Session>);

impl Sessions {
    fn authorized(&mut self, token: &NodeId) -> ServiceResult<&mut Session> {
        let expired = self
            .0
            .as_ref()
            .is_some_and(|s| s.touched.elapsed() >= s.timeout);
        if expired {
            self.0 = None;
            return Err(StatusCode::BadSessionClosed);
        }
        let session = self.0.as_mut().ok_or(StatusCode::BadSessionIdInvalid)?;
        if *token != session.token {
            return Err(StatusCode::BadSessionIdInvalid);
        }
        session.touched = Instant::now();
        Ok(session)
    }

    pub fn enqueue_publish(
        &mut self,
        id: u32,
        env: Envelope<'_>,
        ctx: &Context<'_>,
    ) -> ServiceResult<()> {
        let session = self.authorized(&env.token)?;
        if !session.active {
            return Err(StatusCode::BadSessionNotActivated);
        }
        session.subscriptions.enqueue(id, env.request(ctx)?)
    }

    pub fn idle_deadline(&self) -> Instant {
        self.0.as_ref().filter(|s| s.active).map_or_else(
            || Instant::now() + StdDuration::from_secs(5),
            |s| s.touched + s.timeout,
        )
    }

    pub fn next_wake(&self) -> Option<Instant> {
        self.0.as_ref().map(|s| {
            s.subscriptions
                .next_wake()
                .unwrap_or(s.touched + s.timeout)
                .min(s.touched + s.timeout)
        })
    }

    pub fn poll(
        &mut self,
        host: &Host,
        ctx: &Context<'_>,
    ) -> ServiceResult<Option<(u32, Vec<u8>)>> {
        if self
            .0
            .as_ref()
            .is_some_and(|s| s.touched.elapsed() >= s.timeout)
        {
            self.0 = None;
            return Ok(None);
        }
        match &mut self.0 {
            Some(s) => s.subscriptions.poll(host, ctx, s.response_limit),
            None => Ok(None),
        }
    }

    pub fn dispatch(
        &mut self,
        host: &Host,
        secure: bool,
        request: Envelope<'_>,
        ctx: &Context<'_>,
    ) -> ServiceResult<Vec<u8>> {
        use ObjectId::*;
        let id = request.id.ok_or(StatusCode::BadServiceUnsupported)?;
        let handle = request.handle;
        let response_header = ResponseHeader::new_good(handle);
        match id {
            FindServersRequest_Encoding_DefaultBinary => {
                let find: FindServersRequest = request.request(ctx)?;
                let filter = find.server_uris.unwrap_or_default();
                let app = host.endpoint().server;
                let servers = if filter.is_empty() || filter.contains(&app.application_uri) {
                    vec![app]
                } else {
                    vec![]
                };
                return encode(
                    FindServersResponse {
                        response_header,
                        servers: Some(servers),
                    },
                    ctx,
                );
            }
            GetEndpointsRequest_Encoding_DefaultBinary => {
                let get: GetEndpointsRequest = request.request(ctx)?;
                let filter = get.profile_uris.unwrap_or_default();
                let endpoints =
                    if filter.is_empty() || filter.iter().any(|s| s.as_ref() == TRANSPORT) {
                        vec![host.endpoint()]
                    } else {
                        vec![]
                    };
                return encode(
                    GetEndpointsResponse {
                        response_header,
                        endpoints: Some(endpoints),
                    },
                    ctx,
                );
            }
            CreateSessionRequest_Encoding_DefaultBinary => {
                if host.credentials.is_some() != secure {
                    return Err(StatusCode::BadSecurityPolicyRejected);
                }
                if self
                    .0
                    .as_ref()
                    .is_some_and(|s| s.touched.elapsed() < s.timeout)
                {
                    return Err(StatusCode::BadTooManySessions);
                }
                let create: CreateSessionRequest = request.request(ctx)?;
                if !create.requested_session_timeout.is_finite() {
                    return Err(StatusCode::BadInvalidArgument);
                }
                let mut signature = SignatureData {
                    algorithm: UAString::null(),
                    signature: ByteString::null(),
                };
                if let Some(c) = &host.credentials {
                    if create.client_description.application_uri.as_ref() != c.client_uri {
                        return Err(StatusCode::BadCertificateUriInvalid);
                    }
                    if create.client_certificate.as_ref() != c.client.der {
                        return Err(StatusCode::BadCertificateInvalid);
                    }
                    if !(32..=128).contains(&create.client_nonce.len()) {
                        return Err(StatusCode::BadNonceInvalid);
                    }
                    let proof = [c.client.der.as_slice(), create.client_nonce.as_ref()].concat();
                    signature.algorithm = c.policy.signature_uri().into();
                    signature.signature = c.server.sign(c.policy, &proof)?.into();
                }
                let revised = if create.requested_session_timeout <= 0.0 {
                    60_000.0
                } else {
                    create.requested_session_timeout.clamp(1_000.0, 300_000.0)
                };
                let challenge = nonce()?;
                let token = NodeId::new(1, ByteString::from(nonce()?.to_vec()));
                self.0 = Some(Session {
                    token: token.clone(),
                    challenge,
                    active: false,
                    touched: Instant::now(),
                    timeout: StdDuration::from_secs_f64(revised / 1000.0),
                    subscriptions: Default::default(),
                    cursors: HashMap::new(),
                    response_limit: if create.max_response_message_size == 0 {
                        MESSAGE_LIMIT
                    } else {
                        (create.max_response_message_size as usize).min(MESSAGE_LIMIT)
                    },
                });
                let endpoint = host.endpoint();
                return encode(
                    CreateSessionResponse {
                        response_header,
                        session_id: NodeId::new(1, ByteString::from(nonce()?.to_vec())),
                        authentication_token: token,
                        revised_session_timeout: revised,
                        server_nonce: challenge.to_vec().into(),
                        server_certificate: endpoint.server_certificate.clone(),
                        server_endpoints: Some(vec![endpoint]),
                        server_software_certificates: None,
                        server_signature: signature,
                        max_request_message_size: MESSAGE_LIMIT as u32,
                    },
                    ctx,
                );
            }
            _ => {}
        }
        let session = self.authorized(&request.token)?;
        if id == ActivateSessionRequest_Encoding_DefaultBinary {
            let activation: ActivateSessionRequest = request.request(ctx)?;
            // Part 4 §5.7.3.2 interprets a null user token as anonymous.
            if !activation.user_identity_token.is_null() {
                let identity = activation
                    .user_identity_token
                    .inner_as::<AnonymousIdentityToken>()
                    .ok_or(StatusCode::BadIdentityTokenRejected)?;
                if !identity.policy_id.is_empty() && identity.policy_id.as_ref() != "anonymous" {
                    return Err(StatusCode::BadIdentityTokenInvalid);
                }
            }
            let signature = activation.client_signature;
            if let Some(c) = &host.credentials {
                if signature.algorithm.as_ref() != c.policy.signature_uri() {
                    return Err(StatusCode::BadApplicationSignatureInvalid);
                }
                let proof = [c.server.der.as_slice(), &session.challenge].concat();
                c.client
                    .verify(c.policy, &proof, signature.signature.as_ref())
                    .map_err(|_| StatusCode::BadApplicationSignatureInvalid)?;
            }
            session.challenge = nonce()?;
            session.active = true;
            return encode(
                ActivateSessionResponse {
                    response_header,
                    server_nonce: session.challenge.to_vec().into(),
                    results: None,
                    diagnostic_infos: None,
                },
                ctx,
            );
        }
        if id == CloseSessionRequest_Encoding_DefaultBinary {
            let _: CloseSessionRequest = request.request(ctx)?;
            self.0 = None;
            return encode(CloseSessionResponse { response_header }, ctx);
        }
        if !session.active {
            return Err(StatusCode::BadSessionNotActivated);
        }
        let body = match id {
            ReadRequest_Encoding_DefaultBinary => {
                let read: ReadRequest = request.request(ctx)?;
                if !read.max_age.is_finite() || read.max_age < 0.0 {
                    return Err(StatusCode::BadMaxAgeInvalid);
                }
                if read.timestamps_to_return == TimestampsToReturn::Invalid {
                    return Err(StatusCode::BadTimestampsToReturnInvalid);
                }
                let nodes = operations(read.nodes_to_read)?;
                let mut budget = session.response_limit;
                let mut results = Vec::with_capacity(nodes.len());
                for item in nodes {
                    let value =
                        host.read(item, read.timestamps_to_return)
                            .unwrap_or_else(|status| DataValue {
                                status: Some(status),
                                ..DataValue::null()
                            });
                    budget = budget
                        .checked_sub(value.encoded_len(ctx)?)
                        .ok_or(StatusCode::BadResponseTooLarge)?;
                    results.push(value);
                }
                encode(
                    ReadResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )?
            }
            TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary => {
                let translate: TranslateBrowsePathsToNodeIdsRequest = request.request(ctx)?;
                let results = operations(translate.browse_paths)?
                    .into_iter()
                    .map(|path| match host.translate(path) {
                        Ok(targets) => BrowsePathResult {
                            status_code: StatusCode::Good,
                            targets: Some(targets),
                        },
                        Err(status_code) => BrowsePathResult {
                            status_code,
                            targets: None,
                        },
                    })
                    .collect();
                encode(
                    TranslateBrowsePathsToNodeIdsResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )?
            }
            BrowseRequest_Encoding_DefaultBinary => {
                let browse: BrowseRequest = request.request(ctx)?;
                if !browse.view.view_id.is_null() {
                    return Err(StatusCode::BadViewIdUnknown);
                }
                let size = match browse.requested_max_references_per_node {
                    0 => 128,
                    n => n.min(128) as usize,
                };
                let mut results = Vec::new();
                let mut budget = session.response_limit;
                for item in operations(browse.nodes_to_browse)? {
                    let result = session
                        .page(host, item, size, None)
                        .unwrap_or_else(browse_error);
                    budget = budget
                        .checked_sub(result.encoded_len(ctx)?)
                        .ok_or(StatusCode::BadResponseTooLarge)?;
                    results.push(result);
                }
                encode(
                    BrowseResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )?
            }
            BrowseNextRequest_Encoding_DefaultBinary => {
                let next: BrowseNextRequest = request.request(ctx)?;
                let mut results = Vec::new();
                for token in operations(next.continuation_points)? {
                    let Some((size, browse, after)) = session.cursors.remove(token.as_ref()) else {
                        results.push(browse_error(StatusCode::BadContinuationPointInvalid));
                        continue;
                    };
                    if !next.release_continuation_points {
                        results.push(
                            session
                                .page(host, browse, size, Some(after))
                                .unwrap_or_else(browse_error),
                        );
                    }
                }
                if next.release_continuation_points {
                    results.clear();
                }
                encode(
                    BrowseNextResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )?
            }
            WriteRequest_Encoding_DefaultBinary
            | AddNodesRequest_Encoding_DefaultBinary
            | DeleteNodesRequest_Encoding_DefaultBinary
            | AddReferencesRequest_Encoding_DefaultBinary
            | DeleteReferencesRequest_Encoding_DefaultBinary
            | CallRequest_Encoding_DefaultBinary
            | HistoryUpdateRequest_Encoding_DefaultBinary => {
                return Err(StatusCode::BadUserAccessDenied);
            }
            _ => session.subscriptions.request(host, request, ctx)?,
        };
        if body.len() > session.response_limit {
            return Err(StatusCode::BadResponseTooLarge);
        }
        Ok(body)
    }
}

pub(super) fn operations<T>(operations: Option<Vec<T>>) -> ServiceResult<Vec<T>> {
    let operations = operations.unwrap_or_default();
    match operations.len() {
        0 => Err(StatusCode::BadNothingToDo),
        1..=1024 => Ok(operations),
        _ => Err(StatusCode::BadTooManyOperations),
    }
}

impl Session {
    fn page(
        &mut self,
        host: &Host,
        browse: BrowseDescription,
        size: usize,
        after: Option<NodeId>,
    ) -> ServiceResult<BrowseResult> {
        let mut refs = host.references(&browse, after.as_ref(), size)?;
        let mut continuation_point = ByteString::null();
        if refs.len() > size {
            if self.cursors.len() >= 8 {
                return Err(StatusCode::BadNoContinuationPoints);
            }
            refs.truncate(size);
            let last = refs
                .last()
                .ok_or(StatusCode::BadInternalError)?
                .node_id
                .node_id
                .clone();
            let token = nonce()?.to_vec();
            self.cursors.insert(token.clone(), (size, browse, last));
            continuation_point = token.into();
        }
        Ok(BrowseResult {
            status_code: StatusCode::Good,
            continuation_point,
            references: Some(refs),
        })
    }
}

fn browse_error(status_code: StatusCode) -> BrowseResult {
    BrowseResult {
        status_code,
        continuation_point: ByteString::null(),
        references: None,
    }
}
