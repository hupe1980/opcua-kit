// Generated from OPC Foundation UA-Nodeset ed0b821f6a6f1f0c440c442ed95a9146ae8b7f8d.
// Regenerate with tools/generate-ua.py. See LICENSE-OPC-Foundation.
use super::*;
ua_enum!(ApplicationType {
    Server = 0,
    Client = 1,
    ClientAndServer = 2,
    DiscoveryServer = 3,
});
ua_enum!(BrowseDirection {
    Forward = 0,
    Inverse = 1,
    Both = 2,
    Invalid = 3,
});
ua_enum!(DataChangeTrigger {
    Status = 0,
    StatusValue = 1,
    StatusValueTimestamp = 2,
});
ua_enum!(FilterOperator {
    Equals = 0,
    IsNull = 1,
    GreaterThan = 2,
    LessThan = 3,
    GreaterThanOrEqual = 4,
    LessThanOrEqual = 5,
    Like = 6,
    Not = 7,
    Between = 8,
    InList = 9,
    And = 10,
    Or = 11,
    Cast = 12,
    InView = 13,
    OfType = 14,
    RelatedTo = 15,
    BitwiseAnd = 16,
    BitwiseOr = 17,
});
ua_enum!(MessageSecurityMode {
    Invalid = 0,
    None = 1,
    Sign = 2,
    SignAndEncrypt = 3,
});
ua_enum!(MonitoringMode {
    Disabled = 0,
    Sampling = 1,
    Reporting = 2,
});
ua_enum!(NodeClass {
    Unspecified = 0,
    Object = 1,
    Variable = 2,
    Method = 4,
    ObjectType = 8,
    VariableType = 16,
    ReferenceType = 32,
    DataType = 64,
    View = 128,
});
ua_enum!(SecurityTokenRequestType {
    Issue = 0,
    Renew = 1,
});
ua_enum!(ServerState {
    Running = 0,
    Failed = 1,
    NoConfiguration = 2,
    Suspended = 3,
    Shutdown = 4,
    Test = 5,
    CommunicationFault = 6,
    Unknown = 7,
});
ua_enum!(TimestampsToReturn {
    Source = 0,
    Server = 1,
    Both = 2,
    Neither = 3,
    Invalid = 4,
});
ua_enum!(UserTokenType {
    Anonymous = 0,
    UserName = 1,
    Certificate = 2,
    IssuedToken = 3,
});
ua_struct!(ActivateSessionRequest {
    request_header: RequestHeader,
    client_signature: SignatureData,
    client_software_certificates: Option<Vec<SignedSoftwareCertificate>>,
    locale_ids: Option<Vec<UAString>>,
    user_identity_token: ExtensionObject,
    user_token_signature: SignatureData,
});
ua_struct!(ActivateSessionResponse {
    response_header: ResponseHeader,
    server_nonce: ByteString,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(AnonymousIdentityToken {
    policy_id: UAString,
});
ua_struct!(ApplicationDescription {
    application_uri: UAString,
    product_uri: UAString,
    application_name: LocalizedText,
    application_type: ApplicationType,
    gateway_server_uri: UAString,
    discovery_profile_uri: UAString,
    discovery_urls: Option<Vec<UAString>>,
});
ua_struct!(Argument {
    name: UAString,
    data_type: NodeId,
    value_rank: i32,
    array_dimensions: Option<Vec<u32>>,
    description: LocalizedText,
});
ua_struct!(BrowseDescription {
    node_id: NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: NodeId,
    include_subtypes: bool,
    node_class_mask: u32,
    result_mask: u32,
});
ua_struct!(BrowseNextRequest {
    request_header: RequestHeader,
    release_continuation_points: bool,
    continuation_points: Option<Vec<ByteString>>,
});
ua_struct!(BrowseNextResponse {
    response_header: ResponseHeader,
    results: Option<Vec<BrowseResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(BrowsePath {
    starting_node: NodeId,
    relative_path: RelativePath,
});
ua_struct!(BrowsePathResult {
    status_code: StatusCode,
    targets: Option<Vec<BrowsePathTarget>>,
});
ua_struct!(BrowsePathTarget {
    target_id: ExpandedNodeId,
    remaining_path_index: u32,
});
ua_struct!(BrowseRequest {
    request_header: RequestHeader,
    view: ViewDescription,
    requested_max_references_per_node: u32,
    nodes_to_browse: Option<Vec<BrowseDescription>>,
});
ua_struct!(BrowseResponse {
    response_header: ResponseHeader,
    results: Option<Vec<BrowseResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(BrowseResult {
    status_code: StatusCode,
    continuation_point: ByteString,
    references: Option<Vec<ReferenceDescription>>,
});
ua_struct!(BuildInfo {
    product_uri: UAString,
    manufacturer_name: UAString,
    product_name: UAString,
    software_version: UAString,
    build_number: UAString,
    build_date: DateTime,
});
ua_struct!(CallMethodRequest {
    object_id: NodeId,
    method_id: NodeId,
    input_arguments: Option<Vec<Variant>>,
});
ua_struct!(CallMethodResult {
    status_code: StatusCode,
    input_argument_results: Option<Vec<StatusCode>>,
    input_argument_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
    output_arguments: Option<Vec<Variant>>,
});
ua_struct!(CallRequest {
    request_header: RequestHeader,
    methods_to_call: Option<Vec<CallMethodRequest>>,
});
ua_struct!(CallResponse {
    response_header: ResponseHeader,
    results: Option<Vec<CallMethodResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(ChannelSecurityToken {
    channel_id: u32,
    token_id: u32,
    created_at: DateTime,
    revised_lifetime: u32,
});
ua_struct!(CloseSecureChannelRequest {
    request_header: RequestHeader,
});
ua_struct!(CloseSecureChannelResponse {
    response_header: ResponseHeader,
});
ua_struct!(CloseSessionRequest {
    request_header: RequestHeader,
    delete_subscriptions: bool,
});
ua_struct!(CloseSessionResponse {
    response_header: ResponseHeader,
});
ua_struct!(ContentFilter {
    elements: Option<Vec<ContentFilterElement>>,
});
ua_struct!(ContentFilterElement {
    filter_operator: FilterOperator,
    filter_operands: Option<Vec<ExtensionObject>>,
});
ua_struct!(ContentFilterElementResult {
    status_code: StatusCode,
    operand_status_codes: Option<Vec<StatusCode>>,
    operand_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(ContentFilterResult {
    element_results: Option<Vec<ContentFilterElementResult>>,
    element_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(CreateMonitoredItemsRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_create: Option<Vec<MonitoredItemCreateRequest>>,
});
ua_struct!(CreateMonitoredItemsResponse {
    response_header: ResponseHeader,
    results: Option<Vec<MonitoredItemCreateResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(CreateSessionRequest {
    request_header: RequestHeader,
    client_description: ApplicationDescription,
    server_uri: UAString,
    endpoint_url: UAString,
    session_name: UAString,
    client_nonce: ByteString,
    client_certificate: ByteString,
    requested_session_timeout: f64,
    max_response_message_size: u32,
});
ua_struct!(CreateSessionResponse {
    response_header: ResponseHeader,
    session_id: NodeId,
    authentication_token: NodeId,
    revised_session_timeout: f64,
    server_nonce: ByteString,
    server_certificate: ByteString,
    server_endpoints: Option<Vec<EndpointDescription>>,
    server_software_certificates: Option<Vec<SignedSoftwareCertificate>>,
    server_signature: SignatureData,
    max_request_message_size: u32,
});
ua_struct!(CreateSubscriptionRequest {
    request_header: RequestHeader,
    requested_publishing_interval: f64,
    requested_lifetime_count: u32,
    requested_max_keep_alive_count: u32,
    max_notifications_per_publish: u32,
    publishing_enabled: bool,
    priority: u8,
});
ua_struct!(CreateSubscriptionResponse {
    response_header: ResponseHeader,
    subscription_id: u32,
    revised_publishing_interval: f64,
    revised_lifetime_count: u32,
    revised_max_keep_alive_count: u32,
});
ua_struct!(DataChangeFilter {
    trigger: DataChangeTrigger,
    deadband_type: u32,
    deadband_value: f64,
});
ua_struct!(DataChangeNotification {
    monitored_items: Option<Vec<MonitoredItemNotification>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(DeleteMonitoredItemsRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    monitored_item_ids: Option<Vec<u32>>,
});
ua_struct!(DeleteMonitoredItemsResponse {
    response_header: ResponseHeader,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(DeleteSubscriptionsRequest {
    request_header: RequestHeader,
    subscription_ids: Option<Vec<u32>>,
});
ua_struct!(DeleteSubscriptionsResponse {
    response_header: ResponseHeader,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(EUInformation {
    namespace_uri: UAString,
    unit_id: i32,
    display_name: LocalizedText,
    description: LocalizedText,
});
ua_struct!(EndpointDescription {
    endpoint_url: UAString,
    server: ApplicationDescription,
    server_certificate: ByteString,
    security_mode: MessageSecurityMode,
    security_policy_uri: UAString,
    user_identity_tokens: Option<Vec<UserTokenPolicy>>,
    transport_profile_uri: UAString,
    security_level: u8,
});
ua_struct!(EventFieldList {
    client_handle: u32,
    event_fields: Option<Vec<Variant>>,
});
ua_struct!(EventFilter {
    select_clauses: Option<Vec<SimpleAttributeOperand>>,
    where_clause: ContentFilter,
});
ua_struct!(EventFilterResult {
    select_clause_results: Option<Vec<StatusCode>>,
    select_clause_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
    where_clause_result: ContentFilterResult,
});
ua_struct!(EventNotificationList {
    events: Option<Vec<EventFieldList>>,
});
ua_struct!(FindServersRequest {
    request_header: RequestHeader,
    endpoint_url: UAString,
    locale_ids: Option<Vec<UAString>>,
    server_uris: Option<Vec<UAString>>,
});
ua_struct!(FindServersResponse {
    response_header: ResponseHeader,
    servers: Option<Vec<ApplicationDescription>>,
});
ua_struct!(GetEndpointsRequest {
    request_header: RequestHeader,
    endpoint_url: UAString,
    locale_ids: Option<Vec<UAString>>,
    profile_uris: Option<Vec<UAString>>,
});
ua_struct!(GetEndpointsResponse {
    response_header: ResponseHeader,
    endpoints: Option<Vec<EndpointDescription>>,
});
ua_struct!(HistoryData {
    data_values: Option<Vec<DataValue>>,
});
ua_struct!(HistoryReadRequest {
    request_header: RequestHeader,
    history_read_details: ExtensionObject,
    timestamps_to_return: TimestampsToReturn,
    release_continuation_points: bool,
    nodes_to_read: Option<Vec<HistoryReadValueId>>,
});
ua_struct!(HistoryReadResponse {
    response_header: ResponseHeader,
    results: Option<Vec<HistoryReadResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(HistoryReadResult {
    status_code: StatusCode,
    continuation_point: ByteString,
    history_data: ExtensionObject,
});
ua_struct!(HistoryReadValueId {
    node_id: NodeId,
    index_range: UAString,
    data_encoding: QualifiedName,
    continuation_point: ByteString,
});
ua_struct!(ModifyMonitoredItemsRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_modify: Option<Vec<MonitoredItemModifyRequest>>,
});
ua_struct!(ModifyMonitoredItemsResponse {
    response_header: ResponseHeader,
    results: Option<Vec<MonitoredItemModifyResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(ModifySubscriptionRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    requested_publishing_interval: f64,
    requested_lifetime_count: u32,
    requested_max_keep_alive_count: u32,
    max_notifications_per_publish: u32,
    priority: u8,
});
ua_struct!(ModifySubscriptionResponse {
    response_header: ResponseHeader,
    revised_publishing_interval: f64,
    revised_lifetime_count: u32,
    revised_max_keep_alive_count: u32,
});
ua_struct!(MonitoredItemCreateRequest {
    item_to_monitor: ReadValueId,
    monitoring_mode: MonitoringMode,
    requested_parameters: MonitoringParameters,
});
ua_struct!(MonitoredItemCreateResult {
    status_code: StatusCode,
    monitored_item_id: u32,
    revised_sampling_interval: f64,
    revised_queue_size: u32,
    filter_result: ExtensionObject,
});
ua_struct!(MonitoredItemModifyRequest {
    monitored_item_id: u32,
    requested_parameters: MonitoringParameters,
});
ua_struct!(MonitoredItemModifyResult {
    status_code: StatusCode,
    revised_sampling_interval: f64,
    revised_queue_size: u32,
    filter_result: ExtensionObject,
});
ua_struct!(MonitoredItemNotification {
    client_handle: u32,
    value: DataValue,
});
ua_struct!(MonitoringParameters {
    client_handle: u32,
    sampling_interval: f64,
    filter: ExtensionObject,
    queue_size: u32,
    discard_oldest: bool,
});
ua_struct!(NotificationMessage {
    sequence_number: u32,
    publish_time: DateTime,
    notification_data: Option<Vec<ExtensionObject>>,
});
ua_struct!(OpenSecureChannelRequest {
    request_header: RequestHeader,
    client_protocol_version: u32,
    request_type: SecurityTokenRequestType,
    security_mode: MessageSecurityMode,
    client_nonce: ByteString,
    requested_lifetime: u32,
});
ua_struct!(OpenSecureChannelResponse {
    response_header: ResponseHeader,
    server_protocol_version: u32,
    security_token: ChannelSecurityToken,
    server_nonce: ByteString,
});
ua_struct!(PublishRequest {
    request_header: RequestHeader,
    subscription_acknowledgements: Option<Vec<SubscriptionAcknowledgement>>,
});
ua_struct!(PublishResponse {
    response_header: ResponseHeader,
    subscription_id: u32,
    available_sequence_numbers: Option<Vec<u32>>,
    more_notifications: bool,
    notification_message: NotificationMessage,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(ReadRawModifiedDetails {
    is_read_modified: bool,
    start_time: DateTime,
    end_time: DateTime,
    num_values_per_node: u32,
    return_bounds: bool,
});
ua_struct!(ReadRequest {
    request_header: RequestHeader,
    max_age: f64,
    timestamps_to_return: TimestampsToReturn,
    nodes_to_read: Option<Vec<ReadValueId>>,
});
ua_struct!(ReadResponse {
    response_header: ResponseHeader,
    results: Option<Vec<DataValue>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(ReadValueId {
    node_id: NodeId,
    attribute_id: u32,
    index_range: UAString,
    data_encoding: QualifiedName,
});
ua_struct!(ReferenceDescription {
    reference_type_id: NodeId,
    is_forward: bool,
    node_id: ExpandedNodeId,
    browse_name: QualifiedName,
    display_name: LocalizedText,
    node_class: NodeClass,
    type_definition: ExpandedNodeId,
});
ua_struct!(RelativePath {
    elements: Option<Vec<RelativePathElement>>,
});
ua_struct!(RelativePathElement {
    reference_type_id: NodeId,
    is_inverse: bool,
    include_subtypes: bool,
    target_name: QualifiedName,
});
ua_struct!(RepublishRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    retransmit_sequence_number: u32,
});
ua_struct!(RepublishResponse {
    response_header: ResponseHeader,
    notification_message: NotificationMessage,
});
ua_struct!(RequestHeader {
    authentication_token: NodeId,
    timestamp: DateTime,
    request_handle: u32,
    return_diagnostics: u32,
    audit_entry_id: UAString,
    timeout_hint: u32,
    additional_header: ExtensionObject,
});
ua_struct!(ResponseHeader {
    timestamp: DateTime,
    request_handle: u32,
    service_result: StatusCode,
    service_diagnostics: DiagnosticInfo,
    string_table: Option<Vec<UAString>>,
    additional_header: ExtensionObject,
});
ua_struct!(ServerStatusDataType {
    start_time: DateTime,
    current_time: DateTime,
    state: ServerState,
    build_info: BuildInfo,
    seconds_till_shutdown: u32,
    shutdown_reason: LocalizedText,
});
ua_struct!(ServiceFault {
    response_header: ResponseHeader,
});
ua_struct!(SetMonitoringModeRequest {
    request_header: RequestHeader,
    subscription_id: u32,
    monitoring_mode: MonitoringMode,
    monitored_item_ids: Option<Vec<u32>>,
});
ua_struct!(SetMonitoringModeResponse {
    response_header: ResponseHeader,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(SetPublishingModeRequest {
    request_header: RequestHeader,
    publishing_enabled: bool,
    subscription_ids: Option<Vec<u32>>,
});
ua_struct!(SetPublishingModeResponse {
    response_header: ResponseHeader,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(SignatureData {
    algorithm: UAString,
    signature: ByteString,
});
ua_struct!(SignedSoftwareCertificate {
    certificate_data: ByteString,
    signature: ByteString,
});
ua_struct!(SimpleAttributeOperand {
    type_definition_id: NodeId,
    browse_path: Option<Vec<QualifiedName>>,
    attribute_id: u32,
    index_range: UAString,
});
ua_struct!(StatusChangeNotification {
    status: StatusCode,
    diagnostic_info: DiagnosticInfo,
});
ua_struct!(SubscriptionAcknowledgement {
    subscription_id: u32,
    sequence_number: u32,
});
ua_struct!(TranslateBrowsePathsToNodeIdsRequest {
    request_header: RequestHeader,
    browse_paths: Option<Vec<BrowsePath>>,
});
ua_struct!(TranslateBrowsePathsToNodeIdsResponse {
    response_header: ResponseHeader,
    results: Option<Vec<BrowsePathResult>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(UserNameIdentityToken {
    policy_id: UAString,
    user_name: UAString,
    password: ByteString,
    encryption_algorithm: UAString,
});
ua_struct!(UserTokenPolicy {
    policy_id: UAString,
    token_type: UserTokenType,
    issued_token_type: UAString,
    issuer_endpoint_url: UAString,
    security_policy_uri: UAString,
});
ua_struct!(ViewDescription {
    view_id: NodeId,
    timestamp: DateTime,
    view_version: u32,
});
ua_struct!(WriteRequest {
    request_header: RequestHeader,
    nodes_to_write: Option<Vec<WriteValue>>,
});
ua_struct!(WriteResponse {
    response_header: ResponseHeader,
    results: Option<Vec<StatusCode>>,
    diagnostic_infos: Option<Vec<DiagnosticInfo>>,
});
ua_struct!(WriteValue {
    node_id: NodeId,
    attribute_id: u32,
    index_range: UAString,
    value: DataValue,
});
object_ids! {
    ActivateSessionRequest_Encoding_DefaultBinary = 467,
    ActivateSessionResponse_Encoding_DefaultBinary = 470,
    AddNodesRequest_Encoding_DefaultBinary = 488,
    AddReferencesRequest_Encoding_DefaultBinary = 494,
    AnonymousIdentityToken_Encoding_DefaultBinary = 321,
    ApplicationDescription_Encoding_DefaultBinary = 310,
    Argument_Encoding_DefaultBinary = 298,
    BrowseDescription_Encoding_DefaultBinary = 516,
    BrowseNextRequest_Encoding_DefaultBinary = 533,
    BrowseNextResponse_Encoding_DefaultBinary = 536,
    BrowsePath_Encoding_DefaultBinary = 545,
    BrowsePathResult_Encoding_DefaultBinary = 551,
    BrowsePathTarget_Encoding_DefaultBinary = 548,
    BrowseRequest_Encoding_DefaultBinary = 527,
    BrowseResponse_Encoding_DefaultBinary = 530,
    BrowseResult_Encoding_DefaultBinary = 524,
    BuildInfo_Encoding_DefaultBinary = 340,
    CallMethodRequest_Encoding_DefaultBinary = 706,
    CallMethodResult_Encoding_DefaultBinary = 709,
    CallRequest_Encoding_DefaultBinary = 712,
    CallResponse_Encoding_DefaultBinary = 715,
    ChannelSecurityToken_Encoding_DefaultBinary = 443,
    CloseSecureChannelRequest_Encoding_DefaultBinary = 452,
    CloseSecureChannelResponse_Encoding_DefaultBinary = 455,
    CloseSessionRequest_Encoding_DefaultBinary = 473,
    CloseSessionResponse_Encoding_DefaultBinary = 476,
    ContentFilter_Encoding_DefaultBinary = 588,
    ContentFilterElement_Encoding_DefaultBinary = 585,
    ContentFilterElementResult_Encoding_DefaultBinary = 606,
    ContentFilterResult_Encoding_DefaultBinary = 609,
    CreateMonitoredItemsRequest_Encoding_DefaultBinary = 751,
    CreateMonitoredItemsResponse_Encoding_DefaultBinary = 754,
    CreateSessionRequest_Encoding_DefaultBinary = 461,
    CreateSessionResponse_Encoding_DefaultBinary = 464,
    CreateSubscriptionRequest_Encoding_DefaultBinary = 787,
    CreateSubscriptionResponse_Encoding_DefaultBinary = 790,
    DataChangeFilter_Encoding_DefaultBinary = 724,
    DataChangeNotification_Encoding_DefaultBinary = 811,
    DeleteMonitoredItemsRequest_Encoding_DefaultBinary = 781,
    DeleteMonitoredItemsResponse_Encoding_DefaultBinary = 784,
    DeleteNodesRequest_Encoding_DefaultBinary = 500,
    DeleteReferencesRequest_Encoding_DefaultBinary = 506,
    DeleteSubscriptionsRequest_Encoding_DefaultBinary = 847,
    DeleteSubscriptionsResponse_Encoding_DefaultBinary = 850,
    EUInformation_Encoding_DefaultBinary = 889,
    EndpointDescription_Encoding_DefaultBinary = 314,
    EventFieldList_Encoding_DefaultBinary = 919,
    EventFilter_Encoding_DefaultBinary = 727,
    EventFilterResult_Encoding_DefaultBinary = 736,
    EventNotificationList_Encoding_DefaultBinary = 916,
    FindServersRequest_Encoding_DefaultBinary = 422,
    FindServersResponse_Encoding_DefaultBinary = 425,
    GetEndpointsRequest_Encoding_DefaultBinary = 428,
    GetEndpointsResponse_Encoding_DefaultBinary = 431,
    HistoryData_Encoding_DefaultBinary = 658,
    HistoryReadRequest_Encoding_DefaultBinary = 664,
    HistoryReadResponse_Encoding_DefaultBinary = 667,
    HistoryReadResult_Encoding_DefaultBinary = 640,
    HistoryReadValueId_Encoding_DefaultBinary = 637,
    HistoryUpdateRequest_Encoding_DefaultBinary = 700,
    ModifyMonitoredItemsRequest_Encoding_DefaultBinary = 763,
    ModifyMonitoredItemsResponse_Encoding_DefaultBinary = 766,
    ModifySubscriptionRequest_Encoding_DefaultBinary = 793,
    ModifySubscriptionResponse_Encoding_DefaultBinary = 796,
    MonitoredItemCreateRequest_Encoding_DefaultBinary = 745,
    MonitoredItemCreateResult_Encoding_DefaultBinary = 748,
    MonitoredItemModifyRequest_Encoding_DefaultBinary = 757,
    MonitoredItemModifyResult_Encoding_DefaultBinary = 760,
    MonitoredItemNotification_Encoding_DefaultBinary = 808,
    MonitoringParameters_Encoding_DefaultBinary = 742,
    NotificationMessage_Encoding_DefaultBinary = 805,
    OpenSecureChannelRequest_Encoding_DefaultBinary = 446,
    OpenSecureChannelResponse_Encoding_DefaultBinary = 449,
    PublishRequest_Encoding_DefaultBinary = 826,
    PublishResponse_Encoding_DefaultBinary = 829,
    ReadRawModifiedDetails_Encoding_DefaultBinary = 649,
    ReadRequest_Encoding_DefaultBinary = 631,
    ReadResponse_Encoding_DefaultBinary = 634,
    ReadValueId_Encoding_DefaultBinary = 628,
    ReferenceDescription_Encoding_DefaultBinary = 520,
    RelativePath_Encoding_DefaultBinary = 542,
    RelativePathElement_Encoding_DefaultBinary = 539,
    RepublishRequest_Encoding_DefaultBinary = 832,
    RepublishResponse_Encoding_DefaultBinary = 835,
    RequestHeader_Encoding_DefaultBinary = 391,
    ResponseHeader_Encoding_DefaultBinary = 394,
    ServerStatusDataType_Encoding_DefaultBinary = 864,
    ServiceFault_Encoding_DefaultBinary = 397,
    SetMonitoringModeRequest_Encoding_DefaultBinary = 769,
    SetMonitoringModeResponse_Encoding_DefaultBinary = 772,
    SetPublishingModeRequest_Encoding_DefaultBinary = 799,
    SetPublishingModeResponse_Encoding_DefaultBinary = 802,
    SignatureData_Encoding_DefaultBinary = 458,
    SignedSoftwareCertificate_Encoding_DefaultBinary = 346,
    SimpleAttributeOperand_Encoding_DefaultBinary = 603,
    StatusChangeNotification_Encoding_DefaultBinary = 820,
    SubscriptionAcknowledgement_Encoding_DefaultBinary = 823,
    TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary = 554,
    TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultBinary = 557,
    UserNameIdentityToken_Encoding_DefaultBinary = 324,
    UserTokenPolicy_Encoding_DefaultBinary = 306,
    ViewDescription_Encoding_DefaultBinary = 513,
    WriteRequest_Encoding_DefaultBinary = 673,
    WriteResponse_Encoding_DefaultBinary = 676,
    WriteValue_Encoding_DefaultBinary = 670,
}
message!(
    ActivateSessionRequest,
    ActivateSessionRequest_Encoding_DefaultBinary
);
message!(
    ActivateSessionResponse,
    ActivateSessionResponse_Encoding_DefaultBinary
);
message!(
    AnonymousIdentityToken,
    AnonymousIdentityToken_Encoding_DefaultBinary
);
message!(
    ApplicationDescription,
    ApplicationDescription_Encoding_DefaultBinary
);
message!(Argument, Argument_Encoding_DefaultBinary);
message!(BrowseDescription, BrowseDescription_Encoding_DefaultBinary);
message!(BrowseNextRequest, BrowseNextRequest_Encoding_DefaultBinary);
message!(
    BrowseNextResponse,
    BrowseNextResponse_Encoding_DefaultBinary
);
message!(BrowsePath, BrowsePath_Encoding_DefaultBinary);
message!(BrowsePathResult, BrowsePathResult_Encoding_DefaultBinary);
message!(BrowsePathTarget, BrowsePathTarget_Encoding_DefaultBinary);
message!(BrowseRequest, BrowseRequest_Encoding_DefaultBinary);
message!(BrowseResponse, BrowseResponse_Encoding_DefaultBinary);
message!(BrowseResult, BrowseResult_Encoding_DefaultBinary);
message!(BuildInfo, BuildInfo_Encoding_DefaultBinary);
message!(CallMethodRequest, CallMethodRequest_Encoding_DefaultBinary);
message!(CallMethodResult, CallMethodResult_Encoding_DefaultBinary);
message!(CallRequest, CallRequest_Encoding_DefaultBinary);
message!(CallResponse, CallResponse_Encoding_DefaultBinary);
message!(
    ChannelSecurityToken,
    ChannelSecurityToken_Encoding_DefaultBinary
);
message!(
    CloseSecureChannelRequest,
    CloseSecureChannelRequest_Encoding_DefaultBinary
);
message!(
    CloseSecureChannelResponse,
    CloseSecureChannelResponse_Encoding_DefaultBinary
);
message!(
    CloseSessionRequest,
    CloseSessionRequest_Encoding_DefaultBinary
);
message!(
    CloseSessionResponse,
    CloseSessionResponse_Encoding_DefaultBinary
);
message!(ContentFilter, ContentFilter_Encoding_DefaultBinary);
message!(
    ContentFilterElement,
    ContentFilterElement_Encoding_DefaultBinary
);
message!(
    ContentFilterElementResult,
    ContentFilterElementResult_Encoding_DefaultBinary
);
message!(
    ContentFilterResult,
    ContentFilterResult_Encoding_DefaultBinary
);
message!(
    CreateMonitoredItemsRequest,
    CreateMonitoredItemsRequest_Encoding_DefaultBinary
);
message!(
    CreateMonitoredItemsResponse,
    CreateMonitoredItemsResponse_Encoding_DefaultBinary
);
message!(
    CreateSessionRequest,
    CreateSessionRequest_Encoding_DefaultBinary
);
message!(
    CreateSessionResponse,
    CreateSessionResponse_Encoding_DefaultBinary
);
message!(
    CreateSubscriptionRequest,
    CreateSubscriptionRequest_Encoding_DefaultBinary
);
message!(
    CreateSubscriptionResponse,
    CreateSubscriptionResponse_Encoding_DefaultBinary
);
message!(DataChangeFilter, DataChangeFilter_Encoding_DefaultBinary);
message!(
    DataChangeNotification,
    DataChangeNotification_Encoding_DefaultBinary
);
message!(
    DeleteMonitoredItemsRequest,
    DeleteMonitoredItemsRequest_Encoding_DefaultBinary
);
message!(
    DeleteMonitoredItemsResponse,
    DeleteMonitoredItemsResponse_Encoding_DefaultBinary
);
message!(
    DeleteSubscriptionsRequest,
    DeleteSubscriptionsRequest_Encoding_DefaultBinary
);
message!(
    DeleteSubscriptionsResponse,
    DeleteSubscriptionsResponse_Encoding_DefaultBinary
);
message!(EUInformation, EUInformation_Encoding_DefaultBinary);
message!(
    EndpointDescription,
    EndpointDescription_Encoding_DefaultBinary
);
message!(EventFieldList, EventFieldList_Encoding_DefaultBinary);
message!(EventFilter, EventFilter_Encoding_DefaultBinary);
message!(EventFilterResult, EventFilterResult_Encoding_DefaultBinary);
message!(
    EventNotificationList,
    EventNotificationList_Encoding_DefaultBinary
);
message!(
    FindServersRequest,
    FindServersRequest_Encoding_DefaultBinary
);
message!(
    FindServersResponse,
    FindServersResponse_Encoding_DefaultBinary
);
message!(
    GetEndpointsRequest,
    GetEndpointsRequest_Encoding_DefaultBinary
);
message!(
    GetEndpointsResponse,
    GetEndpointsResponse_Encoding_DefaultBinary
);
message!(HistoryData, HistoryData_Encoding_DefaultBinary);
message!(
    HistoryReadRequest,
    HistoryReadRequest_Encoding_DefaultBinary
);
message!(
    HistoryReadResponse,
    HistoryReadResponse_Encoding_DefaultBinary
);
message!(HistoryReadResult, HistoryReadResult_Encoding_DefaultBinary);
message!(
    HistoryReadValueId,
    HistoryReadValueId_Encoding_DefaultBinary
);
message!(
    ModifyMonitoredItemsRequest,
    ModifyMonitoredItemsRequest_Encoding_DefaultBinary
);
message!(
    ModifyMonitoredItemsResponse,
    ModifyMonitoredItemsResponse_Encoding_DefaultBinary
);
message!(
    ModifySubscriptionRequest,
    ModifySubscriptionRequest_Encoding_DefaultBinary
);
message!(
    ModifySubscriptionResponse,
    ModifySubscriptionResponse_Encoding_DefaultBinary
);
message!(
    MonitoredItemCreateRequest,
    MonitoredItemCreateRequest_Encoding_DefaultBinary
);
message!(
    MonitoredItemCreateResult,
    MonitoredItemCreateResult_Encoding_DefaultBinary
);
message!(
    MonitoredItemModifyRequest,
    MonitoredItemModifyRequest_Encoding_DefaultBinary
);
message!(
    MonitoredItemModifyResult,
    MonitoredItemModifyResult_Encoding_DefaultBinary
);
message!(
    MonitoredItemNotification,
    MonitoredItemNotification_Encoding_DefaultBinary
);
message!(
    MonitoringParameters,
    MonitoringParameters_Encoding_DefaultBinary
);
message!(
    NotificationMessage,
    NotificationMessage_Encoding_DefaultBinary
);
message!(
    OpenSecureChannelRequest,
    OpenSecureChannelRequest_Encoding_DefaultBinary
);
message!(
    OpenSecureChannelResponse,
    OpenSecureChannelResponse_Encoding_DefaultBinary
);
message!(PublishRequest, PublishRequest_Encoding_DefaultBinary);
message!(PublishResponse, PublishResponse_Encoding_DefaultBinary);
message!(
    ReadRawModifiedDetails,
    ReadRawModifiedDetails_Encoding_DefaultBinary
);
message!(ReadRequest, ReadRequest_Encoding_DefaultBinary);
message!(ReadResponse, ReadResponse_Encoding_DefaultBinary);
message!(ReadValueId, ReadValueId_Encoding_DefaultBinary);
message!(
    ReferenceDescription,
    ReferenceDescription_Encoding_DefaultBinary
);
message!(RelativePath, RelativePath_Encoding_DefaultBinary);
message!(
    RelativePathElement,
    RelativePathElement_Encoding_DefaultBinary
);
message!(RepublishRequest, RepublishRequest_Encoding_DefaultBinary);
message!(RepublishResponse, RepublishResponse_Encoding_DefaultBinary);
message!(RequestHeader, RequestHeader_Encoding_DefaultBinary);
message!(ResponseHeader, ResponseHeader_Encoding_DefaultBinary);
message!(
    ServerStatusDataType,
    ServerStatusDataType_Encoding_DefaultBinary
);
message!(ServiceFault, ServiceFault_Encoding_DefaultBinary);
message!(
    SetMonitoringModeRequest,
    SetMonitoringModeRequest_Encoding_DefaultBinary
);
message!(
    SetMonitoringModeResponse,
    SetMonitoringModeResponse_Encoding_DefaultBinary
);
message!(
    SetPublishingModeRequest,
    SetPublishingModeRequest_Encoding_DefaultBinary
);
message!(
    SetPublishingModeResponse,
    SetPublishingModeResponse_Encoding_DefaultBinary
);
message!(SignatureData, SignatureData_Encoding_DefaultBinary);
message!(
    SignedSoftwareCertificate,
    SignedSoftwareCertificate_Encoding_DefaultBinary
);
message!(
    SimpleAttributeOperand,
    SimpleAttributeOperand_Encoding_DefaultBinary
);
message!(
    StatusChangeNotification,
    StatusChangeNotification_Encoding_DefaultBinary
);
message!(
    SubscriptionAcknowledgement,
    SubscriptionAcknowledgement_Encoding_DefaultBinary
);
message!(
    TranslateBrowsePathsToNodeIdsRequest,
    TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary
);
message!(
    TranslateBrowsePathsToNodeIdsResponse,
    TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultBinary
);
message!(
    UserNameIdentityToken,
    UserNameIdentityToken_Encoding_DefaultBinary
);
message!(UserTokenPolicy, UserTokenPolicy_Encoding_DefaultBinary);
message!(ViewDescription, ViewDescription_Encoding_DefaultBinary);
message!(WriteRequest, WriteRequest_Encoding_DefaultBinary);
message!(WriteResponse, WriteResponse_Encoding_DefaultBinary);
message!(WriteValue, WriteValue_Encoding_DefaultBinary);
pub(super) fn decode_extension(
    id: u32,
    mut bytes: &[u8],
    ctx: &Context<'_>,
) -> Result<Option<ExtensionObject>, StatusCode> {
    let object = match id {
        321 => ExtensionObject::decode_known::<AnonymousIdentityToken>(&mut bytes, ctx)?,
        298 => ExtensionObject::decode_known::<Argument>(&mut bytes, ctx)?,
        340 => ExtensionObject::decode_known::<BuildInfo>(&mut bytes, ctx)?,
        724 => ExtensionObject::decode_known::<DataChangeFilter>(&mut bytes, ctx)?,
        811 => ExtensionObject::decode_known::<DataChangeNotification>(&mut bytes, ctx)?,
        889 => ExtensionObject::decode_known::<EUInformation>(&mut bytes, ctx)?,
        727 => ExtensionObject::decode_known::<EventFilter>(&mut bytes, ctx)?,
        736 => ExtensionObject::decode_known::<EventFilterResult>(&mut bytes, ctx)?,
        916 => ExtensionObject::decode_known::<EventNotificationList>(&mut bytes, ctx)?,
        658 => ExtensionObject::decode_known::<HistoryData>(&mut bytes, ctx)?,
        649 => ExtensionObject::decode_known::<ReadRawModifiedDetails>(&mut bytes, ctx)?,
        864 => ExtensionObject::decode_known::<ServerStatusDataType>(&mut bytes, ctx)?,
        820 => ExtensionObject::decode_known::<StatusChangeNotification>(&mut bytes, ctx)?,
        324 => ExtensionObject::decode_known::<UserNameIdentityToken>(&mut bytes, ctx)?,
        _ => return Ok(None),
    };
    if !bytes.is_empty() {
        return Err(StatusCode::BadDecodingError);
    }
    Ok(Some(object))
}
#[allow(non_upper_case_globals)]
impl StatusCode {
    /// The operation succeeded.
    pub const Good: Self = Self(0x00000000);
    /// The operation was uncertain.
    pub const Uncertain: Self = Self(0x40000000);
    /// The operation failed.
    pub const Bad: Self = Self(0x80000000);
    /// An unexpected error occurred.
    pub const BadUnexpectedError: Self = Self(0x80010000);
    /// An internal error occurred as a result of a programming or configuration error.
    pub const BadInternalError: Self = Self(0x80020000);
    /// Not enough memory to complete the operation.
    pub const BadOutOfMemory: Self = Self(0x80030000);
    /// An operating system resource is not available.
    pub const BadResourceUnavailable: Self = Self(0x80040000);
    /// A low level communication error occurred.
    pub const BadCommunicationError: Self = Self(0x80050000);
    /// Encoding halted because of invalid data in the objects being serialized.
    pub const BadEncodingError: Self = Self(0x80060000);
    /// Decoding halted because of invalid data in the stream.
    pub const BadDecodingError: Self = Self(0x80070000);
    /// The message encoding/decoding limits imposed by the stack have been exceeded.
    pub const BadEncodingLimitsExceeded: Self = Self(0x80080000);
    /// The request message size exceeds limits set by the server.
    pub const BadRequestTooLarge: Self = Self(0x80B80000);
    /// The response message size exceeds limits set by the client or server.
    pub const BadResponseTooLarge: Self = Self(0x80B90000);
    /// An unrecognized response was received from the server.
    pub const BadUnknownResponse: Self = Self(0x80090000);
    /// The operation timed out.
    pub const BadTimeout: Self = Self(0x800A0000);
    /// The server does not support the requested service.
    pub const BadServiceUnsupported: Self = Self(0x800B0000);
    /// The operation was cancelled because the application is shutting down.
    pub const BadShutdown: Self = Self(0x800C0000);
    /// The operation could not complete because the client is not connected to the server.
    pub const BadServerNotConnected: Self = Self(0x800D0000);
    /// The server has stopped and cannot process any requests.
    pub const BadServerHalted: Self = Self(0x800E0000);
    /// No processing could be done because there was nothing to do.
    pub const BadNothingToDo: Self = Self(0x800F0000);
    /// The request could not be processed because it specified too many operations.
    pub const BadTooManyOperations: Self = Self(0x80100000);
    /// The request could not be processed because there are too many monitored items in the subscription.
    pub const BadTooManyMonitoredItems: Self = Self(0x80DB0000);
    /// The extension object cannot be (de)serialized because the data type id is not recognized.
    pub const BadDataTypeIdUnknown: Self = Self(0x80110000);
    /// The certificate provided as a parameter is not valid.
    pub const BadCertificateInvalid: Self = Self(0x80120000);
    /// An error occurred verifying security.
    pub const BadSecurityChecksFailed: Self = Self(0x80130000);
    /// The certificate does not meet the requirements of the security policy.
    pub const BadCertificatePolicyCheckFailed: Self = Self(0x81140000);
    /// The certificate has expired or is not yet valid.
    pub const BadCertificateTimeInvalid: Self = Self(0x80140000);
    /// An issuer certificate has expired or is not yet valid.
    pub const BadCertificateIssuerTimeInvalid: Self = Self(0x80150000);
    /// The HostName used to connect to a server does not match a HostName in the certificate.
    pub const BadCertificateHostNameInvalid: Self = Self(0x80160000);
    /// The URI specified in the ApplicationDescription does not match the URI in the certificate.
    pub const BadCertificateUriInvalid: Self = Self(0x80170000);
    /// The certificate may not be used for the requested operation.
    pub const BadCertificateUseNotAllowed: Self = Self(0x80180000);
    /// The issuer certificate may not be used for the requested operation.
    pub const BadCertificateIssuerUseNotAllowed: Self = Self(0x80190000);
    /// The certificate is not trusted.
    pub const BadCertificateUntrusted: Self = Self(0x801A0000);
    /// It was not possible to determine if the certificate has been revoked.
    pub const BadCertificateRevocationUnknown: Self = Self(0x801B0000);
    /// It was not possible to determine if the issuer certificate has been revoked.
    pub const BadCertificateIssuerRevocationUnknown: Self = Self(0x801C0000);
    /// The certificate has been revoked.
    pub const BadCertificateRevoked: Self = Self(0x801D0000);
    /// The issuer certificate has been revoked.
    pub const BadCertificateIssuerRevoked: Self = Self(0x801E0000);
    /// The certificate chain is incomplete.
    pub const BadCertificateChainIncomplete: Self = Self(0x810D0000);
    /// User does not have permission to perform the requested operation.
    pub const BadUserAccessDenied: Self = Self(0x801F0000);
    /// The user identity token is not valid.
    pub const BadIdentityTokenInvalid: Self = Self(0x80200000);
    /// The user identity token is valid but the server has rejected it.
    pub const BadIdentityTokenRejected: Self = Self(0x80210000);
    /// The specified secure channel is no longer valid.
    pub const BadSecureChannelIdInvalid: Self = Self(0x80220000);
    /// The timestamp is outside the range allowed by the server.
    pub const BadInvalidTimestamp: Self = Self(0x80230000);
    /// The nonce does appear to be not a random value or it is not the correct length.
    pub const BadNonceInvalid: Self = Self(0x80240000);
    /// The session id is not valid.
    pub const BadSessionIdInvalid: Self = Self(0x80250000);
    /// The session was closed by the client.
    pub const BadSessionClosed: Self = Self(0x80260000);
    /// The session cannot be used because ActivateSession has not been called.
    pub const BadSessionNotActivated: Self = Self(0x80270000);
    /// The subscription id is not valid.
    pub const BadSubscriptionIdInvalid: Self = Self(0x80280000);
    /// The header for the request is missing or invalid.
    pub const BadRequestHeaderInvalid: Self = Self(0x802A0000);
    /// The timestamps to return parameter is invalid.
    pub const BadTimestampsToReturnInvalid: Self = Self(0x802B0000);
    /// The request was cancelled by the client.
    pub const BadRequestCancelledByClient: Self = Self(0x802C0000);
    /// Too many arguments were provided.
    pub const BadTooManyArguments: Self = Self(0x80E50000);
    /// The server requires a license to operate in general or to perform a service or operation, but existing license is expired.
    pub const BadLicenseExpired: Self = Self(0x810E0000);
    /// The server has limits on number of allowed operations / objects, based on installed licenses, and these limits where exceeded.
    pub const BadLicenseLimitsExceeded: Self = Self(0x810F0000);
    /// The server does not have a license which is required to operate in general or to perform a service or operation.
    pub const BadLicenseNotAvailable: Self = Self(0x81100000);
    /// The Server does not have the resources to process the request at this time.
    pub const BadServerTooBusy: Self = Self(0x80EE0000);
    /// The log-on for the user succeeded but the user is required to change the password.
    pub const GoodPasswordChangeRequired: Self = Self(0x00EF0000);
    /// The subscription was transferred to another session.
    pub const GoodSubscriptionTransferred: Self = Self(0x002D0000);
    /// The processing will complete asynchronously.
    pub const GoodCompletesAsynchronously: Self = Self(0x002E0000);
    /// Sampling has slowed down due to resource limitations.
    pub const GoodOverload: Self = Self(0x002F0000);
    /// The value written was accepted but was clamped.
    pub const GoodClamped: Self = Self(0x00300000);
    /// Communication with the data source is defined, but not established, and there is no last known value available.
    pub const BadNoCommunication: Self = Self(0x80310000);
    /// Waiting for the server to obtain values from the underlying data source.
    pub const BadWaitingForInitialData: Self = Self(0x80320000);
    /// The syntax the node id is not valid or refers to a node that is not valid for the operation.
    pub const BadNodeIdInvalid: Self = Self(0x80330000);
    /// The node id refers to a node that does not exist in the server address space.
    pub const BadNodeIdUnknown: Self = Self(0x80340000);
    /// The attribute is not supported for the specified Node.
    pub const BadAttributeIdInvalid: Self = Self(0x80350000);
    /// The syntax of the index range parameter is invalid.
    pub const BadIndexRangeInvalid: Self = Self(0x80360000);
    /// No data exists within the range of indexes specified.
    pub const BadIndexRangeNoData: Self = Self(0x80370000);
    /// The written data does not match the IndexRange specified.
    pub const BadIndexRangeDataMismatch: Self = Self(0x80EA0000);
    /// The data encoding is invalid.
    pub const BadDataEncodingInvalid: Self = Self(0x80380000);
    /// The server does not support the requested data encoding for the node.
    pub const BadDataEncodingUnsupported: Self = Self(0x80390000);
    /// The access level does not allow reading or subscribing to the Node.
    pub const BadNotReadable: Self = Self(0x803A0000);
    /// The access level does not allow writing to the Node.
    pub const BadNotWritable: Self = Self(0x803B0000);
    /// The value was out of range.
    pub const BadOutOfRange: Self = Self(0x803C0000);
    /// The value is over the allowed range.
    pub const UncertainOverRange: Self = Self(0x40F20000);
    /// The value is under the allowed range.
    pub const UncertainUnderRange: Self = Self(0x40F30000);
    /// The requested operation is not supported.
    pub const BadNotSupported: Self = Self(0x803D0000);
    /// A requested item was not found or a search operation ended without success.
    pub const BadNotFound: Self = Self(0x803E0000);
    /// The object cannot be used because it has been deleted.
    pub const BadObjectDeleted: Self = Self(0x803F0000);
    /// Requested operation is not implemented.
    pub const BadNotImplemented: Self = Self(0x80400000);
    /// The monitoring mode is invalid.
    pub const BadMonitoringModeInvalid: Self = Self(0x80410000);
    /// The monitoring item id does not refer to a valid monitored item.
    pub const BadMonitoredItemIdInvalid: Self = Self(0x80420000);
    /// The monitored item filter parameter is not valid.
    pub const BadMonitoredItemFilterInvalid: Self = Self(0x80430000);
    /// The server does not support the requested monitored item filter.
    pub const BadMonitoredItemFilterUnsupported: Self = Self(0x80440000);
    /// A monitoring filter cannot be used in combination with the attribute specified.
    pub const BadFilterNotAllowed: Self = Self(0x80450000);
    /// A mandatory structured parameter was missing or null.
    pub const BadStructureMissing: Self = Self(0x80460000);
    /// The event filter is not valid.
    pub const BadEventFilterInvalid: Self = Self(0x80470000);
    /// The content filter is not valid.
    pub const BadContentFilterInvalid: Self = Self(0x80480000);
    /// An unrecognized operator was provided in a filter.
    pub const BadFilterOperatorInvalid: Self = Self(0x80C10000);
    /// A valid operator was provided, but the server does not provide support for this filter operator.
    pub const BadFilterOperatorUnsupported: Self = Self(0x80C20000);
    /// The number of operands provided for the filter operator was less then expected for the operand provided.
    pub const BadFilterOperandCountMismatch: Self = Self(0x80C30000);
    /// The operand used in a content filter is not valid.
    pub const BadFilterOperandInvalid: Self = Self(0x80490000);
    /// The referenced element is not a valid element in the content filter.
    pub const BadFilterElementInvalid: Self = Self(0x80C40000);
    /// The referenced literal is not a valid value.
    pub const BadFilterLiteralInvalid: Self = Self(0x80C50000);
    /// The continuation point provide is longer valid.
    pub const BadContinuationPointInvalid: Self = Self(0x804A0000);
    /// The operation could not be processed because all continuation points have been allocated.
    pub const BadNoContinuationPoints: Self = Self(0x804B0000);
    /// The reference type id does not refer to a valid reference type node.
    pub const BadReferenceTypeIdInvalid: Self = Self(0x804C0000);
    /// The browse direction is not valid.
    pub const BadBrowseDirectionInvalid: Self = Self(0x804D0000);
    /// The node is not part of the view.
    pub const BadNodeNotInView: Self = Self(0x804E0000);
    /// The number was not accepted because of a numeric overflow.
    pub const BadNumericOverflow: Self = Self(0x81120000);
    /// The locale in the requested write operation is not supported.
    pub const BadLocaleNotSupported: Self = Self(0x80ED0000);
    /// The variable has no default value and no initial value.
    pub const BadNoValue: Self = Self(0x80F00000);
    /// The ServerUri is not a valid URI.
    pub const BadServerUriInvalid: Self = Self(0x804F0000);
    /// No ServerName was specified.
    pub const BadServerNameMissing: Self = Self(0x80500000);
    /// No DiscoveryUrl was specified.
    pub const BadDiscoveryUrlMissing: Self = Self(0x80510000);
    /// The semaphore file specified by the client is not valid.
    pub const BadSemaphoreFileMissing: Self = Self(0x80520000);
    /// The security token request type is not valid.
    pub const BadRequestTypeInvalid: Self = Self(0x80530000);
    /// The security mode does not meet the requirements set by the server.
    pub const BadSecurityModeRejected: Self = Self(0x80540000);
    /// The security policy does not meet the requirements set by the server.
    pub const BadSecurityPolicyRejected: Self = Self(0x80550000);
    /// The server has reached its maximum number of sessions.
    pub const BadTooManySessions: Self = Self(0x80560000);
    /// The user token signature is missing or invalid.
    pub const BadUserSignatureInvalid: Self = Self(0x80570000);
    /// The signature generated with the client certificate is missing or invalid.
    pub const BadApplicationSignatureInvalid: Self = Self(0x80580000);
    /// The client did not provide at least one software certificate that is valid and meets the profile requirements for the server.
    pub const BadNoValidCertificates: Self = Self(0x80590000);
    /// The server does not support changing the user identity assigned to the session.
    pub const BadIdentityChangeNotSupported: Self = Self(0x80C60000);
    /// The request was cancelled by the client with the Cancel service.
    pub const BadRequestCancelledByRequest: Self = Self(0x805A0000);
    /// The parent node id does not to refer to a valid node.
    pub const BadParentNodeIdInvalid: Self = Self(0x805B0000);
    /// The reference could not be created because it violates constraints imposed by the data model.
    pub const BadReferenceNotAllowed: Self = Self(0x805C0000);
    /// The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client.
    pub const BadNodeIdRejected: Self = Self(0x805D0000);
    /// The requested node id is already used by another node.
    pub const BadNodeIdExists: Self = Self(0x805E0000);
    /// The node class is not valid.
    pub const BadNodeClassInvalid: Self = Self(0x805F0000);
    /// The browse name is invalid.
    pub const BadBrowseNameInvalid: Self = Self(0x80600000);
    /// The browse name is not unique among nodes that share the same relationship with the parent.
    pub const BadBrowseNameDuplicated: Self = Self(0x80610000);
    /// The node attributes are not valid for the node class.
    pub const BadNodeAttributesInvalid: Self = Self(0x80620000);
    /// The type definition node id does not reference an appropriate type node.
    pub const BadTypeDefinitionInvalid: Self = Self(0x80630000);
    /// The source node id does not reference a valid node.
    pub const BadSourceNodeIdInvalid: Self = Self(0x80640000);
    /// The target node id does not reference a valid node.
    pub const BadTargetNodeIdInvalid: Self = Self(0x80650000);
    /// The reference type between the nodes is already defined.
    pub const BadDuplicateReferenceNotAllowed: Self = Self(0x80660000);
    /// The server does not allow this type of self reference on this node.
    pub const BadInvalidSelfReference: Self = Self(0x80670000);
    /// The reference type is not valid for a reference to a remote server.
    pub const BadReferenceLocalOnly: Self = Self(0x80680000);
    /// The server will not allow the node to be deleted.
    pub const BadNoDeleteRights: Self = Self(0x80690000);
    /// The server was not able to delete all target references.
    pub const UncertainReferenceNotDeleted: Self = Self(0x40BC0000);
    /// The server index is not valid.
    pub const BadServerIndexInvalid: Self = Self(0x806A0000);
    /// The view id does not refer to a valid view node.
    pub const BadViewIdUnknown: Self = Self(0x806B0000);
    /// The view timestamp is not available or not supported.
    pub const BadViewTimestampInvalid: Self = Self(0x80C90000);
    /// The view parameters are not consistent with each other.
    pub const BadViewParameterMismatch: Self = Self(0x80CA0000);
    /// The view version is not available or not supported.
    pub const BadViewVersionInvalid: Self = Self(0x80CB0000);
    /// The list of references may not be complete because the underlying system is not available.
    pub const UncertainNotAllNodesAvailable: Self = Self(0x40C00000);
    /// The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete.
    pub const GoodResultsMayBeIncomplete: Self = Self(0x00BA0000);
    /// The provided Nodeid was not a type definition nodeid.
    pub const BadNotTypeDefinition: Self = Self(0x80C80000);
    /// One of the references to follow in the relative path references to a node in the address space in another server.
    pub const UncertainReferenceOutOfServer: Self = Self(0x406C0000);
    /// The requested operation has too many matches to return.
    pub const BadTooManyMatches: Self = Self(0x806D0000);
    /// The requested operation requires too many resources in the server.
    pub const BadQueryTooComplex: Self = Self(0x806E0000);
    /// The requested operation has no match to return.
    pub const BadNoMatch: Self = Self(0x806F0000);
    /// The max age parameter is invalid.
    pub const BadMaxAgeInvalid: Self = Self(0x80700000);
    /// The operation is not permitted over the current secure channel.
    pub const BadSecurityModeInsufficient: Self = Self(0x80E60000);
    /// The history details parameter is not valid.
    pub const BadHistoryOperationInvalid: Self = Self(0x80710000);
    /// The server does not support the requested operation.
    pub const BadHistoryOperationUnsupported: Self = Self(0x80720000);
    /// The defined timestamp to return was invalid.
    pub const BadInvalidTimestampArgument: Self = Self(0x80BD0000);
    /// The server does not support writing the combination of value, status and timestamps provided.
    pub const BadWriteNotSupported: Self = Self(0x80730000);
    /// The value supplied for the attribute is not of the same type as the attribute's value.
    pub const BadTypeMismatch: Self = Self(0x80740000);
    /// The method id does not refer to a method for the specified object.
    pub const BadMethodInvalid: Self = Self(0x80750000);
    /// The client did not specify all of the input arguments for the method.
    pub const BadArgumentsMissing: Self = Self(0x80760000);
    /// The executable attribute does not allow the execution of the method.
    pub const BadNotExecutable: Self = Self(0x81110000);
    /// The server has reached its maximum number of subscriptions.
    pub const BadTooManySubscriptions: Self = Self(0x80770000);
    /// The server has reached the maximum number of queued publish requests.
    pub const BadTooManyPublishRequests: Self = Self(0x80780000);
    /// There is no subscription available for this session.
    pub const BadNoSubscription: Self = Self(0x80790000);
    /// The sequence number is unknown to the server.
    pub const BadSequenceNumberUnknown: Self = Self(0x807A0000);
    /// The Server does not support retransmission queue and acknowledgement of sequence numbers is not available.
    pub const GoodRetransmissionQueueNotSupported: Self = Self(0x00DF0000);
    /// The requested notification message is no longer available.
    pub const BadMessageNotAvailable: Self = Self(0x807B0000);
    /// The client of the current session does not support one or more Profiles that are necessary for the subscription.
    pub const BadInsufficientClientProfile: Self = Self(0x807C0000);
    /// The sub-state machine is not currently active.
    pub const BadStateNotActive: Self = Self(0x80BF0000);
    /// An equivalent rule already exists.
    pub const BadAlreadyExists: Self = Self(0x81150000);
    /// The server cannot process the request because it is too busy.
    pub const BadTcpServerTooBusy: Self = Self(0x807D0000);
    /// The type of the message specified in the header invalid.
    pub const BadTcpMessageTypeInvalid: Self = Self(0x807E0000);
    /// The SecureChannelId and/or TokenId are not currently in use.
    pub const BadTcpSecureChannelUnknown: Self = Self(0x807F0000);
    /// The size of the message chunk specified in the header is too large.
    pub const BadTcpMessageTooLarge: Self = Self(0x80800000);
    /// There are not enough resources to process the request.
    pub const BadTcpNotEnoughResources: Self = Self(0x80810000);
    /// An internal error occurred.
    pub const BadTcpInternalError: Self = Self(0x80820000);
    /// The server does not recognize the QueryString specified.
    pub const BadTcpEndpointUrlInvalid: Self = Self(0x80830000);
    /// The request could not be sent because of a network interruption.
    pub const BadRequestInterrupted: Self = Self(0x80840000);
    /// Timeout occurred while processing the request.
    pub const BadRequestTimeout: Self = Self(0x80850000);
    /// The secure channel has been closed.
    pub const BadSecureChannelClosed: Self = Self(0x80860000);
    /// The token has expired or is not recognized.
    pub const BadSecureChannelTokenUnknown: Self = Self(0x80870000);
    /// The sequence number is not valid.
    pub const BadSequenceNumberInvalid: Self = Self(0x80880000);
    /// The applications do not have compatible protocol versions.
    pub const BadProtocolVersionUnsupported: Self = Self(0x80BE0000);
    /// There is a problem with the configuration that affects the usefulness of the value.
    pub const BadConfigurationError: Self = Self(0x80890000);
    /// The variable should receive its value from another variable, but has never been configured to do so.
    pub const BadNotConnected: Self = Self(0x808A0000);
    /// There has been a failure in the device/data source that generates the value that has affected the value.
    pub const BadDeviceFailure: Self = Self(0x808B0000);
    /// There has been a failure in the sensor from which the value is derived by the device/data source.
    pub const BadSensorFailure: Self = Self(0x808C0000);
    /// The source of the data is not operational.
    pub const BadOutOfService: Self = Self(0x808D0000);
    /// The deadband filter is not valid.
    pub const BadDeadbandFilterInvalid: Self = Self(0x808E0000);
    /// Communication to the data source has failed. The variable value is the last value that had a good quality.
    pub const UncertainNoCommunicationLastUsableValue: Self = Self(0x408F0000);
    /// Whatever was updating this value has stopped doing so.
    pub const UncertainLastUsableValue: Self = Self(0x40900000);
    /// The value is an operational value that was manually overwritten.
    pub const UncertainSubstituteValue: Self = Self(0x40910000);
    /// The value is an initial value for a variable that normally receives its value from another variable.
    pub const UncertainInitialValue: Self = Self(0x40920000);
    /// The value is at one of the sensor limits.
    pub const UncertainSensorNotAccurate: Self = Self(0x40930000);
    /// The value is outside of the range of values defined for this parameter.
    pub const UncertainEngineeringUnitsExceeded: Self = Self(0x40940000);
    /// The data value is derived from multiple sources and has less than the required number of Good sources.
    pub const UncertainSubNormal: Self = Self(0x40950000);
    /// The value has been overridden.
    pub const GoodLocalOverride: Self = Self(0x00960000);
    /// The value is derived from multiple sources and has the required number of Good sources, but less than the full number of Good sources.
    pub const GoodSubNormal: Self = Self(0x00EB0000);
    /// This Condition refresh failed, a Condition refresh operation is already in progress.
    pub const BadRefreshInProgress: Self = Self(0x80970000);
    /// This condition has already been disabled.
    pub const BadConditionAlreadyDisabled: Self = Self(0x80980000);
    /// This condition has already been enabled.
    pub const BadConditionAlreadyEnabled: Self = Self(0x80CC0000);
    /// Property not available, this condition is disabled.
    pub const BadConditionDisabled: Self = Self(0x80990000);
    /// The specified event id is not recognized.
    pub const BadEventIdUnknown: Self = Self(0x809A0000);
    /// The event cannot be acknowledged.
    pub const BadEventNotAcknowledgeable: Self = Self(0x80BB0000);
    /// The dialog condition is not active.
    pub const BadDialogNotActive: Self = Self(0x80CD0000);
    /// The response is not valid for the dialog.
    pub const BadDialogResponseInvalid: Self = Self(0x80CE0000);
    /// The condition branch has already been acknowledged.
    pub const BadConditionBranchAlreadyAcked: Self = Self(0x80CF0000);
    /// The condition branch has already been confirmed.
    pub const BadConditionBranchAlreadyConfirmed: Self = Self(0x80D00000);
    /// The condition has already been shelved.
    pub const BadConditionAlreadyShelved: Self = Self(0x80D10000);
    /// The condition is not currently shelved.
    pub const BadConditionNotShelved: Self = Self(0x80D20000);
    /// The shelving time not within an acceptable range.
    pub const BadShelvingTimeOutOfRange: Self = Self(0x80D30000);
    /// No data exists for the requested time range or event filter.
    pub const BadNoData: Self = Self(0x809B0000);
    /// No data found to provide upper or lower bound value.
    pub const BadBoundNotFound: Self = Self(0x80D70000);
    /// The server cannot retrieve a bound for the variable.
    pub const BadBoundNotSupported: Self = Self(0x80D80000);
    /// Data is missing due to collection started/stopped/lost.
    pub const BadDataLost: Self = Self(0x809D0000);
    /// Expected data is unavailable for the requested time range due to an un-mounted volume, an off-line archive or tape, or similar reason for temporary unavailability.
    pub const BadDataUnavailable: Self = Self(0x809E0000);
    /// The data or event was not successfully inserted because a matching entry exists.
    pub const BadEntryExists: Self = Self(0x809F0000);
    /// The data or event was not successfully updated because no matching entry exists.
    pub const BadNoEntryExists: Self = Self(0x80A00000);
    /// The Client requested history using a TimestampsToReturn the Server does not support.
    pub const BadTimestampNotSupported: Self = Self(0x80A10000);
    /// The data or event was successfully inserted into the historical database.
    pub const GoodEntryInserted: Self = Self(0x00A20000);
    /// The data or event field was successfully replaced in the historical database.
    pub const GoodEntryReplaced: Self = Self(0x00A30000);
    /// The aggregate value is derived from multiple values and has less than the required number of Good values.
    pub const UncertainDataSubNormal: Self = Self(0x40A40000);
    /// No data exists for the requested time range or event filter.
    pub const GoodNoData: Self = Self(0x00A50000);
    /// More data is available in the time range beyond the number of values requested.
    pub const GoodMoreData: Self = Self(0x00A60000);
    /// The requested number of Aggregates does not match the requested number of NodeIds.
    pub const BadAggregateListMismatch: Self = Self(0x80D40000);
    /// The requested Aggregate is not support by the server.
    pub const BadAggregateNotSupported: Self = Self(0x80D50000);
    /// The aggregate value could not be derived due to invalid data inputs.
    pub const BadAggregateInvalidInputs: Self = Self(0x80D60000);
    /// The aggregate configuration is not valid for specified node.
    pub const BadAggregateConfigurationRejected: Self = Self(0x80DA0000);
    /// The request specifies fields which are not valid for the EventType or cannot be saved by the historian.
    pub const GoodDataIgnored: Self = Self(0x00D90000);
    /// The request was rejected by the server because it did not meet the criteria set by the server.
    pub const BadRequestNotAllowed: Self = Self(0x80E40000);
    /// The request has not been processed by the server yet.
    pub const BadRequestNotComplete: Self = Self(0x81130000);
    /// The operation is not allowed because a transaction is in progress.
    pub const BadTransactionPending: Self = Self(0x80E80000);
    /// The operation failed and all changes which were part of the transaction are rolled back.
    pub const BadTransactionFailed: Self = Self(0x80F10000);
    /// The device identity needs a ticket before it can be accepted.
    pub const BadTicketRequired: Self = Self(0x811F0000);
    /// The device identity needs a ticket before it can be accepted.
    pub const BadTicketInvalid: Self = Self(0x81200000);
    /// The requested operation is not allowed, because the Node is locked by a different application.
    pub const BadLocked: Self = Self(0x80E90000);
    /// The requested operation is not allowed, because the Node is not locked by the application.
    pub const BadRequiresLock: Self = Self(0x80EC0000);
    /// The value does not come from the real source and has been edited by the server.
    pub const GoodEdited: Self = Self(0x00DC0000);
    /// There was an error in execution of these post-actions.
    pub const GoodPostActionFailed: Self = Self(0x00DD0000);
    /// The related EngineeringUnit has been changed but the Variable Value is still provided based on the previous unit.
    pub const UncertainDominantValueChanged: Self = Self(0x40DE0000);
    /// A dependent value has been changed but the change has not been applied to the device.
    pub const GoodDependentValueChanged: Self = Self(0x00E00000);
    /// The related EngineeringUnit has been changed but this change has not been applied to the device. The Variable Value is still dependent on the previous unit but its status is currently Bad.
    pub const BadDominantValueChanged: Self = Self(0x80E10000);
    /// A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is uncertain.
    pub const UncertainDependentValueChanged: Self = Self(0x40E20000);
    /// A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is Bad.
    pub const BadDependentValueChanged: Self = Self(0x80E30000);
    /// It is delivered with a dominant Variable value when a dependent Variable has changed but the change has not been applied.
    pub const GoodEdited_DependentValueChanged: Self = Self(0x01160000);
    /// It is delivered with a dependent Variable value when a dominant Variable has changed but the change has not been applied.
    pub const GoodEdited_DominantValueChanged: Self = Self(0x01170000);
    /// It is delivered with a dependent Variable value when a dominant or dependent Variable has changed but change has not been applied.
    pub const GoodEdited_DominantValueChanged_DependentValueChanged: Self = Self(0x01180000);
    /// It is delivered with a Variable value when Variable has changed but the value is not legal.
    pub const BadEdited_OutOfRange: Self = Self(0x81190000);
    /// It is delivered with a Variable value when a source Variable has changed but the value is not legal.
    pub const BadInitialValue_OutOfRange: Self = Self(0x811A0000);
    /// It is delivered with a dependent Variable value when a dominant Variable has changed and the value is not legal.
    pub const BadOutOfRange_DominantValueChanged: Self = Self(0x811B0000);
    /// It is delivered with a dependent Variable value when a dominant Variable has changed, the value is not legal and the change has not been applied.
    pub const BadEdited_OutOfRange_DominantValueChanged: Self = Self(0x811C0000);
    /// It is delivered with a dependent Variable value when a dominant or dependent Variable has changed and the value is not legal.
    pub const BadOutOfRange_DominantValueChanged_DependentValueChanged: Self = Self(0x811D0000);
    /// It is delivered with a dependent Variable value when a dominant or dependent Variable has changed, the value is not legal and the change has not been applied.
    pub const BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged: Self =
        Self(0x811E0000);
    /// The communication layer has raised an event.
    pub const GoodCommunicationEvent: Self = Self(0x00A70000);
    /// The system is shutting down.
    pub const GoodShutdownEvent: Self = Self(0x00A80000);
    /// The operation is not finished and needs to be called again.
    pub const GoodCallAgain: Self = Self(0x00A90000);
    /// A non-critical timeout occurred.
    pub const GoodNonCriticalTimeout: Self = Self(0x00AA0000);
    /// One or more arguments are invalid.
    pub const BadInvalidArgument: Self = Self(0x80AB0000);
    /// Could not establish a network connection to remote server.
    pub const BadConnectionRejected: Self = Self(0x80AC0000);
    /// The server has disconnected from the client.
    pub const BadDisconnect: Self = Self(0x80AD0000);
    /// The network connection has been closed.
    pub const BadConnectionClosed: Self = Self(0x80AE0000);
    /// The operation cannot be completed because the object is closed, uninitialized or in some other invalid state.
    pub const BadInvalidState: Self = Self(0x80AF0000);
    /// Cannot move beyond end of the stream.
    pub const BadEndOfStream: Self = Self(0x80B00000);
    /// No data is currently available for reading from a non-blocking stream.
    pub const BadNoDataAvailable: Self = Self(0x80B10000);
    /// The asynchronous operation is waiting for a response.
    pub const BadWaitingForResponse: Self = Self(0x80B20000);
    /// The asynchronous operation was abandoned by the caller.
    pub const BadOperationAbandoned: Self = Self(0x80B30000);
    /// The stream did not return all data requested (possibly because it is a non-blocking stream).
    pub const BadExpectedStreamToBlock: Self = Self(0x80B40000);
    /// Non blocking behaviour is required and the operation would block.
    pub const BadWouldBlock: Self = Self(0x80B50000);
    /// A value had an invalid syntax.
    pub const BadSyntaxError: Self = Self(0x80B60000);
    /// The operation could not be finished because all available connections are in use.
    pub const BadMaxConnectionsReached: Self = Self(0x80B70000);
    /// The value may not be accurate because the transducer is in manual mode.
    pub const UncertainTransducerInManual: Self = Self(0x42080000);
    /// The value is simulated.
    pub const UncertainSimulatedValue: Self = Self(0x42090000);
    /// The value may not be accurate due to a sensor calibration fault.
    pub const UncertainSensorCalibration: Self = Self(0x420A0000);
    /// The value may not be accurate due to a configuration issue.
    pub const UncertainConfigurationError: Self = Self(0x420F0000);
    /// The value source supports cascade handshaking and the value has been Initialized based on an initialization request from a cascade secondary.
    pub const GoodCascadeInitializationAcknowledged: Self = Self(0x04010000);
    /// The value source supports cascade handshaking and is requesting initialization of a cascade primary.
    pub const GoodCascadeInitializationRequest: Self = Self(0x04020000);
    /// The value source supports cascade handshaking, however, the source's current state does not allow for cascade.
    pub const GoodCascadeNotInvited: Self = Self(0x04030000);
    /// The value source supports cascade handshaking, however, the source has not selected the corresponding cascade primary for use.
    pub const GoodCascadeNotSelected: Self = Self(0x04040000);
    /// There is a fault state condition active in the value source.
    pub const GoodFaultStateActive: Self = Self(0x04070000);
    /// A fault state condition is being requested of the destination.
    pub const GoodInitiateFaultState: Self = Self(0x04080000);
    /// The value is accurate, and the signal source supports cascade handshaking.
    pub const GoodCascade: Self = Self(0x04090000);
    /// The DataSet specified for the DataSetWriter creation is invalid.
    pub const BadDataSetIdInvalid: Self = Self(0x80E70000);
    /// Standard symbolic name, ignoring the information bits.
    pub fn name(self) -> Option<&'static str> {
        match self.bits() & 0xffff0000 {
            0x00000000 => Some("Good"),
            0x40000000 => Some("Uncertain"),
            0x80000000 => Some("Bad"),
            0x80010000 => Some("BadUnexpectedError"),
            0x80020000 => Some("BadInternalError"),
            0x80030000 => Some("BadOutOfMemory"),
            0x80040000 => Some("BadResourceUnavailable"),
            0x80050000 => Some("BadCommunicationError"),
            0x80060000 => Some("BadEncodingError"),
            0x80070000 => Some("BadDecodingError"),
            0x80080000 => Some("BadEncodingLimitsExceeded"),
            0x80B80000 => Some("BadRequestTooLarge"),
            0x80B90000 => Some("BadResponseTooLarge"),
            0x80090000 => Some("BadUnknownResponse"),
            0x800A0000 => Some("BadTimeout"),
            0x800B0000 => Some("BadServiceUnsupported"),
            0x800C0000 => Some("BadShutdown"),
            0x800D0000 => Some("BadServerNotConnected"),
            0x800E0000 => Some("BadServerHalted"),
            0x800F0000 => Some("BadNothingToDo"),
            0x80100000 => Some("BadTooManyOperations"),
            0x80DB0000 => Some("BadTooManyMonitoredItems"),
            0x80110000 => Some("BadDataTypeIdUnknown"),
            0x80120000 => Some("BadCertificateInvalid"),
            0x80130000 => Some("BadSecurityChecksFailed"),
            0x81140000 => Some("BadCertificatePolicyCheckFailed"),
            0x80140000 => Some("BadCertificateTimeInvalid"),
            0x80150000 => Some("BadCertificateIssuerTimeInvalid"),
            0x80160000 => Some("BadCertificateHostNameInvalid"),
            0x80170000 => Some("BadCertificateUriInvalid"),
            0x80180000 => Some("BadCertificateUseNotAllowed"),
            0x80190000 => Some("BadCertificateIssuerUseNotAllowed"),
            0x801A0000 => Some("BadCertificateUntrusted"),
            0x801B0000 => Some("BadCertificateRevocationUnknown"),
            0x801C0000 => Some("BadCertificateIssuerRevocationUnknown"),
            0x801D0000 => Some("BadCertificateRevoked"),
            0x801E0000 => Some("BadCertificateIssuerRevoked"),
            0x810D0000 => Some("BadCertificateChainIncomplete"),
            0x801F0000 => Some("BadUserAccessDenied"),
            0x80200000 => Some("BadIdentityTokenInvalid"),
            0x80210000 => Some("BadIdentityTokenRejected"),
            0x80220000 => Some("BadSecureChannelIdInvalid"),
            0x80230000 => Some("BadInvalidTimestamp"),
            0x80240000 => Some("BadNonceInvalid"),
            0x80250000 => Some("BadSessionIdInvalid"),
            0x80260000 => Some("BadSessionClosed"),
            0x80270000 => Some("BadSessionNotActivated"),
            0x80280000 => Some("BadSubscriptionIdInvalid"),
            0x802A0000 => Some("BadRequestHeaderInvalid"),
            0x802B0000 => Some("BadTimestampsToReturnInvalid"),
            0x802C0000 => Some("BadRequestCancelledByClient"),
            0x80E50000 => Some("BadTooManyArguments"),
            0x810E0000 => Some("BadLicenseExpired"),
            0x810F0000 => Some("BadLicenseLimitsExceeded"),
            0x81100000 => Some("BadLicenseNotAvailable"),
            0x80EE0000 => Some("BadServerTooBusy"),
            0x00EF0000 => Some("GoodPasswordChangeRequired"),
            0x002D0000 => Some("GoodSubscriptionTransferred"),
            0x002E0000 => Some("GoodCompletesAsynchronously"),
            0x002F0000 => Some("GoodOverload"),
            0x00300000 => Some("GoodClamped"),
            0x80310000 => Some("BadNoCommunication"),
            0x80320000 => Some("BadWaitingForInitialData"),
            0x80330000 => Some("BadNodeIdInvalid"),
            0x80340000 => Some("BadNodeIdUnknown"),
            0x80350000 => Some("BadAttributeIdInvalid"),
            0x80360000 => Some("BadIndexRangeInvalid"),
            0x80370000 => Some("BadIndexRangeNoData"),
            0x80EA0000 => Some("BadIndexRangeDataMismatch"),
            0x80380000 => Some("BadDataEncodingInvalid"),
            0x80390000 => Some("BadDataEncodingUnsupported"),
            0x803A0000 => Some("BadNotReadable"),
            0x803B0000 => Some("BadNotWritable"),
            0x803C0000 => Some("BadOutOfRange"),
            0x40F20000 => Some("UncertainOverRange"),
            0x40F30000 => Some("UncertainUnderRange"),
            0x803D0000 => Some("BadNotSupported"),
            0x803E0000 => Some("BadNotFound"),
            0x803F0000 => Some("BadObjectDeleted"),
            0x80400000 => Some("BadNotImplemented"),
            0x80410000 => Some("BadMonitoringModeInvalid"),
            0x80420000 => Some("BadMonitoredItemIdInvalid"),
            0x80430000 => Some("BadMonitoredItemFilterInvalid"),
            0x80440000 => Some("BadMonitoredItemFilterUnsupported"),
            0x80450000 => Some("BadFilterNotAllowed"),
            0x80460000 => Some("BadStructureMissing"),
            0x80470000 => Some("BadEventFilterInvalid"),
            0x80480000 => Some("BadContentFilterInvalid"),
            0x80C10000 => Some("BadFilterOperatorInvalid"),
            0x80C20000 => Some("BadFilterOperatorUnsupported"),
            0x80C30000 => Some("BadFilterOperandCountMismatch"),
            0x80490000 => Some("BadFilterOperandInvalid"),
            0x80C40000 => Some("BadFilterElementInvalid"),
            0x80C50000 => Some("BadFilterLiteralInvalid"),
            0x804A0000 => Some("BadContinuationPointInvalid"),
            0x804B0000 => Some("BadNoContinuationPoints"),
            0x804C0000 => Some("BadReferenceTypeIdInvalid"),
            0x804D0000 => Some("BadBrowseDirectionInvalid"),
            0x804E0000 => Some("BadNodeNotInView"),
            0x81120000 => Some("BadNumericOverflow"),
            0x80ED0000 => Some("BadLocaleNotSupported"),
            0x80F00000 => Some("BadNoValue"),
            0x804F0000 => Some("BadServerUriInvalid"),
            0x80500000 => Some("BadServerNameMissing"),
            0x80510000 => Some("BadDiscoveryUrlMissing"),
            0x80520000 => Some("BadSemaphoreFileMissing"),
            0x80530000 => Some("BadRequestTypeInvalid"),
            0x80540000 => Some("BadSecurityModeRejected"),
            0x80550000 => Some("BadSecurityPolicyRejected"),
            0x80560000 => Some("BadTooManySessions"),
            0x80570000 => Some("BadUserSignatureInvalid"),
            0x80580000 => Some("BadApplicationSignatureInvalid"),
            0x80590000 => Some("BadNoValidCertificates"),
            0x80C60000 => Some("BadIdentityChangeNotSupported"),
            0x805A0000 => Some("BadRequestCancelledByRequest"),
            0x805B0000 => Some("BadParentNodeIdInvalid"),
            0x805C0000 => Some("BadReferenceNotAllowed"),
            0x805D0000 => Some("BadNodeIdRejected"),
            0x805E0000 => Some("BadNodeIdExists"),
            0x805F0000 => Some("BadNodeClassInvalid"),
            0x80600000 => Some("BadBrowseNameInvalid"),
            0x80610000 => Some("BadBrowseNameDuplicated"),
            0x80620000 => Some("BadNodeAttributesInvalid"),
            0x80630000 => Some("BadTypeDefinitionInvalid"),
            0x80640000 => Some("BadSourceNodeIdInvalid"),
            0x80650000 => Some("BadTargetNodeIdInvalid"),
            0x80660000 => Some("BadDuplicateReferenceNotAllowed"),
            0x80670000 => Some("BadInvalidSelfReference"),
            0x80680000 => Some("BadReferenceLocalOnly"),
            0x80690000 => Some("BadNoDeleteRights"),
            0x40BC0000 => Some("UncertainReferenceNotDeleted"),
            0x806A0000 => Some("BadServerIndexInvalid"),
            0x806B0000 => Some("BadViewIdUnknown"),
            0x80C90000 => Some("BadViewTimestampInvalid"),
            0x80CA0000 => Some("BadViewParameterMismatch"),
            0x80CB0000 => Some("BadViewVersionInvalid"),
            0x40C00000 => Some("UncertainNotAllNodesAvailable"),
            0x00BA0000 => Some("GoodResultsMayBeIncomplete"),
            0x80C80000 => Some("BadNotTypeDefinition"),
            0x406C0000 => Some("UncertainReferenceOutOfServer"),
            0x806D0000 => Some("BadTooManyMatches"),
            0x806E0000 => Some("BadQueryTooComplex"),
            0x806F0000 => Some("BadNoMatch"),
            0x80700000 => Some("BadMaxAgeInvalid"),
            0x80E60000 => Some("BadSecurityModeInsufficient"),
            0x80710000 => Some("BadHistoryOperationInvalid"),
            0x80720000 => Some("BadHistoryOperationUnsupported"),
            0x80BD0000 => Some("BadInvalidTimestampArgument"),
            0x80730000 => Some("BadWriteNotSupported"),
            0x80740000 => Some("BadTypeMismatch"),
            0x80750000 => Some("BadMethodInvalid"),
            0x80760000 => Some("BadArgumentsMissing"),
            0x81110000 => Some("BadNotExecutable"),
            0x80770000 => Some("BadTooManySubscriptions"),
            0x80780000 => Some("BadTooManyPublishRequests"),
            0x80790000 => Some("BadNoSubscription"),
            0x807A0000 => Some("BadSequenceNumberUnknown"),
            0x00DF0000 => Some("GoodRetransmissionQueueNotSupported"),
            0x807B0000 => Some("BadMessageNotAvailable"),
            0x807C0000 => Some("BadInsufficientClientProfile"),
            0x80BF0000 => Some("BadStateNotActive"),
            0x81150000 => Some("BadAlreadyExists"),
            0x807D0000 => Some("BadTcpServerTooBusy"),
            0x807E0000 => Some("BadTcpMessageTypeInvalid"),
            0x807F0000 => Some("BadTcpSecureChannelUnknown"),
            0x80800000 => Some("BadTcpMessageTooLarge"),
            0x80810000 => Some("BadTcpNotEnoughResources"),
            0x80820000 => Some("BadTcpInternalError"),
            0x80830000 => Some("BadTcpEndpointUrlInvalid"),
            0x80840000 => Some("BadRequestInterrupted"),
            0x80850000 => Some("BadRequestTimeout"),
            0x80860000 => Some("BadSecureChannelClosed"),
            0x80870000 => Some("BadSecureChannelTokenUnknown"),
            0x80880000 => Some("BadSequenceNumberInvalid"),
            0x80BE0000 => Some("BadProtocolVersionUnsupported"),
            0x80890000 => Some("BadConfigurationError"),
            0x808A0000 => Some("BadNotConnected"),
            0x808B0000 => Some("BadDeviceFailure"),
            0x808C0000 => Some("BadSensorFailure"),
            0x808D0000 => Some("BadOutOfService"),
            0x808E0000 => Some("BadDeadbandFilterInvalid"),
            0x408F0000 => Some("UncertainNoCommunicationLastUsableValue"),
            0x40900000 => Some("UncertainLastUsableValue"),
            0x40910000 => Some("UncertainSubstituteValue"),
            0x40920000 => Some("UncertainInitialValue"),
            0x40930000 => Some("UncertainSensorNotAccurate"),
            0x40940000 => Some("UncertainEngineeringUnitsExceeded"),
            0x40950000 => Some("UncertainSubNormal"),
            0x00960000 => Some("GoodLocalOverride"),
            0x00EB0000 => Some("GoodSubNormal"),
            0x80970000 => Some("BadRefreshInProgress"),
            0x80980000 => Some("BadConditionAlreadyDisabled"),
            0x80CC0000 => Some("BadConditionAlreadyEnabled"),
            0x80990000 => Some("BadConditionDisabled"),
            0x809A0000 => Some("BadEventIdUnknown"),
            0x80BB0000 => Some("BadEventNotAcknowledgeable"),
            0x80CD0000 => Some("BadDialogNotActive"),
            0x80CE0000 => Some("BadDialogResponseInvalid"),
            0x80CF0000 => Some("BadConditionBranchAlreadyAcked"),
            0x80D00000 => Some("BadConditionBranchAlreadyConfirmed"),
            0x80D10000 => Some("BadConditionAlreadyShelved"),
            0x80D20000 => Some("BadConditionNotShelved"),
            0x80D30000 => Some("BadShelvingTimeOutOfRange"),
            0x809B0000 => Some("BadNoData"),
            0x80D70000 => Some("BadBoundNotFound"),
            0x80D80000 => Some("BadBoundNotSupported"),
            0x809D0000 => Some("BadDataLost"),
            0x809E0000 => Some("BadDataUnavailable"),
            0x809F0000 => Some("BadEntryExists"),
            0x80A00000 => Some("BadNoEntryExists"),
            0x80A10000 => Some("BadTimestampNotSupported"),
            0x00A20000 => Some("GoodEntryInserted"),
            0x00A30000 => Some("GoodEntryReplaced"),
            0x40A40000 => Some("UncertainDataSubNormal"),
            0x00A50000 => Some("GoodNoData"),
            0x00A60000 => Some("GoodMoreData"),
            0x80D40000 => Some("BadAggregateListMismatch"),
            0x80D50000 => Some("BadAggregateNotSupported"),
            0x80D60000 => Some("BadAggregateInvalidInputs"),
            0x80DA0000 => Some("BadAggregateConfigurationRejected"),
            0x00D90000 => Some("GoodDataIgnored"),
            0x80E40000 => Some("BadRequestNotAllowed"),
            0x81130000 => Some("BadRequestNotComplete"),
            0x80E80000 => Some("BadTransactionPending"),
            0x80F10000 => Some("BadTransactionFailed"),
            0x811F0000 => Some("BadTicketRequired"),
            0x81200000 => Some("BadTicketInvalid"),
            0x80E90000 => Some("BadLocked"),
            0x80EC0000 => Some("BadRequiresLock"),
            0x00DC0000 => Some("GoodEdited"),
            0x00DD0000 => Some("GoodPostActionFailed"),
            0x40DE0000 => Some("UncertainDominantValueChanged"),
            0x00E00000 => Some("GoodDependentValueChanged"),
            0x80E10000 => Some("BadDominantValueChanged"),
            0x40E20000 => Some("UncertainDependentValueChanged"),
            0x80E30000 => Some("BadDependentValueChanged"),
            0x01160000 => Some("GoodEdited_DependentValueChanged"),
            0x01170000 => Some("GoodEdited_DominantValueChanged"),
            0x01180000 => Some("GoodEdited_DominantValueChanged_DependentValueChanged"),
            0x81190000 => Some("BadEdited_OutOfRange"),
            0x811A0000 => Some("BadInitialValue_OutOfRange"),
            0x811B0000 => Some("BadOutOfRange_DominantValueChanged"),
            0x811C0000 => Some("BadEdited_OutOfRange_DominantValueChanged"),
            0x811D0000 => Some("BadOutOfRange_DominantValueChanged_DependentValueChanged"),
            0x811E0000 => Some("BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged"),
            0x00A70000 => Some("GoodCommunicationEvent"),
            0x00A80000 => Some("GoodShutdownEvent"),
            0x00A90000 => Some("GoodCallAgain"),
            0x00AA0000 => Some("GoodNonCriticalTimeout"),
            0x80AB0000 => Some("BadInvalidArgument"),
            0x80AC0000 => Some("BadConnectionRejected"),
            0x80AD0000 => Some("BadDisconnect"),
            0x80AE0000 => Some("BadConnectionClosed"),
            0x80AF0000 => Some("BadInvalidState"),
            0x80B00000 => Some("BadEndOfStream"),
            0x80B10000 => Some("BadNoDataAvailable"),
            0x80B20000 => Some("BadWaitingForResponse"),
            0x80B30000 => Some("BadOperationAbandoned"),
            0x80B40000 => Some("BadExpectedStreamToBlock"),
            0x80B50000 => Some("BadWouldBlock"),
            0x80B60000 => Some("BadSyntaxError"),
            0x80B70000 => Some("BadMaxConnectionsReached"),
            0x42080000 => Some("UncertainTransducerInManual"),
            0x42090000 => Some("UncertainSimulatedValue"),
            0x420A0000 => Some("UncertainSensorCalibration"),
            0x420F0000 => Some("UncertainConfigurationError"),
            0x04010000 => Some("GoodCascadeInitializationAcknowledged"),
            0x04020000 => Some("GoodCascadeInitializationRequest"),
            0x04030000 => Some("GoodCascadeNotInvited"),
            0x04040000 => Some("GoodCascadeNotSelected"),
            0x04070000 => Some("GoodFaultStateActive"),
            0x04080000 => Some("GoodInitiateFaultState"),
            0x04090000 => Some("GoodCascade"),
            0x80E70000 => Some("BadDataSetIdInvalid"),
            _ => None,
        }
    }
}
