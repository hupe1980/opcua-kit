"""Independent encrypted asyncua server for native read interoperability."""

import asyncio
from contextlib import asynccontextmanager, suppress

from asyncua import Server, ua
from asyncua.common.callback import CallbackType
from asyncua.common.utils import ServiceError
from cryptography.hazmat.primitives.serialization import Encoding


async def add_meter(server, hvac, evidence):
    node = await server.nodes.objects.add_variable(
        ua.NodeId("TestRegister", hvac),
        ua.QualifiedName("TestRegister", hvac),
        ua.Variant(42, ua.VariantType.UInt64),
    )
    await node.write_value_rank(-1)
    wh = ua.EUInformation(
        NamespaceUri="http://www.opcfoundation.org/UA/units/un/cefact",
        UnitId=int.from_bytes(b"WHR", "big"),
    )
    prop = await node.add_property(
        ua.NodeId("TestRegisterUnits", hvac),
        ua.QualifiedName("EngineeringUnits", 0),
        ua.Variant(wh, ua.VariantType.ExtensionObject),
        datatype=ua.ObjectIds.EUInformation,
    )
    await prop.write_value_rank(-1)
    evidence.update(
        reads=[],
        rank=ua.DataValue(ua.Variant(-1, ua.VariantType.Int32)),
        unit_rank=ua.DataValue(ua.Variant(-1, ua.VariantType.Int32)),
        unit=ua.DataValue(ua.Variant(wh, ua.VariantType.ExtensionObject)),
        register=ua.DataValue(ua.Variant(42, ua.VariantType.UInt64)),
    )

    def read_register(node_id, attr):
        evidence["reads"].append(attr)
        if replacement := evidence.get("unit_after_register"):
            evidence["unit"] = replacement
        return evidence["register"]

    server.set_attribute_value_callback(node.nodeid, read_register)
    server.set_attribute_value_callback(
        node.nodeid, lambda node_id, attr: evidence["rank"], ua.AttributeIds.ValueRank
    )
    server.set_attribute_value_callback(
        prop.nodeid, lambda node_id, attr: evidence["unit"]
    )
    server.set_attribute_value_callback(
        prop.nodeid,
        lambda node_id, attr: evidence["unit_rank"],
        ua.AttributeIds.ValueRank,
    )


@asynccontextmanager
async def attribute_peer(
    folder, *, meter=None, read_log=None, navigation=False, monitored=None
):
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:0/")
    await server.set_application_uri("urn:fixture:server")
    await server.load_certificate(folder / "server.der")
    await server.load_private_key(folder / "server.key", format="pem")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    server.set_identity_tokens([ua.AnonymousIdentityToken])
    trusted = (folder / "client.der").read_bytes()

    async def validate(certificate, application):
        if certificate.public_bytes(Encoding.DER) != trusted:
            raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)
        if application.ApplicationUri != "urn:fixture:client":
            raise ServiceError(ua.StatusCodes.BadCertificateUriInvalid)

    server.set_certificate_validator(validate)
    types = await server.register_namespace("urn:fixture:types")
    hvac = await server.register_namespace("urn:fixture:hvac")
    delays = meter.get("delays", {}) if meter is not None else {}
    if read_log is not None or delays:

        async def observe_read(event, service):
            for operand in event.request_params.NodesToRead:
                if operand.NodeId.NamespaceIndex != hvac:
                    continue
                name, attr = operand.NodeId.Identifier, operand.AttributeId
                if read_log is not None:
                    read_log.append((name, attr))
                if name == "TestRegisterUnits" and attr in delays:
                    meter["delayed"].append(attr)
                    await asyncio.sleep(delays[attr])

        server.subscribe_server_callback(CallbackType.PreRead, observe_read)
    if monitored is not None:

        async def observe_create(event, service):
            params = event.request_params
            monitored["created"].append(
                (
                    params.SubscriptionId,
                    [
                        (
                            item.ItemToMonitor.NodeId.Identifier,
                            result.MonitoredItemId,
                            result.StatusCode.is_good(),
                        )
                        for item, result in zip(
                            params.ItemsToCreate, event.response_params, strict=True
                        )
                    ],
                )
            )

        async def observe_delete(event, service):
            params = event.request_params
            monitored["deleted"].update(
                (params.SubscriptionId, item)
                for item, status in zip(
                    params.MonitoredItemIds, event.response_params, strict=True
                )
                if status.is_good()
            )

        server.subscribe_server_callback(
            CallbackType.ItemSubscriptionCreated, observe_create
        )
        server.subscribe_server_callback(
            CallbackType.ItemSubscriptionDeleted, observe_delete
        )
    if meter is not None:
        await add_meter(server, hvac, meter)
    double = server.get_node(ua.NodeId(ua.ObjectIds.Double))
    custom = await double.add_data_type(
        ua.NodeId(7401, types), ua.QualifiedName("Temperature", types)
    )
    for name in (
        "Temperature",
        "DeniedRank",
        "MalformedRank",
        "UnidentifiedUnit",
        "DeniedUnitType",
        "FlaggedRank",
        "RemoteUnit",
        "AliasViaUri",
    ):
        sensor = await server.nodes.objects.add_variable(
            ua.NodeId(name, hvac),
            ua.QualifiedName(name, hvac),
            22.0,
            datatype=custom.nodeid,
        )
        await sensor.write_value_rank(-1)
        if name in ("RemoteUnit", "AliasViaUri"):
            # These targets are published using the ExpandedNodeId form of
            # ReferenceDescription, independently of their namespace-table index.
            target = ua.ExpandedNodeId(
                Identifier="TemperatureUnits",
                NamespaceUri="urn:fixture:hvac",
                ServerIndex=1 if name == "RemoteUnit" else 0,
            )
            server.iserver.aspace[sensor.nodeid].references.append(
                ua.ReferenceDescription(
                    ReferenceTypeId=ua.NodeId(ua.ObjectIds.HasProperty),
                    IsForward=True,
                    BrowseName=ua.QualifiedName("EngineeringUnits", 0),
                    NodeClass=ua.NodeClass.Variable,
                    NodeId=target,
                )
            )
        if name == "FlaggedRank":
            server.set_attribute_value_callback(
                sensor.nodeid,
                lambda node, attr: ua.DataValue(
                    ua.Variant(-1, ua.VariantType.Int32),
                    StatusCode=ua.StatusCode(0x4000),
                ),
                ua.AttributeIds.ValueRank,
            )
        if name in ("Temperature", "UnidentifiedUnit", "DeniedUnitType"):
            unknown = name == "UnidentifiedUnit"
            engineering_units = ua.EUInformation(
                NamespaceUri="" if unknown else "urn:fixture:unit-catalog",
                UnitId=-1 if unknown else int.from_bytes(b"CEL", "big"),
                DisplayName=ua.LocalizedText("PRIVATE UNIT LABEL"),
                Description=ua.LocalizedText("PRIVATE UNIT DESCRIPTION"),
            )
            prop = await sensor.add_property(
                ua.NodeId(f"{name}Units", hvac),
                ua.QualifiedName("EngineeringUnits", 0),
                ua.Variant(engineering_units, ua.VariantType.ExtensionObject),
                datatype=ua.ObjectIds.EUInformation,
            )
            await prop.write_value_rank(-1)
            if name == "DeniedUnitType":
                server.set_attribute_value_callback(
                    prop.nodeid,
                    lambda node, attr: ua.DataValue(
                        StatusCode=ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
                    ),
                    ua.AttributeIds.DataType,
                )
        if name == "DeniedRank":
            server.set_attribute_value_callback(
                sensor.nodeid,
                lambda node, attr: ua.DataValue(
                    StatusCode=ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
                ),
                ua.AttributeIds.ValueRank,
            )
        if name == "MalformedRank":
            server.set_attribute_value_callback(
                sensor.nodeid,
                lambda node, attr: ua.DataValue(
                    ua.Variant("invalid rank", ua.VariantType.String)
                ),
                ua.AttributeIds.ValueRank,
            )
    if navigation:
        root = await server.nodes.objects.add_object(
            ua.NodeId("Navigation", hvac), ua.QualifiedName("Navigation", hvac)
        )
        area = await root.add_object(
            ua.NodeId("Area", hvac), ua.QualifiedName("Area", hvac)
        )
        for node, browse, ns, number in [
            ("Steady", "Steady", hvac, 42),
            ("Idle", "Idle", hvac, 7),
            ("Resume", "Resume", hvac, 1),
            ("Counter", "Counter", hvac, 2**53 + 1),
            ("OtherCounter", "Counter", types, 0),
            ("TwinA", "Twin", hvac, 0),
            ("TwinB", "Twin", hvac, 0),
            ("Overflow", "Overflow", hvac, 0),
        ]:
            item = await area.add_variable(
                ua.NodeId(node, hvac),
                ua.QualifiedName(browse, ns),
                ua.Variant(number, ua.VariantType.UInt64),
            )
            if node == "Counter":
                counter = item
            if node == "Idle":
                idle = item
            if node == "Overflow":
                await item.write_value(
                    ua.DataValue(
                        ua.Variant(0, ua.VariantType.UInt64),
                        StatusCode=ua.StatusCode(0x480),
                    )
                )

        async def resume_on_read(event, service):
            if any(
                op.NodeId == ua.NodeId("Resume", hvac)
                and op.AttributeId == ua.AttributeIds.Value
                for op in event.request_params.NodesToRead
            ):
                await idle.write_value(ua.Variant(8, ua.VariantType.UInt64))

        server.subscribe_server_callback(CallbackType.PostRead, resume_on_read)

        async def tick():
            value = 2**53 + 1
            while True:
                await asyncio.sleep(0.025)
                value += 1
                await counter.write_value(ua.Variant(value, ua.VariantType.UInt64))

    async with server:
        ticker = asyncio.create_task(tick()) if navigation else None
        try:
            yield f"opc.tcp://127.0.0.1:{server.bserver.port}/"
        finally:
            if ticker is not None:
                ticker.cancel()
                with suppress(asyncio.CancelledError):
                    await ticker
