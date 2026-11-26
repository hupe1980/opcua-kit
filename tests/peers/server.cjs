// Ephemeral node-opcua peer for tests/capture_peer.py. All PKI lives in cwd.
const fs = require("node:fs");
const path = require("node:path");
const { OPCUAServer, OPCUACertificateManager, SecurityPolicy, MessageSecurityMode,
        DataType, Variant, VariantArrayType, StatusCode, StatusCodes, AttributeIds, BrowseRequest, BrowseResponse,
        BrowseNextRequest, BrowseNextResponse, ReadRequest, makeEUInformation } = require("node-opcua");

async function main() {
  const label = process.argv[2];
  const maxRead = { limit1: 1, limit2: 2 }[label];
  const pki = new OPCUACertificateManager({ rootFolder: path.resolve(label + "-server-pki") });
  const server = new OPCUAServer({
    port: 0, host: "127.0.0.1", hostname: "127.0.0.1",
    serverInfo: { applicationUri: label === "other" ? "urn:fixture:other" : "urn:fixture:server" },
    certificateFile: path.resolve("server.pem"), privateKeyFile: path.resolve("server.key"),
    serverCertificateManager: pki,
    serverCapabilities: maxRead ? { operationLimits: { maxNodesPerRead: maxRead } } : undefined,
    userCertificateManager: new OPCUACertificateManager({ rootFolder: path.resolve(label + "-user-pki") }),
    securityModes: [MessageSecurityMode.None, MessageSecurityMode.SignAndEncrypt],
    securityPolicies: [SecurityPolicy.None, SecurityPolicy.Basic256Sha256],
  });
  await server.initialize();
  await pki.trustCertificate(fs.readFileSync("client.der"));
  const space = server.engine.addressSpace;
  // The contract deliberately has no knowledge of these server-assigned indexes.
  space.registerNamespace("urn:fixture:other");
  const order = ["reordered", "limit2"].includes(label) ? ["types", "hvac"] : ["hvac", "types"];
  for (const name of order) space.registerNamespace("urn:fixture:" + name);
  const ns = space.getNamespace("urn:fixture:hvac");
  const types = space.getNamespace("urn:fixture:types");
  if (label === "navigation") {
    const root = ns.addObject({ organizedBy: space.rootFolder.objects, nodeId: "s=Navigation", browseName: "Navigation" });
    const area = ns.addObject({ componentOf: root, nodeId: "s=Area", browseName: "Area" });
    let ticks = 1;
    const counter = ns.addVariable({
      componentOf: area, nodeId: "s=Counter", browseName: "Counter", dataType: "UInt64",
      minimumSamplingInterval: 20, value: new Variant({ dataType: DataType.UInt64, arrayType: VariantArrayType.Scalar, value: [0x200000, ticks] }),
    });
    ns.addVariable({ componentOf: area, nodeId: "s=OtherCounter", browseName: { namespaceIndex: types.index, name: "Counter" },
      dataType: "UInt64", value: new Variant({ dataType: DataType.UInt64, arrayType: VariantArrayType.Scalar, value: [0, 0] }) });
    ns.addVariable({ componentOf: area, nodeId: "s=Steady", browseName: "Steady", dataType: "UInt64",
      value: new Variant({ dataType: DataType.UInt64, arrayType: VariantArrayType.Scalar, value: [0, 42] }) });
    const timer = setInterval(() => counter.setValueFromSource({ dataType: DataType.UInt64, arrayType: VariantArrayType.Scalar, value: [0x200000, ++ticks] }), 25);
    timer.unref();
    const wide = ns.addObject({ componentOf: root, nodeId: "s=Wide", browseName: "Wide" });
    for (let n = 0; n < 386; n++) ns.addObject({ componentOf: wide, browseName: "Child" + n });
    server.on("request", (request) => {
      if (request instanceof BrowseRequest) {
        request.requestedMaxReferencesPerNode = request.nodesToBrowse[0].nodeId.value === "Wide" ? 128 : 1;
      }
      if (request instanceof BrowseNextRequest) fs.appendFileSync("navigation.pages", request.releaseContinuationPoints ? "release\n" : "next\n");
    });
  }
  const temperature = types.createDataType({
    browseName: "Temperature", nodeId: "i=7401", subtypeOf: "Double", isAbstract: false,
  });
  const signal = ns.addVariable({
    organizedBy: space.rootFolder.objects, nodeId: "s=Temperature", browseName: "Temperature",
    dataType: temperature.nodeId, valueRank: -1,
    value: new Variant({ dataType: DataType.Double, value: 22.0 }),
  });
  ns.addVariable({
    propertyOf: signal, nodeId: "s=UnitProperty", browseName: { namespaceIndex: 0, name: "EngineeringUnits" },
    dataType: "EUInformation", valueRank: -1,
    value: new Variant({ dataType: DataType.ExtensionObject, value: makeEUInformation(
      ["reordered", "limit2"].includes(label) ? "FAH" : "CEL", "PRIVATE UNIT LABEL", "PRIVATE UNIT DESCRIPTION",
    ) }),
  });
  if (label === "limit1") {
    const unit = makeEUInformation("CEL", "PRIVATE UNIT LABEL", "PRIVATE UNIT DESCRIPTION");
    for (const [name, properties] of [
      ["PagedTemperature", ["DeviceTag", "EngineeringUnits"]],
      ["AmbiguousUnits", ["EngineeringUnits", "EngineeringUnits", "ZZZ"]],
    ]) {
      const variable = ns.addVariable({
        organizedBy: space.rootFolder.objects, browseName: name, nodeId: "s=" + name,
        dataType: "Double", valueRank: -1, value: new Variant({ dataType: DataType.Double, value: 22 }),
      });
      properties.forEach((property, index) => {
        ns.addVariable({
          propertyOf: variable, nodeId: "s=" + name + index, browseName: { namespaceIndex: 0, name: property },
          dataType: "EUInformation", valueRank: -1, value: new Variant({ dataType: DataType.ExtensionObject, value: unit }),
        });
      });
    }
    for (const name of ["WrongUnitType", "WrongUnitRank", "UncertainUnit"]) {
      const variable = ns.addVariable({
        organizedBy: space.rootFolder.objects, browseName: name, nodeId: "s=" + name,
        dataType: "Double", valueRank: -1, value: new Variant({ dataType: DataType.Double, value: 22 }),
      });
      const array = name === "WrongUnitRank";
      const wrongType = name === "WrongUnitType";
      const value = new Variant({
        dataType: wrongType ? DataType.String : DataType.ExtensionObject,
        arrayType: array ? VariantArrayType.Array : VariantArrayType.Scalar,
        value: wrongType ? "PRIVATE UNIT LABEL" : (array ? [unit] : unit),
      });
      const property = ns.addVariable({
        propertyOf: variable, nodeId: "s=" + name + "Property",
        browseName: { namespaceIndex: 0, name: "EngineeringUnits" },
        dataType: wrongType ? "String" : "EUInformation", valueRank: array ? 1 : -1, value,
      });
      if (name === "UncertainUnit") {
        const status = StatusCode.makeStatusCode(StatusCodes.UncertainLastUsableValue, "SemanticChanged");
        property.setValueFromSource(value, status, new Date("2020-10-25T00:45:00Z"));
      }
    }
  }
  const later = ["reordered", "uncertain", "coarse"].includes(label);
  // Use a historical Berlin clock change; receipt time comes from the running test host.
  const sourceTime = new Date(later ? "2020-10-25T01:00:00Z" : "2020-10-25T00:45:00Z");
  const status = label === "uncertain" ? StatusCodes.UncertainLastUsableValue : StatusCodes.Good;
  const meters = new Map();
  function addMeter(name, dataType, value, withUnits = true) {
    const meter = ns.addVariable({
      organizedBy: space.rootFolder.objects, nodeId: "s=" + name, browseName: name,
      dataType, valueRank: -1,
    });
    const file = label + "." + name + ".reads";
    fs.writeFileSync(file, "0");
    meters.set(meter.nodeId.toString(), { file, reads: 0 });
    meter.setValueFromSource(
      { dataType: DataType[dataType], arrayType: VariantArrayType.Scalar, value }, status, sourceTime,
    );
    if (!withUnits) return;
    ns.addVariable({
      propertyOf: meter, nodeId: "s=" + name + "Units",
      browseName: { namespaceIndex: 0, name: "EngineeringUnits" },
      dataType: "EUInformation", valueRank: -1,
      value: new Variant({ dataType: DataType.ExtensionObject, value: makeEUInformation(
        label === "wrongunit" ? "KWH" : "WHR", "", "",
      ) }),
    });
  }
  // The UInt64 stays above JavaScript's safe integer range. The second fixture
  // moves the namespace index and adds 285 kWh to both registers.
  addMeter("GridImportWh", "UInt64", [0x200000, later ? 285001 : 1]);
  addMeter("GridImportU32Wh", "UInt32", 4_000_000_001 + (later ? 285000 : 0));
  if (maxRead) addMeter("MissingUnitWh", "UInt64", [0, 42], false);
  addMeter("GridImportFloatWh", "Float", label === "coarse" ? 16777216 : (later ? 1285000 : 1000000));
  // At 2^52 + 1 the binary64 significand ends in a set bit and still resolves single Wh.
  const doubleStart = 2 ** 52 + 1;
  addMeter("GridImportDoubleWh", "Double", label === "coarse" ? 2 ** 53 : doubleStart + (later ? 285000 : 0));
  // Count actual Read service operands, independent of caching or SDK calls.
  let pagedNode;
  const logPage = (event) => fs.appendFileSync(label + ".pages", JSON.stringify([pagedNode, ...event]) + "\n");
  server.on("request", (request) => {
    if (maxRead && request instanceof BrowseRequest) {
      pagedNode = undefined;
      for (const target of request.nodesToBrowse) {
        fs.appendFileSync(label + ".browse", JSON.stringify([
          target.nodeId.toString(), target.referenceTypeId.toString(), target.browseDirection,
          target.includeSubtypes, request.requestedMaxReferencesPerNode,
        ]) + "\n");
        if (["PagedTemperature", "AmbiguousUnits"].includes(target.nodeId.value)) {
          pagedNode = target.nodeId.value;
          // Impose a smaller server-side page ceiling before node-opcua's
          // normal Browse/continuation-point manager handles the request.
          request.requestedMaxReferencesPerNode = 1;
        }
      }
    }
    if (pagedNode && request instanceof BrowseNextRequest) {
      logPage([request.releaseContinuationPoints ? "release" : "next"]);
    }
    if (request instanceof ReadRequest) {
      if (maxRead) {
        const operands = request.nodesToRead.map((r) => [r.nodeId.toString(), r.attributeId]);
        fs.appendFileSync(label + ".batches", JSON.stringify(operands) + "\n");
        // Simulate an ordinary service rejection after the client has received the first
        // chunk: reconfigure the server's real limit as the second chunk arrives.
        const reconfigured = label === "limit2" && request.nodesToRead.some((r) =>
          r.nodeId.namespace === ns.index && r.nodeId.value === "LowerLimit");
        server.engine.serverCapabilities.operationLimits.maxNodesPerRead = reconfigured ? 1 : maxRead;
      }
      for (const operand of request.nodesToRead) {
        const meter = meters.get(operand.nodeId.toString());
        if (meter && operand.attributeId === AttributeIds.Value) {
          fs.writeFileSync(meter.file, String(++meter.reads));
        }
      }
    }
  });
  server.on("response", (response) => {
    if (pagedNode && (response instanceof BrowseResponse || response instanceof BrowseNextResponse)) {
      for (const page of response.results ?? []) {
        logPage(["page", page.references.map((ref) => ref.browseName.name), Boolean(page.continuationPoint?.length)]);
      }
    }
  });
  fs.writeFileSync(label + ".indexes", JSON.stringify({ signal: ns.index, type: types.index }));
  const sensor = ns.addVariable({
    organizedBy: space.rootFolder.objects, nodeId: "s=Sensor", browseName: "Sensor",
    dataType: "String", valueRank: -1,
    value: new Variant({ dataType: DataType.String, value: "PRIVATE PROCESS VALUE" }),
  });
  // A vendor property with the same name must not satisfy the namespace-zero path.
  ns.addVariable({
    propertyOf: sensor, browseName: { namespaceIndex: ns.index, name: "EngineeringUnits" },
    dataType: "String", valueRank: -1,
    value: new Variant({ dataType: DataType.String, value: "PRIVATE VENDOR UNIT" }),
  });
  await server.start();
  fs.writeFileSync(label + ".port", String(server.endpoints[0].port));
  process.once("SIGTERM", () => server.shutdown(0));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
