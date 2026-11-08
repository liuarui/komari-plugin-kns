"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Module = require("node:module");

function response() {
  return { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = value == null ? "" : String(value); } };
}

test("admin policy, task callback, remote status, and protected URI subscription work end to end", async () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), "kns-plugin-"));
  const originalLoad = Module._load;
  const routes = new Map();
  const crons = [];
  let plugin;
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  let taskResult = null;
  let execParams = null;
  const mockServer = {
    route(method, url, handler) { routes.set(method + " " + url, handler); },
    cron(expression, handler) { crons.push({ expression, handler }); },
    async call(method, params) {
      if (method === "admin:listClients") return [{ uuid: machineUuid, name: "test-node", ipv4: "1.2.3.4", online: true, os: "linux", arch: "amd64" }];
      if (method === "admin:exec") { execParams = params; return { task_id: "task-1" }; }
      if (method === "admin:getSpecificTaskResult") return taskResult;
      throw new Error("unexpected RPC " + method);
    },
  };
  Module._load = function (request, parent, isMain) {
    if (request === "server") return mockServer;
    return originalLoad.call(this, request, parent, isMain);
  };
  global.__storageDir__ = storage;
  const target = require.resolve("../kns/index");
  delete require.cache[target];
  try {
    plugin = require(target);
    plugin.load();
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(routes.has("GET /api/onebox-bridge/state"));
    const admin = { context: { principal: { roles: ["admin"], username: "tester" } }, headers: { host: "monitor.example" } };
    const stateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, stateRes);
    const initial = JSON.parse(stateRes.body);
    assert.equal(initial.machines.length, 1);
    assert.equal(initial.machines[0].policy.deployAllowed, false);

    const policyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: true, addressMode: "ipv4" } }) }, policyRes);
    assert.equal(policyRes.statusCode, 200);
    const auditStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, auditStateRes);
    const auditState = JSON.parse(auditStateRes.body);
    assert.ok(auditState.audit.some((event) => event.action === "machine.policy.updated"));
    assert.equal(auditState.auditRetention.retentionDays, 365);
    const auditLogsRes = response();
    await routes.get("GET /api/kns/admin/logs")({ ...admin, query: { limit: "10" } }, auditLogsRes);
    const auditLogs = JSON.parse(auditLogsRes.body);
    assert.ok(auditLogs.audit.some((event) => event.action === "machine.policy.updated"));
    assert.equal(auditLogs.auditRetention.maxBytes, 16 * 1024 * 1024);

    const settingsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example" }) }, settingsRes);
    assert.equal(settingsRes.statusCode, 200);

    const denyPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: false } }) }, denyPolicyRes);
    assert.equal(denyPolicyRes.statusCode, 200);
    const deniedInstallRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "install", machineUuid, protocol: "vless", listenPort: 443, listenAddress: "::", options: { security: "reality" }, confirm: true, idempotencyKey: "denied-install-1" }) }, deniedInstallRes);
    assert.equal(deniedInstallRes.statusCode, 403);
    assert.equal(JSON.parse(deniedInstallRes.body).error.code, "deployment_not_allowed");
    assert.equal(execParams, null);
    const allowPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: true } }) }, allowPolicyRes);
    assert.equal(allowPolicyRes.statusCode, 200);

    const reverseProxyPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "komari.internal:25774", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "dual" } }) }, reverseProxyPolicyRes);
    assert.equal(reverseProxyPolicyRes.statusCode, 200, reverseProxyPolicyRes.body);
    const crossSitePolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "komari.internal:25774", origin: "https://attacker.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, crossSitePolicyRes);
    assert.equal(crossSitePolicyRes.statusCode, 403);
    assert.equal(JSON.parse(crossSitePolicyRes.body).error.code, "csrf_origin");
    const insecureSameHostPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "http://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, insecureSameHostPolicyRes);
    assert.equal(insecureSameHostPolicyRes.statusCode, 403);
    assert.equal(JSON.parse(insecureSameHostPolicyRes.body).error.code, "csrf_origin");

    const invalidNatRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({
      action: "install", machineUuid, protocol: "vless", listenPort: 443, listenAddress: "::", options: { security: "reality" },
      externalPort: 70000, confirm: true, idempotencyKey: "invalid-nat-1",
    }) }, invalidNatRes);
    assert.equal(invalidNatRes.statusCode, 400);

    const installRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({
      action: "install", machineUuid, protocol: "vless", listenPort: 443, listenAddress: "::", options: { security: "reality" },
      name: "test vless", endpointHost: "node.example.com", externalPort: 30443, tags: ["prod"], confirm: true, idempotencyKey: "test-idempotency-1",
    }) }, installRes);
    assert.equal(installRes.statusCode, 202, installRes.body);
    assert.ok(execParams.command.includes("sha256sum -c"));
    assert.ok(!fs.readFileSync(path.join(storage, "kns", "state.json"), "utf8").includes("oneTimeToken"));

    const encoded = execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1];
    const request = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    assert.equal(request.instance.options.sni, "");
    const credentialUuid = "faaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const report = {
      schema: 1, jobId: request.jobId, machineUuid, status: "succeeded", runtime: { id: "onebox-main", engine: "sing-box" },
      instances: [{ id: request.instance.id, protocol: "vless", listen: { port: 443, transport: "tcp" }, tls: { security: "reality", sni: "www.example.com", publicKey: "public-key", shortId: "01" }, credential: { type: "uuid", value: credentialUuid, flow: "xtls-rprx-vision" }, resources: [{ type: "configFragment", id: "kns-test", owned: true, shared: false }] }],
      artifactVersion: "1.4.0",
    };
    const reportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { authorization: "Bearer " + request.report.oneTimeToken, "content-type": "application/json" }, body: JSON.stringify(report) }, reportRes);
    assert.equal(reportRes.statusCode, 204);
    const duplicateReportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { "content-type": "application/json" }, body: JSON.stringify(report) }, duplicateReportRes);
    assert.equal(duplicateReportRes.statusCode, 204);
    const status = { schema: 1, runtime: { engine: "sing-box", id: "onebox-main" }, instance: { id: request.instance.id, machineUuid, protocol: "vless", installed: true, enabled: true } };
    taskResult = { exit_code: 0, stdout: "KNS_STATUS=" + JSON.stringify(status) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 10));

    const afterRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, afterRes);
    const after = JSON.parse(afterRes.body);
    assert.equal(after.jobs[0].state, "succeeded");
    assert.equal(after.instances[0].id, request.instance.id);
    assert.equal(after.instances[0].endpoint.host, "node.example.com");
    assert.equal(after.instances[0].endpoint.port, 30443);
    assert.equal(after.instances[0].nat.publicHost, "node.example.com");
    assert.equal("credential" in after.instances[0], false);

    taskResult = { exit_code: 0, stdout: "KNS_STATUS=" + JSON.stringify({ schema: 1, runtime: { engine: "sing-box", id: "onebox-main" }, instance: { id: request.instance.id, machineUuid, installed: true, enabled: true, serviceState: "active", healthLevel: "L1", uninstallPreview: { complete: true, serviceImpact: "reload" }, resources: [{ type: "runtimeService", id: "onebox", owned: false, shared: true, present: true, referenceCount: 2, action: "reload" }] } }) };
    const statusJobRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.status", machineUuid, instanceId: request.instance.id, idempotencyKey: "status-preview-1" }) }, statusJobRes);
    assert.equal(statusJobRes.statusCode, 202);
    crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const remoteStatusStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, remoteStatusStateRes);
    const remoteStatusState = JSON.parse(remoteStatusStateRes.body);
    assert.equal(remoteStatusState.instances[0].remoteStatus.uninstallPreview.complete, true);
    assert.equal(remoteStatusState.instances[0].remoteStatus.resources[0].referenceCount, 2);

    const legacyDiscoveryRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.discover", machineUuid, idempotencyKey: "legacy-discovery-1" }) }, legacyDiscoveryRes);
    assert.equal(legacyDiscoveryRes.statusCode, 202);
    assert.match(execParams.command, /kns discover/);
    const overlappingStatusRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.status", machineUuid, instanceId: request.instance.id, idempotencyKey: "status-during-discovery" }) }, overlappingStatusRes);
    assert.equal(overlappingStatusRes.statusCode, 409);
    assert.equal(JSON.parse(overlappingStatusRes.body).error.code, "runtime_busy");
    const legacyDiscovery = { schema: 1, adapterVersion: "1.4.0", runtime: { engine: "sing-box", id: "onebox-main" }, instances: [{ tag: "old-vless", protocol: "vless", listen: { port: 8443, address: "::", transport: "tcp" }, managed: false, importable: true, options: { security: "reality", sni: "www.example.com", method: "" }, reason: "" }] };
    taskResult = { exit_code: 0, stdout: "KNS_DISCOVERY=" + JSON.stringify(legacyDiscovery) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const discoveredStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, discoveredStateRes);
    const discoveredState = JSON.parse(discoveredStateRes.body);
    assert.equal(discoveredState.machines[0].discoveredNodes[0].tag, "old-vless");
    assert.equal(JSON.stringify(discoveredState).includes("credential"), false);

    const invalidTwoFactorScanRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.discover", machineUuid, twoFactorCode: "invalid", idempotencyKey: "legacy-discovery-invalid-2fa" }) }, invalidTwoFactorScanRes);
    assert.equal(invalidTwoFactorScanRes.statusCode, 400);
    assert.equal(JSON.parse(invalidTwoFactorScanRes.body).error.code, "invalid_2fa");

    const lowResourceDiscoveryRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.discover", machineUuid, idempotencyKey: "legacy-discovery-low-resource" }) }, lowResourceDiscoveryRes);
    assert.equal(lowResourceDiscoveryRes.statusCode, 202);
    assert.match(execParams.command, /KNS_RESOURCE=low_pid_headroom/);
    const lowResourceJobId = JSON.parse(lowResourceDiscoveryRes.body).job.id;
    taskResult = { exit_code: 1, stdout: "KNS_RESOURCE=low_pid_headroom" };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const lowResourceStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, lowResourceStateRes);
    const lowResourceJob = JSON.parse(lowResourceStateRes.body).jobs.find((job) => job.id === lowResourceJobId);
    assert.equal(lowResourceJob.state, "failed");
    assert.match(lowResourceJob.message, /进程额度不足/);

    const invalidTwoFactorImportRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.import", machineUuid, legacyTag: "old-vless", name: "old-vless", tags: ["prod"], endpointHost: "2.3.4.5", externalPort: 30443, confirm: true, twoFactorCode: "invalid", idempotencyKey: "legacy-import-invalid-2fa" }) }, invalidTwoFactorImportRes);
    assert.equal(invalidTwoFactorImportRes.statusCode, 400);
    assert.equal(JSON.parse(invalidTwoFactorImportRes.body).error.code, "invalid_2fa");

    const legacyImportRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.import", machineUuid, legacyTag: "old-vless", name: "old-vless", tags: ["prod"], endpointHost: "2.3.4.5", externalPort: 30443, confirm: true, idempotencyKey: "legacy-import-1" }) }, legacyImportRes);
    assert.equal(legacyImportRes.statusCode, 202, legacyImportRes.body);
    assert.match(execParams.command, /kns 'import'/);
    const legacyEncoded = execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1];
    const legacyRequest = JSON.parse(Buffer.from(legacyEncoded, "base64").toString("utf8"));
    assert.equal(legacyRequest.instance.legacyTag, "old-vless");
    const legacyCredentialUuid = "4aaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const legacyReport = {
      schema: 1, jobId: legacyRequest.jobId, machineUuid, status: "succeeded", runtime: { id: "onebox-main", engine: "sing-box" },
      instances: [{ id: legacyRequest.instance.id, legacyTag: "old-vless", protocol: "vless", listen: { port: 8443, transport: "tcp" }, tls: { security: "reality", sni: "www.example.com", publicKey: "legacy-public-key", shortId: "01" }, credential: { type: "uuid", value: legacyCredentialUuid, flow: "xtls-rprx-vision" }, resources: [{ type: "legacyConfigFragment", id: "old-vless", owned: false, shared: true }] }],
      artifactVersion: "1.4.0",
    };
    const legacyReportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { authorization: "Bearer " + legacyRequest.report.oneTimeToken, "content-type": "application/json" }, body: JSON.stringify(legacyReport) }, legacyReportRes);
    assert.equal(legacyReportRes.statusCode, 204);
    taskResult = { exit_code: 0, stdout: "KNS_DISCOVERY=" + JSON.stringify(legacyDiscovery) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const afterLegacyImportRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, afterLegacyImportRes);
    const afterLegacyImport = JSON.parse(afterLegacyImportRes.body);
    const importedLegacy = afterLegacyImport.instances.find((item) => item.legacyTag === "old-vless");
    assert.ok(importedLegacy);
    assert.equal(importedLegacy.managedBy, "legacy_import");
    assert.equal(importedLegacy.readOnly, true);
    assert.equal(importedLegacy.endpoint.host, "2.3.4.5");
    assert.equal(importedLegacy.nat.externalPort, 30443);
    assert.equal("credential" in importedLegacy, false);
    assert.equal(JSON.stringify(afterLegacyImport).includes(legacyCredentialUuid), false);
    const importedDisableRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "disable", machineUuid, instanceId: importedLegacy.id, confirm: true, idempotencyKey: "legacy-disable-denied" }) }, importedDisableRes);
    assert.equal(importedDisableRes.statusCode, 409);
    assert.equal(JSON.parse(importedDisableRes.body).error.code, "legacy_instance_readonly");

    const natCollisionRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({
      action: "install", machineUuid, protocol: "vless", listenPort: 9443, listenAddress: "::", options: { security: "reality" },
      name: "colliding nat", endpointHost: "node.example.com", externalPort: 30443, confirm: true, idempotencyKey: "nat-collision-1",
    }) }, natCollisionRes);
    assert.equal(natCollisionRes.statusCode, 409);
    assert.equal(JSON.parse(natCollisionRes.body).error.code, "nat_mapping_conflict");

    const exportRes = response();
    const exportPassphrase = "correct horse battery staple 2026";
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "backup.export", passphrase: exportPassphrase }) }, exportRes);
    assert.equal(exportRes.statusCode, 200);
    const envelope = JSON.parse(exportRes.body);
    assert.equal(envelope.format, "KNS-ENCRYPTED-EXPORT");
    assert.equal(envelope.cipher.name, "AES-256-GCM");
    assert.equal(exportRes.body.includes(credentialUuid), false);
    const exportKey = crypto.pbkdf2Sync(exportPassphrase, Buffer.from(envelope.kdf.salt, "hex"), envelope.kdf.iterations, 32, "sha256");
    const decipher = crypto.createDecipheriv("aes-256-gcm", exportKey, Buffer.from(envelope.cipher.iv, "hex"));
    decipher.setAAD(Buffer.from(envelope.cipher.aad, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.cipher.tag, "hex"));
    const clearExport = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.cipher.data, "base64")), decipher.final()]).toString("utf8"));
    assert.equal(clearExport.format, "KNS-ENCRYPTED-EXPORT");
    assert.ok(clearExport.masterKey);
    assert.equal(clearExport.state.instances[0].id, request.instance.id);
    assert.equal(JSON.stringify(clearExport.state).includes(credentialUuid), false);

    const badExportRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "backup.export", passphrase: "short" }) }, badExportRes);
    assert.equal(badExportRes.statusCode, 400);

    const badImportRes = response();
    await routes.get("POST /api/kns/admin/import")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ envelope, passphrase: "wrong passphrase 2026" }) }, badImportRes);
    assert.equal(badImportRes.statusCode, 400);
    const changedSettingsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterTarget: "loon" }) }, changedSettingsRes);
    assert.equal(changedSettingsRes.statusCode, 200);
    assert.equal(JSON.parse(changedSettingsRes.body).settings.converterTarget, "loon");
    const invalidConverterTargetRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterTarget: "unsupported" }) }, invalidConverterTargetRes);
    assert.equal(invalidConverterTargetRes.statusCode, 400);
    const importRes = response();
    await routes.get("POST /api/kns/admin/import")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ envelope, passphrase: exportPassphrase }) }, importRes);
    assert.equal(importRes.statusCode, 200, importRes.body);
    const importedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, importedStateRes);
    assert.equal(JSON.parse(importedStateRes.body).settings.converterTarget, "clash");

    const postImportSettingsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterTarget: "loon" }) }, postImportSettingsRes);
    assert.equal(postImportSettingsRes.statusCode, 200);

    const profileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.create", name: "test", formats: ["uri", "mihomo-full"], machineUuids: [machineUuid], excludeMachineUuids: [], protocols: ["vless"], includeTags: ["prod"], addressMode: "ipv4", sortBy: "machine" }) }, profileRes);
    const created = JSON.parse(profileRes.body);
    const url = new URL(created.tokenUrl);
    assert.deepEqual(Object.keys(created.subscriptionUrls).sort(), ["mihomo-full", "uri"]);
    assert.equal(new URL(created.converterUrl).searchParams.get("url"), created.tokenUrl);
    assert.equal(new URL(created.converterUrl).searchParams.get("target"), "loon");
    assert.equal(new URL(created.converterUrls.clash).searchParams.get("target"), "clash");
    assert.equal(new URL(created.converterUrls.quanx).searchParams.get("url"), created.tokenUrl);
    assert.equal(Object.keys(created.converterUrls).length, 22);
    const profileStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, profileStateRes);
    const profileState = JSON.parse(profileStateRes.body).profiles[0];
    assert.deepEqual(profileState.machineUuids, [machineUuid]);
    assert.deepEqual(profileState.protocols, ["vless"]);
    assert.equal(profileState.addressMode, "ipv4");
    assert.equal(profileState.sortBy, "machine");
    assert.equal(profileState.tokens.length, 1);
    assert.equal("salt" in profileState.tokens[0], false);
    assert.equal("hash" in profileState.tokens[0], false);
    let subRes;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      subRes = response();
      await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, subRes);
      if (subRes.statusCode === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(subRes.statusCode, 200);
    assert.match(subRes.body, /^vless:\/\//);
    assert.match(subRes.body, new RegExp(credentialUuid));
    assert.match(subRes.body, new RegExp(legacyCredentialUuid));
    assert.equal(subRes.headers["x-kns-snapshot-success"], "2");
    assert.ok(subRes.headers["x-kns-snapshot-generated-at"]);
    assert.equal(subRes.headers.link, '<https://github.com/liuarui/komari-plugin-kns/tree/v1.1.5>; rel="source"');
    assert.equal(subRes.headers["x-kns-license"], "AGPL-3.0-only");
    const singboxOnlyProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.create", name: "singbox-only", formats: ["singbox-full"] }) }, singboxOnlyProfileRes);
    const singboxOnly = JSON.parse(singboxOnlyProfileRes.body);
    assert.deepEqual(Object.keys(singboxOnly.subscriptionUrls), ["singbox-full"]);
    assert.equal(new URL(singboxOnly.nativeUrl).searchParams.get("format"), "singbox-full");
    assert.equal(singboxOnly.tokenUrl, "");
    assert.equal(singboxOnly.converterUrl, "");
    const addTokenRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.token.create", profileId: profileState.id }) }, addTokenRes);
    assert.equal(addTokenRes.statusCode, 201, addTokenRes.body);
    const addedToken = JSON.parse(addTokenRes.body);
    const addedUrl = new URL(addedToken.tokenUrl);
    const addedGet = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(addedUrl.searchParams), headers: {} }, addedGet);
    assert.equal(addedGet.statusCode, 200);
    crons.filter((item) => item.expression === "@every 1m").at(-1).handler();
    const tokenStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, tokenStateRes);
    const profileWithTokens = JSON.parse(tokenStateRes.body).profiles.find((item) => item.id === profileState.id);
    assert.equal(profileWithTokens.tokens.length, 2);
    assert.ok(profileWithTokens.tokens.find((item) => item.id === addedToken.tokenId).accessCount >= 1);
    const newestAuditPageRes = response();
    await routes.get("GET /api/kns/admin/logs")({ ...admin, query: { limit: "2" } }, newestAuditPageRes);
    const newestAuditPage = JSON.parse(newestAuditPageRes.body);
    assert.equal(newestAuditPage.audit.length, 2);
    assert.equal(newestAuditPage.hasMore, true);
    assert.equal(newestAuditPage.nextCursor, newestAuditPage.audit[1].id);
    const olderAuditPageRes = response();
    await routes.get("GET /api/kns/admin/logs")({ ...admin, query: { limit: "2", before: newestAuditPage.nextCursor } }, olderAuditPageRes);
    const olderAuditPage = JSON.parse(olderAuditPageRes.body);
    assert.equal(olderAuditPage.audit.length, 2);
    assert.ok(olderAuditPage.audit.every((event) => !newestAuditPage.audit.some((newer) => newer.id === event.id)));

    const expiringProfileRes = response();
    const profileExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.create", name: "expiring", formats: ["uri"], expiresAt: profileExpiry }) }, expiringProfileRes);
    const expiringProfile = JSON.parse(expiringProfileRes.body);
    const expiringStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, expiringStateRes);
    const expiringRecord = JSON.parse(expiringStateRes.body).profiles.find((item) => item.id === expiringProfile.profile.id);
    assert.equal(expiringRecord.tokens[0].expiresAt, profileExpiry);
    const cappedTokenRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.token.create", profileId: expiringProfile.profile.id, expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() }) }, cappedTokenRes);
    assert.equal(cappedTokenRes.statusCode, 201);
    const cappedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, cappedStateRes);
    const cappedRecord = JSON.parse(cappedStateRes.body).profiles.find((item) => item.id === expiringProfile.profile.id);
    assert.ok(cappedRecord.tokens.every((item) => item.expiresAt === profileExpiry));
    const snapshotFiles = fs.readdirSync(path.join(storage, "kns", "subscriptions"));
    assert.ok(snapshotFiles.length >= 1);
    for (const filename of snapshotFiles) assert.equal(fs.readFileSync(path.join(storage, "kns", "subscriptions", filename), "utf8").includes(credentialUuid), false);
    for (const filename of snapshotFiles) assert.equal(fs.readFileSync(path.join(storage, "kns", "subscriptions", filename), "utf8").includes(legacyCredentialUuid), false);
    const subscriptionModule = require("../kns/subscription");
    const originalBuild = subscriptionModule.buildSubscription;
    subscriptionModule.buildSubscription = () => { throw new Error("GET must use the stored snapshot"); };
    try {
      const cachedRes = response();
      await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, cachedRes);
      assert.equal(cachedRes.statusCode, 200);
      assert.equal(cachedRes.body, subRes.body);
    } finally { subscriptionModule.buildSubscription = originalBuild; }
    const revokeTokenRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.token.revoke", profileId: profileState.id, tokenId: addedToken.tokenId }) }, revokeTokenRes);
    assert.equal(revokeTokenRes.statusCode, 200);
    const revokedTokenGet = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(addedUrl.searchParams), headers: {} }, revokedTokenGet);
    assert.equal(revokedTokenGet.statusCode, 404);
    const rotateTokenRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.rotate", profileId: profileState.id, graceSeconds: 60 }) }, rotateTokenRes);
    assert.equal(rotateTokenRes.statusCode, 200, rotateTokenRes.body);
    const rotatedToken = JSON.parse(rotateTokenRes.body);
    const rotatedUrl = new URL(rotatedToken.tokenUrl);
    const oldDuringGrace = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, oldDuringGrace);
    assert.equal(oldDuringGrace.statusCode, 200);
    const newAfterRotation = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(rotatedUrl.searchParams), headers: {} }, newAfterRotation);
    assert.equal(newAfterRotation.statusCode, 200);
    const hideRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.publish.update", instanceId: request.instance.id, publish: false }) }, hideRes);
    assert.equal(hideRes.statusCode, 200);
    const hideImportedRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.publish.update", instanceId: importedLegacy.id, publish: false }) }, hideImportedRes);
    assert.equal(hideImportedRes.statusCode, 200);
    const staleRes = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, staleRes);
    assert.equal(staleRes.statusCode, 503);
    assert.equal(staleRes.headers["retry-after"], "2");
    let refreshedRes;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      refreshedRes = response();
      await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, refreshedRes);
      if (refreshedRes.statusCode === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(refreshedRes.statusCode, 200);
    assert.equal(refreshedRes.body, "");
    const updateProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.update", profileId: profileState.id, machineUuids: [], excludeMachineUuids: [machineUuid], protocols: [], includeTags: [], addressMode: "dual", sortBy: "endpoint" }) }, updateProfileRes);
    assert.equal(updateProfileRes.statusCode, 200, updateProfileRes.body);
    const updatedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, updatedStateRes);
    const updatedProfile = JSON.parse(updatedStateRes.body).profiles[0];
    assert.equal(updatedProfile.machineUuids, null);
    assert.deepEqual(updatedProfile.excludeMachineUuids, [machineUuid]);
    assert.equal(updatedProfile.addressMode, "dual");
    assert.equal(updatedProfile.sortBy, "endpoint");
    const persisted = fs.readFileSync(path.join(storage, "kns", "state.json"), "utf8");
    assert.equal(persisted.includes(credentialUuid), false);
    assert.equal(persisted.includes(request.report.oneTimeToken), false);
    assert.equal(persisted.includes("callbackTokenHash"), false);
    const badRes = response();
    await routes.get("GET /api/kns/sub")({ query: { profile: url.searchParams.get("profile"), format: "uri", token: "wrong" }, headers: {} }, badRes);
    assert.equal(badRes.statusCode, 404);
    const revokeRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.revoke", profileId: url.searchParams.get("profile") }) }, revokeRes);
    assert.equal(revokeRes.statusCode, 200);
    const revokedRes = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, revokedRes);
    assert.equal(revokedRes.statusCode, 403);
  } finally {
    if (plugin) plugin.unload();
    Module._load = originalLoad;
    delete global.__storageDir__;
    fs.rmSync(storage, { recursive: true, force: true });
    delete require.cache[target];
  }
});
