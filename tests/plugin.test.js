"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const secrets = require("../kns/crypto");
const Module = require("node:module");

function response() {
  return { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = value == null ? "" : String(value); } };
}

test("converter links reject unsafe persisted settings and require an HTTPS source", () => {
  const source = fs.readFileSync(path.join(__dirname, "../kns/index.js"), "utf8");
  const context = { URLConstructor: URL, CONVERTER_TARGETS: new Set(["clash", "loon"]), CONVERTER_RULE_PRESETS: { "acl4ssr-mini": "config/ACL4SSR_Online_Mini.ini", "acl4ssr-full": "config/ACL4SSR_Online_Full.ini" } };
  require("node:vm").runInNewContext(source.slice(source.indexOf("function parseConverterUrl("), source.indexOf("function buildProfileTokenLinks(")), context);
  const sourceUrl = "https://monitor.example/api/kns/sub?token=test-token&format=uri";
  for (const converterUrl of [undefined, "", "http://converter.example/sub", "http://localhost:25500/sub", "https://user:pass@converter.example/sub", "https://converter.example/sub#fragment", "invalid"]) {
    const state = { settings: { converterUrl } };
    assert.equal(context.buildConverterUrl(state, sourceUrl), "");
    assert.deepEqual(Object.keys(context.buildConverterUrls(state, sourceUrl)), []);
  }
  const state = { settings: { converterUrl: "https://converter.example/sub?emoji=true" } };
  const converted = new URL(context.buildConverterUrl(state, sourceUrl, "loon"));
  assert.equal(converted.protocol, "https:");
  assert.equal(converted.searchParams.get("url"), sourceUrl);
  assert.equal(converted.searchParams.get("target"), "loon");
  assert.equal(converted.searchParams.get("emoji"), "true");
  assert.equal(context.buildConverterUrl(state, sourceUrl.replace("https:", "http:")), "");
});

test("onebox-bridge leftover migration keeps URI format and serves on-demand native formats", async () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), "kns-legacy-formats-"));
  const originalLoad = Module._load;
  const routes = new Map();
  const crons = [];
  let plugin;
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  const mockServer = {
    route(method, url, handler) { routes.set(method + " " + url, handler); },
    cron(expression, handler) { crons.push({ expression, handler }); },
    async call(method) {
      if (method === "admin:listClients") return [{ uuid: machineUuid, name: "legacy-node" }];
      if (method === "common:getNodesLatestStatus") return { [machineUuid]: { online: true } };
      return [];
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
    fs.writeFileSync(path.join(storage, "onebox-bridge.json"), JSON.stringify({
      token: "a".repeat(32),
      records: [{ clientUuid: machineUuid, clientName: "legacy-node", link: "vless://example", state: "published" }],
    }));
    plugin = require(target);
    plugin.load();
    const admin = { context: { principal: { roles: ["admin"], username: "tester" } }, headers: { host: "monitor.example" } };
    const stateRes = { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } };
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, stateRes);
    const profile = JSON.parse(stateRes.body).profiles.find((item) => item.id === "legacy-default");
    assert.deepEqual(profile.formats, ["uri"]);
    const nativeRes = response();
    await routes.get("GET /api/kns/sub")({ query: { profile: "legacy-default", format: "mihomo-full", token: "a".repeat(32) }, headers: {} }, nativeRes);
    assert.equal(nativeRes.statusCode, 200);
    assert.match(nativeRes.body, /^proxies:/);
    let uriRes;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      uriRes = response();
      await routes.get("GET /api/kns/sub")({ query: { profile: "legacy-default", format: "uri", token: "a".repeat(32) }, headers: {} }, uriRes);
      if (uriRes.statusCode === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(uriRes.statusCode, 200, uriRes.body);
    assert.match(uriRes.body, /^vless:\/\/example/);
  } finally {
    if (plugin) plugin.unload();
    Module._load = originalLoad;
    delete global.__storageDir__;
    fs.rmSync(storage, { recursive: true, force: true });
    delete require.cache[target];
  }
});

test("existing leftover profiles drop empty native formats on load", async () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), "kns-legacy-constrain-"));
  const originalLoad = Module._load;
  const routes = new Map();
  let plugin;
  const mockServer = { route(method, url, handler) { routes.set(method + " " + url, handler); }, cron() {}, async call() { return []; } };
  Module._load = function (request, parent, isMain) {
    if (request === "server") return mockServer;
    return originalLoad.call(this, request, parent, isMain);
  };
  global.__storageDir__ = storage;
  const target = require.resolve("../kns/index");
  delete require.cache[target];
  try {
    const { createStore } = require("../kns/store");
    const store = createStore(storage);
    const state = store.initialState();
    state.pluginVersion = require("../komari-plugin.json").version;
    const token = secrets.tokenRecord("b".repeat(32));
    state.profiles.push({ id: "legacy-default", name: "旧版默认订阅", ...token, createdAt: new Date().toISOString(), formats: ["uri", "mihomo-full", "singbox-full"], instanceIds: [], includeTags: [], excludeUnhealthy: false, legacy: true });
    store.write(state);
    plugin = require(target);
    plugin.load();
    const admin = { context: { principal: { roles: ["admin"], username: "tester" } }, headers: { host: "monitor.example" } };
    const stateRes = { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } };
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, stateRes);
    assert.deepEqual(JSON.parse(stateRes.body).profiles.find((item) => item.id === "legacy-default").formats, ["uri"]);
    const nativeRes = { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } };
    await routes.get("GET /api/kns/sub")({ query: { profile: "legacy-default", format: "singbox-full", token: "b".repeat(32) }, headers: {} }, nativeRes);
    assert.equal(nativeRes.statusCode, 200);
    assert.match(nativeRes.body, /"outbounds"/);
  } finally {
    if (plugin) plugin.unload();
    Module._load = originalLoad;
    delete global.__storageDir__;
    fs.rmSync(storage, { recursive: true, force: true });
    delete require.cache[target];
  }
});

test("admin policy, task callback, remote status, and protected URI subscription work end to end", async () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), "kns-plugin-"));
  const originalLoad = Module._load;
  const routes = new Map();
  const crons = [];
  let plugin;
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  let taskResult = null;
  let execParams = null;
  let execCalls = 0;
  let nextExecError = null;
  let failListClients = false;
  let onlineStatus = true;
  const mockServer = {
    route(method, url, handler) { routes.set(method + " " + url, handler); },
    cron(expression, handler) { crons.push({ expression, handler }); },
    async call(method, params) {
      if (method === "admin:listClients") { if (failListClients) throw new Error("simulated probe sync failure"); return [{ uuid: machineUuid, name: "test-node", ipv4: "1.2.3.4", os: "linux", arch: "amd64" }]; }
      if (method === "common:getNodesLatestStatus") return { [machineUuid]: { online: onlineStatus } };
      if (method === "admin:exec") { execParams = params; execCalls += 1; if (nextExecError) { const error = nextExecError; nextExecError = null; throw error; } return { task_id: "task-1" }; }
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
    assert.equal(initial.machines[0].policy.deployAllowed, true);
    assert.equal(initial.machines[0].online, true, "live status should come from Komari presence RPC, not admin:listClients");
    assert.equal(initial.settings.setupComplete, false);
    assert.equal(initial.settings.converterUrl, "");

    const setupGateRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: true } }) }, setupGateRes);
    assert.equal(setupGateRes.statusCode, 409);
    assert.equal(JSON.parse(setupGateRes.body).error.code, "setup_required");

    const invalidSetupRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "setup.complete", publicBaseUrl: "http://monitor.example", defaultNode: { protocol: "vless", listenPort: 443, listenAddress: "::" }, autoProvisionNewProbes: false }) }, invalidSetupRes);
    assert.equal(invalidSetupRes.statusCode, 400);
    assert.equal(JSON.parse(invalidSetupRes.body).error.code, "invalid_public_url");

    const unconfirmedAutomationRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "setup.complete", publicBaseUrl: "https://monitor.example", defaultNode: { protocol: "vless", listenPort: 443, listenAddress: "::" }, autoProvisionNewProbes: true }) }, unconfirmedAutomationRes);
    assert.equal(unconfirmedAutomationRes.statusCode, 400);
    assert.equal(JSON.parse(unconfirmedAutomationRes.body).error.code, "auto_provision_confirmation_required");

    failListClients = true;
    const syncFailureRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "setup.complete", publicBaseUrl: "https://monitor.example", defaultNode: { protocol: "vless", listenPort: 443, listenAddress: "::" }, autoProvisionNewProbes: false }) }, syncFailureRes);
    assert.equal(syncFailureRes.statusCode, 503);
    assert.equal(JSON.parse(syncFailureRes.body).error.code, "probe_sync_required");
    const failedSetupStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, failedSetupStateRes);
    const failedSetupState = JSON.parse(failedSetupStateRes.body);
    assert.equal(failedSetupState.settings.setupComplete, false);
    assert.equal(failedSetupState.profiles.length, 0);
    failListClients = false;

    const setupRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "setup.complete", publicBaseUrl: "https://monitor.example", defaultNode: { protocol: "vless", listenPort: 443, listenAddress: "::" }, autoProvisionNewProbes: false }) }, setupRes);
    assert.equal(setupRes.statusCode, 200, setupRes.body);
    const setupResult = JSON.parse(setupRes.body);
    assert.equal(setupResult.baselineMachineCount, 1);
    assert.ok(setupResult.subscriptionUrls.uri);
    assert.ok(setupResult.subscriptionUrls["mihomo-full"]);
    assert.equal(setupResult.converterUrl, "");
    assert.deepEqual(setupResult.converterUrls, {});
    const completedSetupStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, completedSetupStateRes);
    const completedSetupState = JSON.parse(completedSetupStateRes.body);
    assert.equal(completedSetupState.settings.setupComplete, true);
    assert.equal(completedSetupState.settings.autoProvisionNewProbes, false);
    assert.deepEqual(completedSetupState.settings.autoProvisionBaselineUuids, [machineUuid]);
    const defaultProfile = completedSetupState.profiles.find((item) => item.name === "KNS 默认订阅");
    assert.equal(defaultProfile.tokens.length, 1);
    assert.ok(completedSetupState.audit.some((event) => event.action === "setup.completed"));
    const repeatSetupRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "setup.complete", publicBaseUrl: "https://monitor.example", defaultNode: { protocol: "vless", listenPort: 443, listenAddress: "::" }, autoProvisionNewProbes: false }) }, repeatSetupRes);
    assert.equal(repeatSetupRes.statusCode, 200);
    assert.equal(JSON.parse(repeatSetupRes.body).alreadyComplete, true);
    const repeatedSetupStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, repeatedSetupStateRes);
    assert.equal(JSON.parse(repeatedSetupStateRes.body).profiles.find((item) => item.name === "KNS 默认订阅").tokens.length, 1);

    const policyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: true, addressMode: "ipv4" }, expectedRevision: completedSetupState.revision }) }, policyRes);
    assert.equal(policyRes.statusCode, 200);
    const staleWriteRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { deployAllowed: false }, expectedRevision: completedSetupState.revision }) }, staleWriteRes);
    assert.equal(staleWriteRes.statusCode, 409);
    assert.equal(JSON.parse(staleWriteRes.body).error.code, "state_revision_conflict");
    assert.ok(JSON.parse(staleWriteRes.body).error.currentRevision > JSON.parse(staleWriteRes.body).error.expectedRevision);
    // An unrelated machine update must not block editing the original profile.
    const profileEditBody = { action: "profile.update", profileId: defaultProfile.id, name: "隔离后的订阅", expectedRevision: completedSetupState.revision, expectedEditVersion: defaultProfile.editVersion };
    const independentProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(profileEditBody) }, independentProfileRes);
    assert.equal(independentProfileRes.statusCode, 200, independentProfileRes.body);
    const conflictingProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ ...profileEditBody, name: "过期草稿" }) }, conflictingProfileRes);
    assert.equal(conflictingProfileRes.statusCode, 409);
    assert.equal(JSON.parse(conflictingProfileRes.body).error.code, "state_revision_conflict");
    const removedProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ ...profileEditBody, profileId: "missing-profile" }) }, removedProfileRes);
    assert.equal(removedProfileRes.statusCode, 409);
    const auditStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, auditStateRes);
    const auditState = JSON.parse(auditStateRes.body);
    assert.ok(auditState.audit.some((event) => event.action === "machine.policy.updated"));
    assert.equal(auditState.auditRetention.retentionDays, 365);
    const connectionBody = { action: "settings.update", publicBaseUrl: "https://monitor.example", privateSite: true, expectedRevision: completedSetupState.revision, expectedEditVersion: completedSetupState.settings.connectionEditVersion };
    const independentConnectionRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(connectionBody) }, independentConnectionRes);
    assert.equal(independentConnectionRes.statusCode, 200, independentConnectionRes.body);
    const conflictingConnectionRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ ...connectionBody, privateSite: false }) }, conflictingConnectionRes);
    assert.equal(conflictingConnectionRes.statusCode, 409);
    const independentDefaultsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.defaults.update", defaultNode: completedSetupState.settings.defaultNode, autoProvisionNewProbes: false, expectedRevision: completedSetupState.revision, expectedEditVersion: completedSetupState.settings.defaultsEditVersion }) }, independentDefaultsRes);
    assert.equal(independentDefaultsRes.statusCode, 200, independentDefaultsRes.body);
    const restoreConnectionRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", privateSite: false }) }, restoreConnectionRes);
    assert.equal(restoreConnectionRes.statusCode, 200, restoreConnectionRes.body);
    const policyVersion = auditState.machines.find((item) => item.uuid === machineUuid).policyVersion;
    const policyVersionBody = { action: "machine.policy.update", machineUuid, policy: { addressMode: "auto" }, expectedRevision: completedSetupState.revision, expectedEditVersion: policyVersion };
    const independentPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(policyVersionBody) }, independentPolicyRes);
    assert.equal(independentPolicyRes.statusCode, 200, independentPolicyRes.body);
    const conflictingPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ ...policyVersionBody, policy: { addressMode: "ipv6" } }) }, conflictingPolicyRes);
    assert.equal(conflictingPolicyRes.statusCode, 409);
    const auditLogsRes = response();
    await routes.get("GET /api/kns/admin/logs")({ ...admin, query: { limit: "10" } }, auditLogsRes);
    const auditLogs = JSON.parse(auditLogsRes.body);
    assert.ok(auditLogs.audit.some((event) => event.action === "machine.policy.updated"));
    assert.equal(auditLogs.auditRetention.maxBytes, 16 * 1024 * 1024);

    const settingsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example" }) }, settingsRes);
    assert.equal(settingsRes.statusCode, 200);

    const unconfirmedDefaultsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.defaults.update", defaultNode: { protocol: "vless", listenPort: 8443, listenAddress: "::" }, autoProvisionNewProbes: true }) }, unconfirmedDefaultsRes);
    assert.equal(unconfirmedDefaultsRes.statusCode, 400);
    assert.equal(JSON.parse(unconfirmedDefaultsRes.body).error.code, "auto_provision_confirmation_required");
    const confirmedDefaultsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.defaults.update", defaultNode: { protocol: "vless", listenPort: 8443, listenAddress: "::" }, autoProvisionNewProbes: true, confirmAutoProvision: true }) }, confirmedDefaultsRes);
    assert.equal(confirmedDefaultsRes.statusCode, 200, confirmedDefaultsRes.body);
    const disabledDefaultsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.defaults.update", defaultNode: { protocol: "vless", listenPort: 8443, listenAddress: "::" }, autoProvisionNewProbes: false }) }, disabledDefaultsRes);
    assert.equal(disabledDefaultsRes.statusCode, 200);

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
    const fetchMetadataProxyPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "komari.internal:25774", origin: "https://panel.5970000.xyz", "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, fetchMetadataProxyPolicyRes);
    assert.equal(fetchMetadataProxyPolicyRes.statusCode, 200, fetchMetadataProxyPolicyRes.body);
    const crossSitePolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "komari.internal:25774", origin: "https://attacker.example", "sec-fetch-site": "cross-site", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, crossSitePolicyRes);
    assert.equal(crossSitePolicyRes.statusCode, 403);
    assert.equal(JSON.parse(crossSitePolicyRes.body).error.code, "csrf_origin");
    const missingOriginRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "komari.internal:25774", "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, missingOriginRes);
    assert.equal(missingOriginRes.statusCode, 403);
    assert.equal(JSON.parse(missingOriginRes.body).error.code, "csrf_origin");
    const insecureSameHostPolicyRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "http://monitor.example", "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.policy.update", machineUuid, policy: { addressMode: "ipv4" } }) }, insecureSameHostPolicyRes);
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
      artifactVersion: "1.8.0",
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

    const jobsBeforeRename = after.jobs.length;
    const renameRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.metadata.update", instanceId: request.instance.id, name: "renamed for display" }) }, renameRes);
    assert.equal(renameRes.statusCode, 200);
    const renamedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, renamedStateRes);
    const renamedState = JSON.parse(renamedStateRes.body);
    assert.equal(renamedState.instances.find((item) => item.id === request.instance.id).name, "renamed for display");
    assert.equal(renamedState.jobs.length, jobsBeforeRename);

    taskResult = { exit_code: 0, stdout: "KNS_STATUS=" + JSON.stringify({ schema: 1, runtime: { engine: "sing-box", id: "onebox-main" }, instance: { id: request.instance.id, machineUuid, installed: true, enabled: true, serviceState: "active", healthLevel: "L1", uninstallPreview: { complete: true, serviceImpact: "reload" }, resources: [{ type: "runtimeService", id: "onebox", owned: false, shared: true, present: true, referenceCount: 2, action: "reload" }] } }) };
    const callsBeforeBadStatus = execCalls;
    const invalidStatusRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.status", machineUuid, instanceId: request.instance.id, twoFactorCode: "bad", idempotencyKey: "status-preview-1" }) }, invalidStatusRes);
    assert.equal(invalidStatusRes.statusCode, 400);
    assert.equal(JSON.parse(invalidStatusRes.body).error.code, "invalid_2fa");
    assert.equal(execCalls, callsBeforeBadStatus);
    const afterInvalidStatusRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, afterInvalidStatusRes);
    const afterInvalidStatus = JSON.parse(afterInvalidStatusRes.body);
    assert.equal(afterInvalidStatus.jobs.length, renamedState.jobs.length);
    assert.equal(afterInvalidStatus.audit.filter((event) => event.action === "instance.status.requested").length, renamedState.audit.filter((event) => event.action === "instance.status.requested").length);
    const statusJobRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.status", machineUuid, instanceId: request.instance.id, twoFactorCode: "123456", idempotencyKey: "status-preview-1" }) }, statusJobRes);
    assert.equal(statusJobRes.statusCode, 202);
    assert.equal(execParams["2fa_code"], "123456");
    assert.equal(execCalls, callsBeforeBadStatus + 1);
    crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const remoteStatusStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, remoteStatusStateRes);
    const remoteStatusState = JSON.parse(remoteStatusStateRes.body);
    assert.equal(remoteStatusState.instances[0].remoteStatus.uninstallPreview.complete, true);
    assert.equal(remoteStatusState.instances[0].remoteStatus.resources[0].referenceCount, 2);
    assert.match(remoteStatusState.instances[0].remoteStatus.uninstallPreview.version, /^[a-f0-9]{64}$/);
    const changedUninstallPreviewRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "uninstall", machineUuid, instanceId: request.instance.id, previewVersion: "0".repeat(64), confirm: true, idempotencyKey: "uninstall-stale-preview-1", expectedRevision: remoteStatusState.revision }) }, changedUninstallPreviewRes);
    assert.equal(changedUninstallPreviewRes.statusCode, 409);
    assert.equal(JSON.parse(changedUninstallPreviewRes.body).error.code, "uninstall_preview_changed");

    const legacyDiscoveryRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "machine.discover", machineUuid, idempotencyKey: "legacy-discovery-1" }) }, legacyDiscoveryRes);
    assert.equal(legacyDiscoveryRes.statusCode, 202);
    assert.match(execParams.command, /kns discover/);
    const overlappingStatusRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "instance.status", machineUuid, instanceId: request.instance.id, idempotencyKey: "status-during-discovery" }) }, overlappingStatusRes);
    assert.equal(overlappingStatusRes.statusCode, 409);
    assert.equal(JSON.parse(overlappingStatusRes.body).error.code, "runtime_busy");
    const legacyDiscovery = { schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main" }, instances: [{ tag: "old-vless", protocol: "vless", listen: { port: 8443, address: "::", transport: "tcp" }, managed: false, importable: true, options: { security: "reality", sni: "www.example.com", method: "" }, reason: "" }] };
    const legacyRuntimeStatus = { schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main", oneboxScriptVersion: "unversioned", oneboxScriptSha256: "a".repeat(64), singBoxVersion: "1.11.0", serviceState: "active" } };
    const runtimeStatusMarker = "\nKNS_RUNTIME_STATUS=" + JSON.stringify(legacyRuntimeStatus);
    taskResult = { exit_code: 0, stdout: "KNS_DISCOVERY=" + JSON.stringify(legacyDiscovery) + runtimeStatusMarker };
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
    const legacyImportBody = { action: "machine.import", machineUuid, legacyTag: "old-vless", tags: ["prod"], endpointHost: "2.3.4.5", externalPort: 30443, confirm: true, idempotencyKey: "legacy-import-1" };
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(legacyImportBody) }, legacyImportRes);
    assert.equal(legacyImportRes.statusCode, 202, legacyImportRes.body);
    const legacyRetryRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(legacyImportBody) }, legacyRetryRes);
    assert.equal(legacyRetryRes.statusCode, 200, legacyRetryRes.body);
    assert.equal(JSON.parse(legacyRetryRes.body).reused, true);
    assert.match(execParams.command, /kns 'claim'/);
    const legacyEncoded = execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1];
    const legacyRequest = JSON.parse(Buffer.from(legacyEncoded, "base64").toString("utf8"));
    assert.equal(legacyRequest.instance.legacyTag, "old-vless");
    const legacyCredentialUuid = "4aaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const legacyExpectedTag = "kns-" + legacyRequest.instance.id;
    const legacyClaimDiscovery = { schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main" }, instances: [{ tag: legacyExpectedTag, protocol: "vless", listen: { port: 8443, address: "::", transport: "tcp" }, managed: true, importable: false, options: { security: "reality", sni: "www.example.com", method: "" }, reason: "" }] };
    const legacyReport = {
      schema: 1, jobId: legacyRequest.jobId, machineUuid, status: "succeeded", runtime: { id: "onebox-main", engine: "sing-box" },
      instances: [{ id: legacyRequest.instance.id, legacyTag: "old-vless", tag: legacyExpectedTag, protocol: "vless", listen: { port: 8443, transport: "tcp" }, tls: { security: "reality", sni: "www.example.com", publicKey: "legacy-public-key", shortId: "01" }, credential: { type: "uuid", value: legacyCredentialUuid, flow: "xtls-rprx-vision" }, resources: [{ type: "oneboxInbound", id: legacyExpectedTag, owned: true, shared: false }] }],
      artifactVersion: "1.8.0",
    };
    const legacyReportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { authorization: "Bearer " + legacyRequest.report.oneTimeToken, "content-type": "application/json" }, body: JSON.stringify(legacyReport) }, legacyReportRes);
    assert.equal(legacyReportRes.statusCode, 204);
    taskResult = { exit_code: 0, stdout: "KNS_DISCOVERY=" + JSON.stringify(legacyClaimDiscovery) + runtimeStatusMarker };
    const cryptoModule = require("../kns/crypto");
    const decryptSecret = cryptoModule.decryptSecret;
    cryptoModule.decryptSecret = () => { throw new Error("legacy import should transfer its encrypted callback credential"); };
    try { await crons.find((item) => item.expression === "@every 15s").handler(); }
    finally { cryptoModule.decryptSecret = decryptSecret; }
    await new Promise((resolve) => setTimeout(resolve, 20));
    const afterLegacyImportRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, afterLegacyImportRes);
    const afterLegacyImport = JSON.parse(afterLegacyImportRes.body);
    const importedLegacy = afterLegacyImport.instances.find((item) => item.legacyTag === "old-vless");
    assert.ok(importedLegacy);
    assert.equal(importedLegacy.name, "VLESS-test-node-30443");
    assert.equal(importedLegacy.managedBy, "onebox");
    assert.equal(importedLegacy.oneboxTag, legacyExpectedTag);
    assert.equal("readOnly" in importedLegacy, false);
    assert.equal(importedLegacy.endpoint.host, "2.3.4.5");
    assert.equal(importedLegacy.nat.externalPort, 30443);
    assert.equal("credential" in importedLegacy, false);
    assert.equal(JSON.stringify(afterLegacyImport).includes(legacyCredentialUuid), false);
    const importedJob = afterLegacyImport.jobs.find((job) => job.id === legacyRequest.jobId);
    assert.equal("keyFingerprint" in importedJob.callback, false);
    const persistedLegacy = JSON.parse(fs.readFileSync(path.join(storage, "kns", "state.json"), "utf8")).instances.find((item) => item.id === importedLegacy.id);
    assert.equal(persistedLegacy.credential.value, legacyCredentialUuid);
    assert.equal("credentialCiphertext" in persistedLegacy, false);
    const scriptUpdateRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "runtime.script.update", machineUuid, confirm: true, idempotencyKey: "runtime-script-update-1" }) }, scriptUpdateRes);
    assert.equal(scriptUpdateRes.statusCode, 202, scriptUpdateRes.body);
    assert.match(execParams.command, /kns 'update-script'/);
    const scriptUpdateRequest = JSON.parse(Buffer.from(execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1], "base64").toString("utf8"));
    assert.equal(scriptUpdateRequest.instance, null);
    assert.match(scriptUpdateRequest.upgrade.scriptSha256, /^[0-9a-f]{64}$/);
    const scriptUpdateCallback = { schema: 1, jobId: scriptUpdateRequest.jobId, machineUuid, status: "succeeded", runtime: { id: "onebox-main", engine: "sing-box" }, instances: [], operationResult: { type: "script_update", version: "1.0.5", previousSha256: "b".repeat(64), scriptSha256: scriptUpdateRequest.upgrade.scriptSha256, changed: true }, artifactVersion: "1.8.0" };
    const scriptUpdateReportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { authorization: "Bearer " + scriptUpdateRequest.report.oneTimeToken, "content-type": "application/json" }, body: JSON.stringify(scriptUpdateCallback) }, scriptUpdateReportRes);
    assert.equal(scriptUpdateReportRes.statusCode, 204);
    const scriptRuntimeStatus = { schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main", oneboxScriptVersion: "1.0.5", oneboxScriptSha256: scriptUpdateRequest.upgrade.scriptSha256, singBoxVersion: "1.11.0", serviceState: "active" } };
    taskResult = { exit_code: 0, stdout: "KNS_RUNTIME_STATUS=" + JSON.stringify(scriptRuntimeStatus) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 15));
    const scriptUpdateStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, scriptUpdateStateRes);
    const scriptUpdateState = JSON.parse(scriptUpdateStateRes.body);
    assert.equal(scriptUpdateState.jobs.find((job) => job.id === scriptUpdateRequest.jobId).state, "succeeded");
    assert.equal(scriptUpdateState.machines[0].runtimeStatus.oneboxScriptSha256, scriptUpdateRequest.upgrade.scriptSha256);

    const kernelUpdateRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "runtime.kernel.update", machineUuid, version: "latest", confirm: true, idempotencyKey: "runtime-kernel-update-1" }) }, kernelUpdateRes);
    assert.equal(kernelUpdateRes.statusCode, 202, kernelUpdateRes.body);
    assert.match(execParams.command, /kns 'update-kernel'/);
    const kernelUpdateRequest = JSON.parse(Buffer.from(execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1], "base64").toString("utf8"));
    assert.equal(kernelUpdateRequest.instance, null);
    assert.equal(kernelUpdateRequest.upgrade.version, "latest");
    const kernelUpdateCallback = { schema: 1, jobId: kernelUpdateRequest.jobId, machineUuid, status: "succeeded", runtime: { id: "onebox-main", engine: "sing-box" }, instances: [], operationResult: { type: "kernel_update", requestedVersion: "latest", previousVersion: "1.11.0", singBoxVersion: "1.12.0", serviceState: "active" }, artifactVersion: "1.8.0" };
    const kernelUpdateReportRes = response();
    await routes.get("POST /api/kns/report")({ headers: { authorization: "Bearer " + kernelUpdateRequest.report.oneTimeToken, "content-type": "application/json" }, body: JSON.stringify(kernelUpdateCallback) }, kernelUpdateReportRes);
    assert.equal(kernelUpdateReportRes.statusCode, 204);
    const kernelRuntimeStatus = { schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main", oneboxScriptVersion: "1.0.5", oneboxScriptSha256: scriptUpdateRequest.upgrade.scriptSha256, singBoxVersion: "1.12.0", serviceState: "active" } };
    taskResult = { exit_code: 0, stdout: "KNS_RUNTIME_STATUS=" + JSON.stringify(kernelRuntimeStatus) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 15));
    const kernelUpdateStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, kernelUpdateStateRes);
    const kernelUpdateState = JSON.parse(kernelUpdateStateRes.body);
    assert.equal(kernelUpdateState.jobs.find((job) => job.id === kernelUpdateRequest.jobId).state, "succeeded");
    assert.equal(kernelUpdateState.machines[0].runtimeStatus.singBoxVersion, "1.12.0");

    const kernelCallbackMissingRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "runtime.kernel.update", machineUuid, version: "latest", confirm: true, idempotencyKey: "runtime-kernel-update-callback-missing" }) }, kernelCallbackMissingRes);
    assert.equal(kernelCallbackMissingRes.statusCode, 202, kernelCallbackMissingRes.body);
    const kernelCallbackMissingRequest = JSON.parse(Buffer.from(execParams.command.match(/printf %s '([A-Za-z0-9+/=]+)' \| base64 -d/)[1], "base64").toString("utf8"));
    taskResult = { exit_code: 1, stdout: "KNS_RUNTIME_STATUS=" + JSON.stringify({ schema: 1, adapterVersion: "1.8.0", runtime: { engine: "sing-box", id: "onebox-main", oneboxScriptVersion: "1.0.5", oneboxScriptSha256: scriptUpdateRequest.upgrade.scriptSha256, singBoxVersion: "1.13.0", serviceState: "active" } }) };
    await crons.find((item) => item.expression === "@every 15s").handler();
    await new Promise((resolve) => setTimeout(resolve, 15));
    const kernelCallbackMissingStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, kernelCallbackMissingStateRes);
    const kernelCallbackMissingState = JSON.parse(kernelCallbackMissingStateRes.body);
    assert.equal(kernelCallbackMissingState.jobs.find((job) => job.id === kernelCallbackMissingRequest.jobId).state, "needs_reconcile", "a changed kernel without its callback must require status reconciliation");
    assert.equal(kernelCallbackMissingState.machines[0].runtimeStatus.singBoxVersion, "1.13.0");

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
    assert.equal(JSON.stringify(clearExport.state).includes(credentialUuid), true);

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
    await routes.get("POST /api/kns/admin/import")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ envelope, passphrase: exportPassphrase, confirmPhrase: "恢复" }) }, importRes);
    assert.equal(importRes.statusCode, 200, importRes.body);
    const importedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, importedStateRes);
    assert.equal(JSON.parse(importedStateRes.body).settings.converterTarget, "clash");

    for (const converterUrl of ["http://converter.example/sub", "http://127.0.0.1:25500/sub", "https://user:pass@converter.example/sub", "https://converter.example/sub#fragment", "https://converter.example/not-sub", "invalid"]) {
      const invalidConverterRes = response();
      await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterUrl }) }, invalidConverterRes);
      assert.equal(invalidConverterRes.statusCode, 400, converterUrl);
      assert.equal(JSON.parse(invalidConverterRes.body).error.code, "invalid_converter_url");
    }
    const postImportSettingsRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterUrl: "https://converter.example/sub", converterTarget: "loon" }) }, postImportSettingsRes);
    assert.equal(postImportSettingsRes.statusCode, 200);

    const profileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.create", name: "test", formats: ["uri", "mihomo-full"], machineUuids: [machineUuid], excludeMachineUuids: [], protocols: ["vless"], includeTags: ["prod"], addressMode: "ipv4", sortBy: "machine" }) }, profileRes);
    const created = JSON.parse(profileRes.body);
    const url = new URL(created.tokenUrl);
    assert.deepEqual(Object.keys(created.subscriptionUrls).sort(), ["mihomo-full", "uri"]);
    assert.equal(Object.keys(created.availableSubscriptionUrls).length, 21);
    for (const format of ["loon", "surge", "quanx", "shadowrocket", "singbox-full"]) {
      const available = new URL(created.availableSubscriptionUrls[format]);
      assert.equal(available.searchParams.get("format"), format);
      assert.equal(available.searchParams.get("token"), url.searchParams.get("token"));
      assert.equal(available.searchParams.get("profile"), url.searchParams.get("profile"));
    }
    assert.equal(new URL(created.converterUrl).searchParams.get("url"), created.tokenUrl);
    assert.equal(new URL(created.converterUrl).searchParams.get("target"), "loon");
    assert.equal(new URL(created.converterUrls.clash).searchParams.get("target"), "clash");
    assert.equal(new URL(created.converterUrls.quanx).searchParams.get("url"), created.tokenUrl);
    assert.equal(Object.keys(created.converterUrls).length, 24);
    const profileStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, profileStateRes);
    const profileState = JSON.parse(profileStateRes.body).profiles.find((item) => item.name === "test");
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
    const loonRes = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(new URL(created.availableSubscriptionUrls.loon).searchParams), headers: {} }, loonRes);
    assert.equal(loonRes.statusCode, 200, loonRes.body);
    assert.match(loonRes.body, /^\[Proxy\]/);
    assert.match(subRes.body, /^vless:\/\//);
    assert.match(subRes.body, new RegExp(credentialUuid));
    assert.match(subRes.body, new RegExp(legacyCredentialUuid));
    assert.equal(subRes.headers["x-kns-snapshot-success"], "2");
    assert.ok(subRes.headers["x-kns-snapshot-generated-at"]);
    assert.equal(subRes.headers.link, '<https://github.com/liuarui/komari-plugin-kns/tree/v' + require("../komari-plugin.json").version + '>; rel="source"');
    assert.equal(subRes.headers["x-kns-license"], "AGPL-3.0-only");
    const singboxOnlyProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.create", name: "singbox-only", formats: ["singbox-full"] }) }, singboxOnlyProfileRes);
    const singboxOnly = JSON.parse(singboxOnlyProfileRes.body);
    assert.deepEqual(Object.keys(singboxOnly.subscriptionUrls), ["singbox-full"]);
    assert.equal(new URL(singboxOnly.nativeUrl).searchParams.get("format"), "singbox-full");
    assert.equal(singboxOnly.tokenUrl, "");
    assert.equal(singboxOnly.converterUrl, "");
    const clearConverterRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "settings.update", publicBaseUrl: "https://monitor.example", converterUrl: "" }) }, clearConverterRes);
    assert.equal(clearConverterRes.statusCode, 200, clearConverterRes.body);
    assert.equal(JSON.parse(clearConverterRes.body).settings.converterUrl, "");
    const latestBeforeRotateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, latestBeforeRotateRes);
    const latestBeforeRotate = JSON.parse(latestBeforeRotateRes.body);
    const addTokenRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.rotate", profileId: profileState.id, expectedRevision: latestBeforeRotate.revision }) }, addTokenRes);
    assert.equal(addTokenRes.statusCode, 200, addTokenRes.body);
    const addedToken = JSON.parse(addTokenRes.body);
    assert.equal(addedToken.converterUrl, "");
    assert.deepEqual(addedToken.converterUrls, {});
    assert.ok(addedToken.subscriptionUrls.uri);
    assert.ok(addedToken.subscriptionUrls["mihomo-full"]);
    const addedUrl = new URL(addedToken.tokenUrl);
    const addedGet = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(addedUrl.searchParams), headers: {} }, addedGet);
    assert.equal(addedGet.statusCode, 200);
    crons.filter((item) => item.expression === "@every 1m").at(-1).handler();
    const tokenStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, tokenStateRes);
    const profileWithTokens = JSON.parse(tokenStateRes.body).profiles.find((item) => item.id === profileState.id);
    assert.equal(profileWithTokens.tokens.length, 1);
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
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.rotate", profileId: expiringProfile.profile.id, expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() }) }, cappedTokenRes);
    assert.equal(cappedTokenRes.statusCode, 200);
    const cappedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, cappedStateRes);
    const cappedRecord = JSON.parse(cappedStateRes.body).profiles.find((item) => item.id === expiringProfile.profile.id);
    assert.ok(cappedRecord.tokens.every((item) => item.expiresAt === profileExpiry));
    await crons.find((item) => item.expression === "@every 5m").handler();
    await new Promise((resolve) => setTimeout(resolve, 150));
    const snapshotFiles = fs.readdirSync(path.join(storage, "kns", "subscriptions"));
    assert.ok(snapshotFiles.length >= 1);
    for (const filename of snapshotFiles) {
      const snapshotPath = path.join(storage, "kns", "subscriptions", filename);
      assert.equal(fs.statSync(snapshotPath).mode & 0o077, 0, "plaintext snapshots must stay private");
    }
    const subscriptionModule = require("../kns/subscription");
    const originalBuild = subscriptionModule.buildSubscription;
    subscriptionModule.buildSubscription = () => { throw new Error("GET must use the stored snapshot"); };
    try {
      const cachedRes = response();
      await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(addedUrl.searchParams), headers: {} }, cachedRes);
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
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.rotate", profileId: profileState.id }) }, rotateTokenRes);
    assert.equal(rotateTokenRes.statusCode, 200, rotateTokenRes.body);
    const rotatedToken = JSON.parse(rotateTokenRes.body);
    const rotatedUrl = new URL(rotatedToken.tokenUrl);
    const oldAfterRotation = response();
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(url.searchParams), headers: {} }, oldAfterRotation);
    assert.equal(oldAfterRotation.statusCode, 404, "rotation invalidates the old token immediately");
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
    await routes.get("GET /api/kns/sub")({ query: Object.fromEntries(rotatedUrl.searchParams), headers: {} }, staleRes);
    assert.equal(staleRes.statusCode, 200);
    assert.equal(staleRes.body, "");
    const refreshedRes = staleRes;
    assert.equal(refreshedRes.body, "");
    const updateProfileRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "profile.update", profileId: profileState.id, machineUuids: [], excludeMachineUuids: [machineUuid], protocols: [], includeTags: [], addressMode: "dual", sortBy: "endpoint" }) }, updateProfileRes);
    assert.equal(updateProfileRes.statusCode, 200, updateProfileRes.body);
    const updatedStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, updatedStateRes);
    const updatedProfile = JSON.parse(updatedStateRes.body).profiles.find((item) => item.id === profileState.id);
    assert.equal(updatedProfile.machineUuids, null);
    assert.deepEqual(updatedProfile.excludeMachineUuids, [machineUuid]);
    assert.equal(updatedProfile.addressMode, "dual");
    assert.equal(updatedProfile.sortBy, "endpoint");
    const persisted = fs.readFileSync(path.join(storage, "kns", "state.json"), "utf8");
    assert.equal(fs.statSync(path.join(storage, "kns", "state.json")).mode & 0o077, 0, "plaintext state must stay private");
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

    const unresolvedInstallRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "install", machineUuid, protocol: "vless", listenPort: 9444, listenAddress: "::", options: { security: "reality" }, confirm: true, idempotencyKey: "blocked-by-old-unresolved-job" }) }, unresolvedInstallRes);
    assert.equal(unresolvedInstallRes.statusCode, 409);
    assert.equal(JSON.parse(unresolvedInstallRes.body).error.code, "dispatch_unconfirmed");
    const acknowledgeUnresolvedRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify({ action: "attention.acknowledge", kind: "job", jobId: kernelCallbackMissingRequest.jobId, expectedState: "needs_reconcile" }) }, acknowledgeUnresolvedRes);
    assert.equal(acknowledgeUnresolvedRes.statusCode, 200, acknowledgeUnresolvedRes.body);

    nextExecError = Object.assign(new Error("admin session expired"), { code: "-32040" });
    const retryBatchBody = { action: "install.batch", machineUuids: [machineUuid], batchId: "batch-retry-12345678", protocol: "vless", listenPort: 9444, listenAddress: "::", options: { security: "reality" }, confirm: true };
    const retryBatchRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(retryBatchBody) }, retryBatchRes);
    assert.equal(retryBatchRes.statusCode, 202, retryBatchRes.body);
    const failedJob = JSON.parse(retryBatchRes.body).results[0].job;
    const failedJobsStateRes = response();
    await routes.get("GET /api/kns/admin/state")({ ...admin, query: {} }, failedJobsStateRes);
    assert.equal(JSON.parse(failedJobsStateRes.body).jobs.find((job) => job.id === failedJob.id).canRetry, true);

    nextExecError = Object.assign(new Error("admin session expired"), { code: "-32040" });
    const retryBody = { action: "job.retry", jobId: failedJob.id, confirm: true, idempotencyKey: "retry-request-key-12345678" };
    const retryRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(retryBody) }, retryRes);
    assert.equal(retryRes.statusCode, 202, retryRes.body);
    const retryJob = JSON.parse(retryRes.body).job;
    assert.equal(retryJob.canRetry, false);
    assert.equal(Object.hasOwn(retryJob, "retryIdempotencyKey"), false);

    const retryReplayRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(retryBody) }, retryReplayRes);
    assert.equal(retryReplayRes.statusCode, 200, retryReplayRes.body);
    assert.equal(JSON.parse(retryReplayRes.body).reused, true);
    assert.equal(JSON.parse(retryReplayRes.body).job.id, retryJob.id);
    const retryConflictRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(Object.assign({}, retryBody, { idempotencyKey: "different-retry-key-12345678" })) }, retryConflictRes);
    assert.equal(retryConflictRes.statusCode, 409);
    assert.equal(JSON.parse(retryConflictRes.body).error.code, "idempotency_conflict");

    const batchBody = { action: "install.batch", machineUuids: [machineUuid], batchId: "batch-test-12345678", protocol: "vless", listenPort: 9443, listenAddress: "::", options: { security: "reality" }, confirm: true, expectedRevision: 0 };
    const callsBeforeBatch = execCalls;
    const batchRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(batchBody) }, batchRes);
    assert.equal(batchRes.statusCode, 202, batchRes.body);
    assert.equal(JSON.parse(batchRes.body).results[0].accepted, true);
    assert.equal(execCalls, callsBeforeBatch + 1);
    const batchReplayRes = response();
    await routes.get("POST /api/kns/admin/action")({ ...admin, headers: { host: "monitor.example", origin: "https://monitor.example", "content-type": "application/json" }, body: JSON.stringify(batchBody) }, batchReplayRes);
    assert.equal(batchReplayRes.statusCode, 202, batchReplayRes.body);
    assert.equal(JSON.parse(batchReplayRes.body).results[0].reused, true);
    assert.equal(execCalls, callsBeforeBatch + 1);
  } finally {
    if (plugin) plugin.unload();
    Module._load = originalLoad;
    delete global.__storageDir__;
    fs.rmSync(storage, { recursive: true, force: true });
    delete require.cache[target];
  }
});
