"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const { createStore } = require("../kns/store");
const secrets = require("../kns/crypto");

function runtime(t, server = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-runtime-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const filename = require.resolve("../kns/index");
  const localRequire = createRequire(filename);
  const context = {
    require: (name) => name === "server" ? server : localRequire(name),
    module: { exports: {} }, __storageDir__: root, Buffer, process, console, setTimeout, clearTimeout, fetch: (...args) => globalThis.fetch(...args), AbortController,
  };
  vm.runInNewContext(fs.readFileSync(filename, "utf8") + `
    masterKey = secrets.getMasterKey(__storageDir__);
    module.exports = { publicState, ensureInstance, handleAction, makeRemoteCommand, downloadPluginUpdate, save, syncMachines, subscriptionSourceHash, refreshHealth, refreshEndpoints, refreshSubscriptionSnapshots, readSubscriptionSnapshot, subscriptionSnapshotKey, serveSubscription, recordTokenUsage, flushTokenUsage, pollPendingJobs, assertNoActiveJobs, jobRetryable, encryptedBackupEnvelope, decryptBackupEnvelope, handleAction, readBody, unload };
  `, context, { filename });
  const api = context.module.exports;
  t.after(() => api.unload());
  const store = createStore(root);
  const state = store.initialState();
  state.pluginVersion = require("../komari-plugin.json").version;
  store.write(state);
  return { api, store, root };
}

test("subscription fingerprints ignore observation metadata but include published changes", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  const profile = { id: "profile" };
  const instance = { id: "node", enabled: true, name: "node", protocol: "vless", endpoint: { host: "one.example", port: 443 }, health: { state: "healthy" } };
  state.instances.push(instance);
  const hash = () => api.subscriptionSourceHash(state, profile, "uri");
  const before = hash();
  instance.updatedAt = "new time";
  instance.endpoint.updatedAt = "new time";
  instance.health = { state: "suspect", consecutiveFailures: 1, lastCheckedAt: "new time" };
  assert.equal(hash(), before);
  instance.health.state = "unhealthy";
  assert.notEqual(hash(), before);
  instance.health.state = "healthy";
  instance.endpoint.host = "two.example";
  assert.notEqual(hash(), before);
});

test("endpoint refresh persists a NAT conflict even when no endpoint is probeable", async (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine", policy: { manualAddress: "shared.example" } });
  state.instances.push(
    { id: "moving", machineUuid: "machine", enabled: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "old.example", port: 443 }, nat: { externalPort: 443, publicHosts: ["old.example"] } },
    { id: "existing", machineUuid: "other", enabled: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "shared.example", port: 443 }, nat: { externalPort: 443, publicHosts: ["shared.example"] } },
  );
  store.write(state);
  await api.refreshEndpoints();
  const updated = store.read();
  assert.deepEqual(updated.instances[0].nat.mappingConflict.publicHosts, ["shared.example"]);
  assert.equal(updated.instances[0].endpoint.host, "old.example");
  assert.equal(store.listAudit(10).events.filter((event) => event.action === "instance.nat.mapping_conflict.detected").length, 1);
  await api.refreshEndpoints();
  assert.equal(store.listAudit(10).events.filter((event) => event.action === "instance.nat.mapping_conflict.detected").length, 1);
});

test("failed token usage commits retain counts for retry without double counting", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.profiles.push({ id: "profile", tokens: [{ id: "token", ...secrets.tokenRecord("secret"), accessCount: 0 }] });
  store.write(state);
  api.recordTokenUsage("profile", "token");
  api.recordTokenUsage("profile", "token");
  const originalRename = fs.renameSync;
  fs.renameSync = function (source, destination) {
    if (destination === store.stateFile) throw new Error("simulated write failure");
    return originalRename.call(this, source, destination);
  };
  try { assert.throws(() => api.flushTokenUsage(), /simulated write failure/); }
  finally { fs.renameSync = originalRename; }
  assert.equal(store.read().profiles[0].tokens[0].accessCount, 0);
  api.recordTokenUsage("profile", "token");
  api.flushTokenUsage();
  assert.equal(store.read().profiles[0].tokens[0].accessCount, 3);
  api.flushTokenUsage();
  assert.equal(store.read().profiles[0].tokens[0].accessCount, 3);
});

test("request body limits count UTF-8 bytes rather than UTF-16 length", (t) => {
  const { api } = runtime(t);
  const body = JSON.stringify({ name: "中文" });
  assert.throws(() => api.readBody({ headers: { "content-type": "application/json" }, body }, body.length), (error) => error.code === "body_too_large");
});


test("stale jobs without task IDs require reconciliation without resending remote work", async (t) => {
  const calls = [];
  const { api, store } = runtime(t, { call: async (...args) => { calls.push(args); throw new Error("unexpected RPC"); } });
  const state = store.read();
  const oldTime = new Date(Date.now() - 31 * 60 * 1000).toISOString();
  state.jobs.push(...["authorized", "dispatched", "running", "verifying"].map((status) => ({
    id: "orphan-" + status, action: "install", state: status, machineUuid: "machine", runtimeId: "onebox-main", taskId: "", createdAt: oldTime,
    callbackTokenHash: "hash", callbackTokenSalt: "salt", retrySpec: { protocol: "vless" },
  })));
  state.jobs.push({ id: "completed", state: "succeeded", taskId: "", createdAt: oldTime });
  store.write(state);
  assert.throws(() => api.assertNoActiveJobs(store.read(), "导入备份"), (error) => error.code === "active_jobs_block_maintenance");
  await api.pollPendingJobs();
  const recovered = store.read();
  for (const job of recovered.jobs.filter((item) => item.id.startsWith("orphan-"))) {
    assert.equal(job.state, "needs_reconcile");
    assert.match(job.message, /未自动重发/);
    assert.equal(job.callbackTokenHash, undefined);
    assert.equal(job.callbackTokenSalt, undefined);
    assert.equal(api.jobRetryable(recovered, job), false);
  }
  assert.equal(recovered.jobs.find((job) => job.id === "completed").state, "succeeded");
  assert.doesNotThrow(() => api.assertNoActiveJobs(recovered, "导入备份"));
  await api.pollPendingJobs();
  assert.equal(store.read().revision, recovered.revision, "second poll must not rewrite recovered jobs");
  assert.deepEqual(calls, [], "recovery must not call or resend admin:exec");
});

test("recent authorizations without task IDs stay active while dispatch may still be pending", async (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.jobs.push({ id: "pending", state: "authorized", taskId: "", createdAt: new Date().toISOString() });
  store.write(state);
  const revision = state.revision;
  await api.pollPendingJobs();
  assert.equal(store.read().jobs[0].state, "authorized");
  assert.equal(store.read().revision, revision);
  assert.throws(() => api.assertNoActiveJobs(store.read(), "恢复备份"), (error) => error.code === "active_jobs_block_maintenance");
});

for (const action of ["reconfigure", "reinstall"]) {
  for (const visibility of ["hidden", "published", "hidden while running"]) {
    test(action + " preserves " + visibility + " visibility in subscriptions", (t) => {
      const { api, store, root } = runtime(t);
      const state = store.read();
      state.machines.push({ uuid: "machine", ipv4: "8.8.8.8", policy: { addressMode: "ipv4" } });
      const instance = { id: "node", machineUuid: "machine", publish: visibility !== "hidden" };
      state.instances.push(instance);
      const job = { action, instanceId: "node", machineUuid: "machine", name: "node", publish: instance.publish };
      if (visibility === "hidden while running") instance.publish = false;
      api.ensureInstance(state, job, {
        id: "node", protocol: "shadowsocks", listen: { port: 443, transport: "tcp+udp" },
        credential: { type: "shadowsocks", method: "aes-128-gcm", value: "secret" }, resources: [],
      });
      assert.equal(state.instances.length, 1);
      assert.equal(instance.publish, visibility === "published");
      const { buildSubscription } = require("../kns/subscription");
      const key = secrets.getMasterKey(root);
      const subscription = buildSubscription(state, { instanceIds: null }, "uri", (box) => secrets.decryptSecret(box, key));
      assert.equal(subscription.successCount, visibility === "published" ? 1 : 0);
      if (visibility === "published") assert.match(subscription.body, /^ss:\/\//);
      else assert.equal(subscription.body, "");
    });
  }
}

test("new installations publish by default", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine", ipv4: "8.8.8.8", policy: { addressMode: "ipv4" } });
  api.ensureInstance(state, { action: "install", instanceId: "node", machineUuid: "machine", name: "node" }, {
    id: "node", protocol: "shadowsocks", listen: { port: 443, transport: "tcp+udp" },
    credential: { type: "shadowsocks", method: "aes-128-gcm", value: "secret" }, resources: [],
  });
  assert.equal(state.instances.length, 1);
  assert.equal(state.instances[0].publish, true);
});


test("backup.inspect accepts a valid encrypted export above 1 MiB within the import limit", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.jobs = Array.from({ length: 700 }, (_, index) => ({ id: "history-" + index, message: "x".repeat(1200) }));
  store.write(state);
  const passphrase = "correct horse battery staple";
  const envelope = api.encryptedBackupEnvelope(store.read(), passphrase);
  const payload = JSON.stringify({ action: "backup.inspect", envelope, passphrase });
  assert.ok(Buffer.byteLength(payload, "utf8") > 1024 * 1024);
  assert.ok(Buffer.byteLength(payload, "utf8") < 16 * 1024 * 1024);
  const request = {
    body: payload,
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    context: { principal: { roles: ["admin"], username: "tester" } },
  };
  const response = { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } };
  const revision = store.read().revision;
  api.handleAction(request, response);
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(JSON.parse(response.body).backup.counts.jobs, 700);
  assert.equal(store.read().revision, revision, "preview must not mutate state");
});

test("large non-preview admin actions remain limited to 1 MiB", async (t) => {
  const { api } = runtime(t);
  const body = JSON.stringify({ action: "profile.preview", payload: "x".repeat(1024 * 1024) });
  assert.throws(() => api.readBody({ headers: { "content-type": "application/json" }, body }, 1024 * 1024), (error) => error.code === "body_too_large");
  await assert.rejects(api.handleAction({
    body,
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    context: { principal: { roles: ["admin"] } },
  }, { setHeader() {}, end() {} }), (error) => error.code === "body_too_large");
});

test("confirmed remote absence rebuilds subscription snapshots without changing publish preference", async (t) => {
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  const task = { id: "status-job", action: "instance.status", state: "dispatched", machineUuid, instanceId: "node", taskId: "task-status", createdAt: new Date().toISOString() };
  const server = { call: async (method) => {
    assert.equal(method, "admin:getSpecificTaskResult");
    return { exit_code: 0, stdout: 'KNS_STATUS={"schema":1,"runtime":{"engine":"sing-box","id":"onebox-main"},"instances":[{"id":"node","installed":false}]}' };
  } };
  const { api, store, root } = runtime(t, server);
  const key = secrets.getMasterKey(root);
  const state = store.read();
  state.machines.push({ uuid: machineUuid, name: "machine", ipv4: "8.8.8.8", policy: { addressMode: "ipv4" } });
  state.instances.push({ id: "node", machineUuid, name: "node", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp+udp" }, endpoint: { host: "8.8.8.8", port: 443 },
    credentialCiphertext: secrets.encryptSecret(JSON.stringify({ method: "aes-128-gcm", password: "secret" }), key) });
  state.profiles.push({ id: "profile", name: "profile", tokens: [], formats: ["uri"], excludeUnhealthy: false });
  state.jobs.push(task);
  store.write(state);
  const before = store.read();
  const profile = before.profiles[0];
  const beforeHash = api.subscriptionSourceHash(before, profile, "uri");
  assert.equal(require("../kns/subscription").buildSubscription(before, profile, "uri", (box) => secrets.decryptSecret(box, key)).successCount, 1);
  await api.pollPendingJobs();
  const absent = store.read();
  assert.equal(absent.instances[0].remoteStatus.installed, false);
  assert.equal(absent.instances[0].enabled, true, "keep admin enable preference");
  assert.equal(absent.instances[0].publish, true, "keep admin publish preference");
  assert.notEqual(api.subscriptionSourceHash(absent, absent.profiles[0], "uri"), beforeHash);
  await api.refreshSubscriptionSnapshots();
  const snapshot = api.readSubscriptionSnapshot("profile", "uri");
  assert.equal(snapshot.successCount, 0);
  assert.equal(snapshot.body, "");
  assert.equal(snapshot.sourceHash, api.subscriptionSourceHash(store.read(), store.read().profiles[0], "uri"));

  const response = { headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } };
  api.serveSubscription({ query: { profile: "profile", format: "uri", token: "unused" }, headers: {} }, response);
  assert.equal(response.statusCode, 404, "invalid token remains rejected after rebuilding snapshot");
  const { buildSubscription } = require("../kns/subscription");
  const reinstated = store.read();
  reinstated.instances[0].remoteStatus = { installed: false, installState: "not_installed" };
  api.ensureInstance(reinstated, { action: "reinstall", instanceId: "node", machineUuid, name: "node" }, {
    id: "node", protocol: "shadowsocks", listen: { port: 443, transport: "tcp+udp" },
    credential: { method: "aes-128-gcm", password: "secret" }, resources: [],
  });
  assert.equal(reinstated.instances[0].publish, true);
  assert.equal(reinstated.instances[0].remoteStatus, undefined);
  assert.equal(buildSubscription(reinstated, reinstated.profiles[0], "uri", (box) => secrets.decryptSecret(box, key)).successCount, 1);
});

test("install rejects globally registered and actively reserved instance IDs before dispatch", async (t) => {
  let execCalls = 0;
  const { api, store } = runtime(t, { call: async (method) => {
    if (method === "admin:exec") { execCalls += 1; return { task_id: "unexpected" }; }
    throw new Error("unexpected RPC " + method);
  } });
  const state = store.read();
  state.settings.setupComplete = true;
  state.settings.publicBaseUrl = "https://monitor.example";
  state.machines.push(
    { uuid: "machine-a", name: "A", online: true, ipv4: "8.8.8.8", policy: { deployAllowed: true, addressMode: "ipv4" } },
    { uuid: "machine-b", name: "B", online: true, ipv4: "1.1.1.1", policy: { deployAllowed: true, addressMode: "ipv4" } },
  );
  state.instances.push({ id: "shared", machineUuid: "machine-a", enabled: true, publish: true });
  state.jobs.push({ id: "reserved", instanceId: "held", machineUuid: "machine-a", action: "install", state: "authorized", taskId: "" });
  store.write(state);
  const request = (instanceId, machineUuid = "machine-b") => ({
    body: JSON.stringify({ action: "install", instanceId, machineUuid, protocol: "vless", listenPort: 8443, listenAddress: "::", options: { security: "reality" }, confirm: true, idempotencyKey: "install-" + instanceId }),
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    context: { principal: { roles: ["admin"], username: "tester" } },
  });
  const response = () => ({ headers: {}, statusCode: 200, body: "", setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = String(value || ""); } });
  for (const id of ["shared", "held"]) {
    await assert.rejects(api.handleAction(request(id), response()), (error) => error.code === "instance_id_conflict" && error.status === 409);
  }
  assert.equal(execCalls, 0, "conflicting IDs must be rejected before remote dispatch");
});

test("ensureInstance refuses a cross-machine callback instead of overwriting ownership", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine-a", ipv4: "8.8.8.8", policy: { addressMode: "ipv4" } }, { uuid: "machine-b", ipv4: "1.1.1.1", policy: { addressMode: "ipv4" } });
  state.instances.push({ id: "shared", machineUuid: "machine-a", name: "owned-by-a", enabled: true, publish: true, listen: { port: 443, transport: "tcp" } });
  assert.throws(() => api.ensureInstance(state, { action: "install", instanceId: "shared", machineUuid: "machine-b", name: "overwrite" }, {
    id: "shared", protocol: "shadowsocks", listen: { port: 8443, transport: "tcp+udp" }, credential: { method: "aes-128-gcm", password: "secret" }, resources: [],
  }), (error) => error.code === "instance_id_conflict");
  assert.equal(state.instances.length, 1);
  assert.equal(state.instances[0].machineUuid, "machine-a");
  assert.equal(state.instances[0].name, "owned-by-a");
});

test("unchanged machine sync does not bump revision", async (t) => {
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  const { api, store } = runtime(t, {
    call: async (method) => {
      if (method === "admin:listClients") return [{ uuid: machineUuid, name: "test-node", ipv4: "1.2.3.4", os: "linux", arch: "amd64" }];
      if (method === "common:getNodesLatestStatus") return { [machineUuid]: { online: true } };
      throw new Error("unexpected RPC " + method);
    },
  });
  const state = store.read();
  state.machines.push({ uuid: machineUuid, name: "test-node", region: "", os: "linux", arch: "amd64", online: true, ipv4: "1.2.3.4", ipv6: "", sourceIp: "", policy: { deployAllowed: false, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [] } });
  store.write(state);
  const revision = store.read().revision;
  await api.syncMachines();
  assert.equal(store.read().revision, revision);
});

function tokenLifecycle(t) {
  const { api, store } = runtime(t, { call() { throw new Error("token actions must not call RPC"); } });
  const state = store.read();
  state.settings.setupComplete = true;
  state.settings.publicBaseUrl = "https://monitor.example";
  state.profiles.push({ id: "profile", name: "profile", formats: ["uri"], tokens: [], createdAt: new Date().toISOString() });
  store.write(state);
  const act = async (action, fields = {}) => {
    const response = { statusCode: 200, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } };
    await api.handleAction({
      headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
      body: JSON.stringify({ action, profileId: "profile", ...fields }),
      context: { principal: { roles: ["admin"], username: "tester" } },
    }, response);
    return JSON.parse(response.body);
  };
  return { api, store, act };
}

test("token rotation beyond historical quota and revoked profile recovery remain possible", async (t) => {
  const { store, act } = tokenLifecycle(t);
  const first = await act("profile.token.create");
  for (let index = 0; index < 55; index += 1) await act("profile.rotate", { graceSeconds: 0 });
  assert.ok(store.read().profiles[0].tokens.length <= 50);
  await act("profile.revoke");
  const restored = await act("profile.rotate", { graceSeconds: 0 });
  const profile = store.read().profiles[0];
  assert.equal(profile.revokedAt, "");
  assert.equal(profile.tokens.length, 1);
  assert.equal(profile.tokens[0].id, restored.tokenId);
  assert.notEqual(restored.tokenId, first.tokenId);
});

test("one token per profile: second issuance is rejected and rotation replaces it", async (t) => {
  const { store, act } = tokenLifecycle(t);
  const first = await act("profile.token.create");
  await assert.rejects(act("profile.token.create"), (error) => error.code === "token_already_exists");
  const rotated = await act("profile.rotate");
  const profile = store.read().profiles[0];
  assert.equal(profile.tokens.length, 1);
  assert.equal(profile.tokens[0].id, rotated.tokenId);
  assert.notEqual(rotated.tokenId, first.tokenId);
});

for (const [field, value] of [["region", "JP"], ["os", "freebsd"], ["arch", "arm64"]]) {
  test("machine sync persists " + field + " changes without unrelated changes", async (t) => {
    const uuid = "123e4567-e89b-42d3-a456-426614174000";
    const source = { uuid, name: "stable-node", region: "SG", os: "linux", arch: "amd64" };
    const { api, store } = runtime(t, {
      call: async (method) => {
        if (method === "admin:listClients") return [{ ...source }];
        if (method === "common:getNodesLatestStatus") return { [uuid]: { online: true } };
        throw new Error("unexpected RPC " + method);
      },
    });
    await api.syncMachines();
    let revision = store.read().revision;
    for (const next of [value, ""]) {
      source[field] = next;
      assert.equal(await api.syncMachines(), true);
      const updated = store.read();
      assert.equal(updated.revision, revision + 1);
      for (const name of ["name", "region", "os", "arch"]) assert.equal(updated.machines[0][name], source[name]);
      assert.equal(api.publicState(updated).machines[0][field], next);
      revision = updated.revision;
      assert.equal(await api.syncMachines(), true);
      assert.equal(store.read().revision, revision, "identical metadata must not trigger another save");
    }
  });
}


test("dual-stack health keeps the reachable family in the default subscription", async (t) => {
  const net = require("node:net");
  const original = net.createConnection;
  t.after(() => { net.createConnection = original; });
  net.createConnection = function (options) {
    const socket = new net.Socket();
    process.nextTick(() => {
      if (options.host === "8.8.8.8") socket.emit("error", new Error("ipv4 failed"));
      else socket.emit("connect");
    });
    return socket;
  };
  const { api, store, root } = runtime(t);
  const key = secrets.getMasterKey(root);
  const state = store.read();
  state.instances.push({
    id: "dual", name: "dual", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", hosts: ["8.8.8.8", "2606:4700:4700::1111"], port: 443 },
    credentialCiphertext: secrets.encryptSecret(JSON.stringify({ method: "aes-128-gcm", password: "secret" }), key),
  });
  store.write(state);
  for (let i = 0; i < 3; i += 1) await api.refreshHealth();
  const instance = store.read().instances[0];
  assert.equal(instance.health.hosts["8.8.8.8"].state, "unhealthy");
  assert.notEqual(instance.health.hosts["2606:4700:4700::1111"].state, "unhealthy");
  assert.notEqual(instance.health.state, "unhealthy");
  const { buildSubscription } = require("../kns/subscription");
  const uri = buildSubscription(store.read(), { excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.equal(uri.successCount, 1);
  assert.match(uri.body, /2606:4700:4700::1111/);
  assert.doesNotMatch(uri.body, /8\.8\.8\.8/);
});

test("health marks a dual-stack node unhealthy only after every family fails", async (t) => {
  const net = require("node:net");
  const original = net.createConnection;
  t.after(() => { net.createConnection = original; });
  net.createConnection = function () {
    const socket = new net.Socket();
    process.nextTick(() => socket.emit("error", new Error("failed")));
    return socket;
  };
  const { api, store, root } = runtime(t);
  const key = secrets.getMasterKey(root);
  const state = store.read();
  state.instances.push({
    id: "dual", name: "dual", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", hosts: ["8.8.8.8", "2606:4700:4700::1111"], port: 443 },
    credentialCiphertext: secrets.encryptSecret(JSON.stringify({ method: "aes-128-gcm", password: "secret" }), key),
  });
  store.write(state);
  for (let i = 0; i < 3; i += 1) await api.refreshHealth();
  const instance = store.read().instances[0];
  assert.equal(instance.health.state, "unhealthy");
  const { buildSubscription } = require("../kns/subscription");
  assert.equal(buildSubscription(store.read(), { excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key)).successCount, 0);
});


test("dual-stack endpoint refresh publishes a reachable IPv4 even when IPv6 fails", async (t) => {
  const net = require("node:net");
  const tls = require("node:tls");
  const originalNet = net.createConnection;
  const originalTls = tls.connect;
  t.after(() => { net.createConnection = originalNet; tls.connect = originalTls; });
  const fakeSocket = (options, ok) => {
    const socket = new net.Socket();
    process.nextTick(() => { if (ok) socket.emit("connect"); else socket.emit("error", new Error("probe failed")); });
    socket.setTimeout = () => {};
    return socket;
  };
  net.createConnection = function (options) { return fakeSocket(options, !String(options.host).includes(":")); };
  tls.connect = function (options) { return fakeSocket(options, !String(options.host).includes(":")); };
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine", ipv4: "8.8.8.8", ipv6: "2606:4700:4700::1111", policy: { addressMode: "dual" } });
  state.instances.push({
    id: "dual", machineUuid: "machine", enabled: true, protocol: "shadowsocks",
    listen: { port: 443, transport: "tcp" },
    endpoint: { host: "1.1.1.1", hosts: ["1.1.1.1", "2606:4700:4700::1111"], port: 443 },
  });
  store.write(state);
  await api.refreshEndpoints();
  const instance = store.read().instances[0];
  assert.equal(instance.endpoint.host, "8.8.8.8");
  assert.deepEqual(instance.endpoint.hosts, ["8.8.8.8"]);
});

test("dual-stack endpoint refresh keeps the previous endpoint when every family fails", async (t) => {
  const net = require("node:net");
  const original = net.createConnection;
  t.after(() => { net.createConnection = original; });
  net.createConnection = function () {
    const socket = new net.Socket();
    process.nextTick(() => socket.emit("error", new Error("failed")));
    return socket;
  };
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine", ipv4: "8.8.8.8", ipv6: "2606:4700:4700::1111", policy: { addressMode: "dual" } });
  state.instances.push({
    id: "dual", machineUuid: "machine", enabled: true, protocol: "shadowsocks",
    listen: { port: 443, transport: "tcp" },
    endpoint: { host: "1.1.1.1", hosts: ["1.1.1.1", "2606:4700:4700::1111"], port: 443 },
  });
  store.write(state);
  await api.refreshEndpoints();
  const instance = store.read().instances[0];
  assert.equal(instance.endpoint.host, "1.1.1.1");
  assert.deepEqual(instance.endpoint.hosts, ["1.1.1.1", "2606:4700:4700::1111"]);
});


test("unchanged DDNS observations stop bumping revision after they stabilize", async (t) => {
  const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  const answers = { A: ["8.8.8.8"], AAAA: [] };
  global.fetch = async (url) => {
    const type = String(url).includes("type=AAAA") ? "AAAA" : "A";
    const records = (answers[type] || []).map((data) => ({ type: type === "AAAA" ? 28 : 1, data }));
    return { ok: true, json: async () => ({ Answer: records }) };
  };
  const { api, store } = runtime(t);
  const state = store.read();
  state.machines.push({ uuid: "machine", policy: { ddnsHostname: "ddns.example" } });
  store.write(state);
  await api.refreshEndpoints();
  const first = store.read();
  assert.deepEqual(first.machines[0].ddnsObservation.addresses, ["8.8.8.8"]);
  assert.equal(first.machines[0].ddnsObservation.count, 1);
  const afterFirst = first.revision;
  await api.refreshEndpoints();
  const second = store.read();
  assert.equal(second.machines[0].ddnsObservation.count, 2);
  assert.ok(second.revision > afterFirst);
  const afterStable = second.revision;
  await api.refreshEndpoints();
  const third = store.read();
  assert.equal(third.machines[0].ddnsObservation.count, 2);
  assert.equal(third.revision, afterStable);
  answers.A = ["1.1.1.1"];
  await api.refreshEndpoints();
  const changed = store.read();
  assert.deepEqual(changed.machines[0].ddnsObservation.addresses, ["1.1.1.1"]);
  assert.equal(changed.machines[0].ddnsObservation.count, 1);
  assert.ok(changed.revision > afterStable);
});


function stubConnect(t, ok) {
  const net = require("node:net");
  const original = net.createConnection;
  t.after(() => { net.createConnection = original; });
  net.createConnection = function () {
    const socket = new net.Socket();
    socket.setTimeout = () => {};
    process.nextTick(() => { if (ok()) socket.emit("connect"); else socket.emit("error", new Error("probe failed")); });
    return socket;
  };
}

test("acknowledging a task and health incident preserves history and re-alerts after recovery", async (t) => {
  let reachable = false; stubConnect(t, () => reachable);
  const { api, store } = runtime(t);
  const state = store.read(); state.settings.setupComplete = true;
  state.jobs.push({ id: "failed-job", state: "failed", action: "install", machineUuid: "m", createdAt: new Date().toISOString() });
  state.instances.push({ id: "node", machineUuid: "m", enabled: true, protocol: "shadowsocks", listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", port: 443 }, health: { state: "unhealthy", hosts: { "8.8.8.8": { state: "unhealthy", consecutiveFailures: 3, consecutiveSuccesses: 0, level: "L1-TCP", reason: "connection_failed" } } } });
  store.write(state);
  const response = () => ({ statusCode: 200, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } });
  const req = (body) => ({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"], username: "tester" } }, body: JSON.stringify({ action: "attention.acknowledge", ...body }) });
  await api.handleAction(req({ kind: "job", jobId: "failed-job", expectedState: "failed", expectedRevision: 0 }), response());
  await api.handleAction(req({ kind: "health", instanceId: "node", incidentId: "legacy", expectedRevision: 0 }), response());
  let current = store.read();
  assert.equal(current.jobs[0].state, "failed"); assert.equal(current.jobs[0].attentionAcknowledgedState, "failed");
  assert.equal(current.instances[0].health.attentionAcknowledgedIncidentId, "legacy");
  await api.refreshHealth();
  assert.equal(store.read().instances[0].health.attentionAcknowledgedIncidentId, "legacy", "ongoing failure stays acknowledged");
  reachable = true; await api.refreshHealth(); await api.refreshHealth();
  assert.equal(store.read().instances[0].health.state, "healthy");
  reachable = false; await api.refreshHealth(); await api.refreshHealth(); await api.refreshHealth();
  current = store.read();
  assert.equal(current.instances[0].health.state, "unhealthy");
  assert.notEqual(current.instances[0].health.attentionIncidentId, "legacy");
  assert.equal(current.instances[0].health.attentionAcknowledgedIncidentId, undefined);
  await assert.rejects(api.handleAction(req({ kind: "health", instanceId: "node", incidentId: "legacy" }), response()), (error) => error.code === "attention_changed");
});

test("fresh bootstrap accepts only the known empty KNS directories", (t) => {
  const { api } = runtime(t); const child = require("node:child_process");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-bootstrap-")); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = path.join(root, "onebox");
  const command = api.makeRemoteCommand({ settings: { publicBaseUrl: "https://monitor.example" } }, { id: "job", machineUuid: "m", action: "install", _callbackToken: "test" }, { id: "node", protocol: "vless", listen: { port: 443, transport: "tcp" } });
  let guard = command.slice(command.indexOf("onebox_config="), command.indexOf('; if [ -n "$onebox_bootstrap_blocked" ]'));
  assert.ok(guard.startsWith("onebox_config="));
  guard = guard.replaceAll("/etc/onebox", config);
  for (const unit of ["/etc/systemd/system/onebox.service", "/run/systemd/system/onebox.service", "/usr/lib/systemd/system/onebox.service", "/lib/systemd/system/onebox.service", "/usr/local/lib/systemd/system/onebox.service", "/etc/init.d/onebox"]) guard = guard.replaceAll(unit, path.join(root, "service"));
  const run = () => child.execFileSync("bash", ["-c", guard + '; printf "%s|%s" "$onebox_bootstrap_blocked" "$onebox_needs_bootstrap"'], { encoding: "utf8" });
  fs.mkdirSync(path.join(config, "kns", "instances"), { recursive: true }); fs.mkdirSync(path.join(config, "kns", "certs"));
  assert.equal(run(), "|1");
  fs.writeFileSync(path.join(config, ".version_cache"), "cache"); assert.equal(run(), "|1"); fs.unlinkSync(path.join(config, ".version_cache"));
  fs.symlinkSync(root, path.join(config, ".version_cache")); assert.equal(run(), "existing_state|0"); fs.unlinkSync(path.join(config, ".version_cache"));
  fs.writeFileSync(path.join(config, "kns", "instances", "old.json"), "{}"); assert.equal(run(), "existing_state|0");
  fs.unlinkSync(path.join(config, "kns", "instances", "old.json")); fs.symlinkSync(root, path.join(config, "kns", "instances", "link")); assert.equal(run(), "existing_state|0");
  fs.unlinkSync(path.join(config, "kns", "instances", "link")); fs.mkdirSync(path.join(config, "unknown")); assert.equal(run(), "existing_state|0");
  fs.rmdirSync(path.join(config, "unknown")); fs.rmdirSync(path.join(config, "kns", "certs")); fs.symlinkSync(root, path.join(config, "kns", "certs")); assert.equal(run(), "existing_state|0");
  fs.unlinkSync(path.join(config, "kns", "certs")); fs.writeFileSync(path.join(root, "service"), ""); assert.equal(run(), "existing_state|0");
});

test("healthy probes do not bump revision after the state has already stabilized", async (t) => {
  stubConnect(t, () => true);
  const { api, store } = runtime(t);
  const state = store.read();
  state.instances.push({
    id: "node", name: "node", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", port: 443 },
    credential: { method: "aes-128-gcm", password: "secret" },
    health: { state: "healthy", consecutiveSuccesses: 2, consecutiveFailures: 0, hosts: { "8.8.8.8": { state: "healthy", consecutiveSuccesses: 2, consecutiveFailures: 0, level: "L1-TCP", reason: "reachable" } } },
  });
  store.write(state);
  const before = store.read();
  await api.refreshHealth();
  const after = store.read();
  assert.equal(after.revision, before.revision);
  assert.equal(after.instances[0].health.state, "healthy");
  assert.equal(after.instances[0].health.consecutiveSuccesses, 2);
});

test("a healthy node still persists when probes start failing", async (t) => {
  stubConnect(t, () => false);
  const { api, store, root } = runtime(t);
  const key = secrets.getMasterKey(root);
  const state = store.read();
  state.instances.push({
    id: "node", name: "node", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", port: 443 },
    credentialCiphertext: secrets.encryptSecret(JSON.stringify({ method: "aes-128-gcm", password: "secret" }), key),
    health: { state: "healthy", consecutiveSuccesses: 2, consecutiveFailures: 0, hosts: { "8.8.8.8": { state: "healthy", consecutiveSuccesses: 2, consecutiveFailures: 0, level: "L1-TCP", reason: "reachable" } } },
  });
  store.write(state);
  const before = store.read().revision;
  await api.refreshHealth();
  const after = store.read();
  assert.ok(after.revision > before);
  assert.equal(after.instances[0].health.state, "suspect");
  assert.equal(after.instances[0].health.hosts["8.8.8.8"].consecutiveFailures, 1);
});


test("legacy imported instances still accept a read-only status check", async (t) => {
  const calls = [];
  const { api, store } = runtime(t, {
    call: async (method, params) => {
      calls.push([method, params]);
      if (method === "common:getNodesLatestStatus") return Object.fromEntries(params.uuids.map((uuid) => [uuid, { online: true }]));
      if (method === "admin:exec") return { task_id: "task-status" };
      throw new Error("unexpected RPC " + method);
    },
  });
  const machineUuid = "123e4567-e89b-42d3-a456-426614174000";
  const state = store.read();
  state.settings.setupComplete = true;
  state.settings.publicBaseUrl = "https://monitor.example";
  state.machines.push({ uuid: machineUuid, name: "probe", online: true, policy: { deployAllowed: true } });
  state.instances.push({
    id: "legacy-node", machineUuid, managedBy: "legacy_import", protocol: "vless", runtimeId: "onebox-main",
    listen: { port: 443, transport: "tcp" },
  });
  store.write(state);
  const response = () => ({ statusCode: 200, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } });
  const req = (action) => ({
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    body: JSON.stringify({ action, machineUuid, instanceId: "legacy-node", confirm: true, idempotencyKey: action + "-1" }),
    context: { principal: { roles: ["admin"] } },
  });
  await assert.rejects(api.handleAction(req("disable"), response()), (error) => error.code === "legacy_instance_readonly");
  const statusRes = response();
  await api.handleAction(req("instance.status"), statusRes);
  const payload = JSON.parse(statusRes.body);
  assert.equal(statusRes.statusCode, 202, statusRes.body);
  assert.equal(payload.job.action, "instance.status");
  assert.equal(payload.job.instanceId, "legacy-node");
  assert.equal(calls[1][0], "admin:exec");
});


test("publicState reports the running plugin version and source URL", (t) => {
  const { api, store } = runtime(t);
  const version = require("../komari-plugin.json").version;
  const published = api.publicState(store.read());
  assert.equal(published.pluginVersion, version);
  assert.equal(published.sourceUrl, "https://github.com/liuarui/komari-plugin-kns/tree/v" + version);
});

test("plugin.update.check only flags GitHub latest when it is a newer SemVer", async (t) => {
  const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  const current = require("../komari-plugin.json").version;
  const cases = [
    { tag: "v0.9.9", available: false },
    { tag: "v" + current, available: false },
    { tag: "v1.3.1", available: true },
  ];
  for (const item of cases) {
    global.fetch = async () => ({ ok: true, json: async () => ({ tag_name: item.tag, html_url: "https://github.com/liuarui/komari-plugin-kns/releases/tag/" + item.tag }) });
    const { api, store } = runtime(t, { call() { throw new Error("update check must not call Komari RPC"); } });
    const state = store.read();
    state.settings.setupComplete = true;
    store.write(state);
    const response = { statusCode: 200, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } };
    await api.handleAction({
      headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
      body: JSON.stringify({ action: "plugin.update.check" }),
      context: { principal: { roles: ["admin"] } },
    }, response);
    const payload = JSON.parse(response.body);
    assert.equal(payload.currentVersion, current);
    assert.equal(payload.latestVersion, item.tag.replace(/^v/i, ""));
    assert.equal(payload.updateAvailable, item.available, item.tag);
  }
});

test("plugin.update.check reports GitHub latest without installing", async (t) => {
  const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  global.fetch = async (url, options) => {
    assert.match(String(url), /repos\/liuarui\/komari-plugin-kns\/releases\/latest/);
    assert.equal(options.headers.accept, "application/vnd.github+json");
    return { ok: true, json: async () => ({ tag_name: "v9.9.9", html_url: "https://github.com/liuarui/komari-plugin-kns/releases/tag/v9.9.9", published_at: "2026-11-09T00:00:00Z" }) };
  };
  const { api, store } = runtime(t, { call() { throw new Error("update check must not call Komari RPC"); } });
  const state = store.read();
  state.settings.setupComplete = true;
  store.write(state);
  const response = { statusCode: 200, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } };
  await api.handleAction({
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    body: JSON.stringify({ action: "plugin.update.check" }),
    context: { principal: { roles: ["admin"] } },
  }, response);
  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(payload.currentVersion, require("../komari-plugin.json").version);
  assert.equal(payload.latestVersion, "9.9.9");
  assert.equal(payload.updateAvailable, true);
});

test("plugin.update.check reports a clear failure when GitHub is unavailable", async (t) => {
  const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  global.fetch = async () => { throw new Error("network down"); };
  const { api, store } = runtime(t, { call() { throw new Error("update check must not call Komari RPC"); } });
  const state = store.read();
  state.settings.setupComplete = true;
  store.write(state);
  await assert.rejects(api.handleAction({
    headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" },
    body: JSON.stringify({ action: "plugin.update.check" }),
    context: { principal: { roles: ["admin"] } },
  }, { setHeader() {}, end() {} }), (error) => error.code === "update_check_failed");
});


test("finished job history is capped while active jobs are always kept", (t) => {
  const { api, store } = runtime(t);
  const state = store.read();
  const finished = Array.from({ length: 205 }, (_, index) => ({ id: "done-" + index, state: index % 2 ? "succeeded" : "failed", createdAt: new Date(Date.now() - (205 - index) * 1000).toISOString() }));
  const active = [
    { id: "live-authorized", state: "authorized", createdAt: new Date(Date.now() - 400000).toISOString() },
    { id: "live-running", state: "running", createdAt: new Date(Date.now() - 300000).toISOString() },
  ];
  state.jobs = finished.concat(active);
  const saved = api.save(state);
  assert.equal(saved.jobs.length, 202);
  assert.deepEqual(saved.jobs.filter((job) => ["authorized", "running"].includes(job.state)).map((job) => job.id), ["live-authorized", "live-running"]);
  assert.equal(saved.jobs[0].id, "done-5");
  assert.equal(store.read().jobs.length, 202);
  const published = api.publicState(store.read());
  assert.equal(published.jobs.length, 202);
  assert.ok(published.jobs.some((job) => job.id === "live-authorized"));
});

test("machine sync removes deleted machines and their nodes from state and subscriptions", async (t) => {
  const removed = "123e4567-e89b-42d3-a456-426614174000";
  const kept = "123e4567-e89b-42d3-a456-426614174001";
  let releasePoll, startedPoll;
  const pollStarted = new Promise((resolve) => { startedPoll = resolve; });
  const server = { call: async (method) => {
    if (method === "admin:listClients") return [{ uuid: kept, name: "kept" }];
    if (method === "common:getNodesLatestStatus") return { [kept]: { online: true } };
    if (method === "admin:getSpecificTaskResult") { startedPoll(); return new Promise((resolve) => { releasePoll = resolve; }); }
    throw new Error("unexpected RPC " + method);
  } };
  const { api, store } = runtime(t, server);
  const state = store.read();
  state.machines.push({ uuid: removed, name: "removed", removedFromKomariAt: new Date().toISOString() }, { uuid: kept, name: "kept" });
  for (const uuid of [removed, kept]) {
    state.instances.push({ id: "node-" + uuid, machineUuid: uuid, name: uuid, protocol: "shadowsocks", enabled: true, publish: true,
      listen: { port: 443, transport: "tcp+udp" }, endpoint: { host: uuid === removed ? "8.8.8.8" : "1.1.1.1", port: 443 },
      credential: { type: "shadowsocks", method: "aes-128-gcm", value: "test-secret" } });
    state.runtimes.push({ machineUuid: uuid, id: "onebox-main" });
    state.legacyNodes.push({ id: "old-" + uuid, machineUuid: uuid === removed ? uuid.toUpperCase() : uuid, enabled: true, uri: "ss://legacy-" + uuid });
  }
  state.profiles.push({ id: "legacy", name: "legacy", legacy: true, tokenRequired: false, formats: ["uri"], excludeUnhealthy: false, machineUuids: [] });
  state.profiles.push({ id: "restricted", name: "restricted", formats: ["uri"], excludeUnhealthy: false, machineUuids: [removed] });
  state.jobs.push({ id: "pending", action: "machine.discover", state: "dispatched", machineUuid: removed, taskId: "task", createdAt: new Date().toISOString(), callbackTokenHash: "hash", callbackTokenSalt: "salt" });
  store.write(state);
  await api.refreshSubscriptionSnapshots();
  assert.ok(api.readSubscriptionSnapshot("legacy", "uri").body.includes("legacy-" + removed));
  const poll = api.pollPendingJobs();
  await pollStarted;
  await api.syncMachines();
  releasePoll({ exit_code: 0, stdout: "KNS_DISCOVERY={}\nKNS_RUNTIME_STATUS={}" });
  await poll;
  const updated = store.read();
  assert.deepEqual(updated.machines.map((item) => item.uuid), [kept]);
  assert.deepEqual(updated.instances.map((item) => item.machineUuid), [kept]);
  assert.deepEqual(updated.runtimes.map((item) => item.machineUuid), [kept]);
  assert.deepEqual(updated.legacyNodes.map((item) => item.machineUuid), [kept]);
  assert.deepEqual(updated.profiles[0].machineUuids, []);
  assert.deepEqual(updated.profiles[1].machineUuids, [removed], "do not broaden a restricted profile");
  assert.equal(updated.jobs[0].state, "cancelled");
  assert.equal(updated.jobs[0].callbackTokenHash, undefined);
  const response = { statusCode: 0, body: "", setHeader() {}, end(value) { this.body = String(value || ""); } };
  api.serveSubscription({ query: { profile: "legacy", format: "uri" }, headers: {} }, response);
  assert.equal(response.statusCode, 200);
  assert.ok(!response.body.includes("legacy-" + removed), "a stale cached snapshot must not publish the removed node");
  await api.refreshSubscriptionSnapshots();
  const snapshot = api.readSubscriptionSnapshot("legacy", "uri");
  assert.ok(!snapshot.body.includes("legacy-" + removed));
  assert.ok(snapshot.body.includes("legacy-" + kept));
  assert.equal(snapshot.sourceHash, api.subscriptionSourceHash(updated, updated.profiles[0], "uri"));
});

test("machine sync rejects malformed lists without deleting existing records", async (t) => {
  let response = {};
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  const { api, store } = runtime(t, { call: async () => response });
  const state = store.read();
  state.machines.push({ uuid, name: "keep" });
  state.instances.push({ id: "keep-node", machineUuid: uuid });
  store.write(state);
  for (const value of [{}, null, [{ name: "missing UUID" }], [{ uuid }, { uuid }]]) {
    response = value;
    await assert.rejects(api.syncMachines(), /机器清单/);
    assert.equal(store.read().machines.length, 1);
    assert.equal(store.read().instances.length, 1);
  }
  response = [];
  await api.syncMachines();
  assert.equal(store.read().machines.length, 0, "a valid empty list removes machines");
});

test("serial discovery submissions use current server state despite a stale page revision", async (t) => {
  let count = 0;
  const fakeBin = fs.mkdtempSync(path.join(os.tmpdir(), "kns-scan-bin-"));
  t.after(() => fs.rmSync(fakeBin, { recursive: true, force: true }));
  for (const name of ["id", "sha256sum"]) fs.writeFileSync(path.join(fakeBin, name), "#!/bin/sh\nprintf '0\\n'\n", { mode: 0o755 });
  const { api, store } = runtime(t, { call: async (method, params) => {
    if (method === "common:getNodesLatestStatus") return Object.fromEntries(params.uuids.map((uuid) => [uuid, { online: true }]));
    assert.equal(method, "admin:exec");
    assert.equal(require("node:child_process").spawnSync("/bin/sh", ["-n", "-c", params.command]).status, 0);
    if (!count) {
      const result = require("node:child_process").spawnSync("/bin/sh", ["-c", params.command], { env: { PATH: fakeBin }, encoding: "utf8" });
      assert.equal(result.status, 127);
      assert.match(result.stdout, /KNS_SCAN_ERROR=missing_bash/);
    }
    return { task_id: "task-" + (++count) };
  } });
  const state = store.read();
  state.settings.setupComplete = true;
  for (let i = 0; i < 26; i++) state.machines.push({ uuid: "123e4567-e89b-42d3-a456-4266141740" + String(i).padStart(2, "0"), name: "machine-" + i, online: true });
  store.write(state);
  const staleRevision = store.read().revision;
  for (const machine of state.machines) {
    const res = { statusCode: 0, body: "", setHeader() {}, end(value) { this.body = value; } };
    await api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify({ action: "machine.discover", machineUuid: machine.uuid, idempotencyKey: machine.uuid, expectedRevision: staleRevision }) }, res);
    assert.equal(JSON.parse(res.body).ok, true);
  }
  assert.equal(count, 26);
  assert.equal(store.read().jobs.length, 26);
  await assert.rejects(api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify({ action: "settings.update", expectedRevision: staleRevision }) }, { setHeader() {}, end() {} }), (error) => error.code === "state_revision_conflict");
});

test("discovery errors expose only recognized scan stages and remote-control failures", async (t) => {
  const responses = { bash: { exit_code: 127, stdout: "KNS_SCAN_ERROR=missing_bash\nsecret output" }, jq: { exit_code: 127, stdout: "KNS_SCAN_ERROR=missing_jq" }, missing: { exit_code: 1, stdout: "KNS_SCAN_ERROR=config_missing" }, disabled: { exit_code: -1, result: "Remote control is disabled." }, unknown: { exit_code: -1, result: "private output" } };
  const { api, store } = runtime(t, { call: async (_method, params) => responses[params.task_id] });
  const state = store.read();
  for (const id of Object.keys(responses)) state.jobs.push({ id, action: "machine.discover", state: "dispatched", machineUuid: "m", taskId: id, createdAt: new Date().toISOString() });
  store.write(state);
  await api.pollPendingJobs();
  const jobs = store.read().jobs;
  assert.match(jobs.find((job) => job.id === "bash").message, /缺少 bash/);
  assert.match(jobs.find((job) => job.id === "jq").message, /缺少 jq/);
  assert.match(jobs.find((job) => job.id === "missing").message, /尚未安装 OneBox/);
  assert.match(jobs.find((job) => job.id === "disabled").message, /远程控制未启用/);
  assert.match(jobs.find((job) => job.id === "unknown").message, /退出码 -1/);
  assert.ok(jobs.every((job) => !/secret output|private output/.test(job.message)));
});

test("deleting a machine while a scan is being submitted does not revive its job", async (t) => {
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  let releaseDispatch, dispatchStarted;
  const started = new Promise((resolve) => { dispatchStarted = resolve; });
  const server = { call: async (method) => {
    if (method === "common:getNodesLatestStatus") return { [uuid]: { online: true } };
    if (method === "admin:exec") { dispatchStarted(); return new Promise((resolve) => { releaseDispatch = resolve; }); }
    if (method === "admin:listClients") return [];
    throw new Error("unexpected RPC " + method);
  } };
  const { api, store } = runtime(t, server);
  const state = store.read(); state.settings.setupComplete = true;
  state.machines.push({ uuid, name: "machine", online: true }); store.write(state);
  const response = { statusCode: 0, body: "", setHeader() {}, end(value) { this.body = value; } };
  const submit = api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify({ action: "machine.discover", machineUuid: uuid, idempotencyKey: "scan" }) }, response);
  await started;
  await api.syncMachines();
  releaseDispatch({ task_id: "task-id" });
  await submit;
  assert.equal(JSON.parse(response.body).ok, false);
  assert.equal(store.read().jobs[0].state, "cancelled");
  assert.equal(store.read().machines.length, 0);
});

test("plugin update package is limited to the latest release and verified before delivery", async (t) => {
  const crypto = require("node:crypto");
  const originalFetch = global.fetch; t.after(() => { global.fetch = originalFetch; });
  const bytes = Buffer.from([0x50, 0x4b, 0x03, 0x04, 1, 2, 3]);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  let checksum = digest; const calls = [];
  global.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith("/latest")) return { ok: true, json: async () => ({ tag_name: "v9.9.9", assets: [{ name: "onebox-bridge.zip", state: "uploaded", size: bytes.length }, { name: "onebox-bridge.zip.sha256", state: "uploaded", size: 84 }] }) };
    if (url.endsWith(".sha256")) return { ok: true, text: async () => checksum + "  onebox-bridge.zip\n" };
    return { ok: true, headers: { get: () => String(bytes.length) }, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  };
  const { api, store } = runtime(t);
  const response = () => ({ headers: {}, chunks: [], setHeader(key, value) { this.headers[key] = value; }, write(chunk) { this.chunks.push(Buffer.from(chunk)); }, end() {} });
  let res = response();
  await api.downloadPluginUpdate({ query: { version: "9.9.9" } }, res);
  assert.deepEqual(Buffer.concat(res.chunks), bytes);
  assert.equal(res.headers["Content-Type"], "application/zip");
  assert.equal(calls.length, 3);
  res = response(); checksum = "0".repeat(64);
  await assert.rejects(api.downloadPluginUpdate({ query: { version: "9.9.9" } }, res), (error) => error.code === "update_checksum_mismatch");
  assert.equal(res.chunks.length, 0);
  await assert.rejects(api.downloadPluginUpdate({ query: { version: "9.9.8" } }, response()), (error) => error.code === "update_version_changed");
  await assert.rejects(api.downloadPluginUpdate({ query: { version: "../../latest" } }, response()), (error) => error.code === "invalid_update_version");
  const state = store.read(); state.jobs.push({ id: "running", state: "running" }); store.write(state);
  await assert.rejects(api.downloadPluginUpdate({ query: { version: "9.9.9" } }, response()), (error) => error.code === "active_jobs_block_maintenance");
});

test("remote dispatch checks live presence and refuses offline or unknown targets", async (t) => {
  let presence = false, execCalls = 0;
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  const { api, store } = runtime(t, { call: async (method) => {
    if (method === "common:getNodesLatestStatus") return presence === null ? {} : { [uuid]: { online: presence } };
    if (method === "admin:exec") { execCalls++; return { task_id: "accepted" }; }
    throw new Error("unexpected RPC");
  } });
  const state = store.read(); state.settings.setupComplete = true;
  state.machines.push({ uuid, name: "probe", online: true }); store.write(state);
  for (const [index, value] of [false, null, true].entries()) {
    presence = value;
    const res = { body: "", setHeader() {}, end(value) { this.body = value; } };
    await api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify({ action: "machine.discover", machineUuid: uuid, idempotencyKey: "scan-" + index }) }, res);
    const result = JSON.parse(res.body);
    assert.equal(result.ok, value === true);
    if (value !== true) assert.match(result.job.message, /未发送远程命令/);
  }
  assert.equal(execCalls, 1);
});

test("a removed and reconnected probe does not automatically deploy a second time", async (t) => {
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  let present = true;
  const { api, store } = runtime(t, { call: async (method) => {
    if (method === "admin:listClients") return present ? [{ uuid, name: "probe" }] : [];
    if (method === "common:getNodesLatestStatus") return { [uuid]: { online: false } };
    throw new Error("unexpected RPC " + method);
  } });
  const state = store.read(); state.settings.setupComplete = true; state.settings.autoProvisionNewProbes = true; store.write(state);
  await api.syncMachines(); assert.equal(store.read().machines[0].autoProvision.state, "queued");
  present = false; await api.syncMachines(); assert.equal(store.read().machines.length, 0);
  present = true; await api.syncMachines();
  assert.equal(store.read().machines[0].autoProvision, undefined);
});

test("a probe removed during presence lookup never receives its queued command", async (t) => {
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  let releasePresence, startedPresence, execCalls = 0;
  const started = new Promise((resolve) => { startedPresence = resolve; });
  const { api, store } = runtime(t, { call: async (method) => {
    if (method === "common:getNodesLatestStatus") { startedPresence(); return new Promise((resolve) => { releasePresence = resolve; }); }
    if (method === "admin:listClients") return [];
    if (method === "admin:exec") { execCalls++; return { task_id: "unexpected" }; }
    throw new Error("unexpected RPC");
  } });
  const state = store.read(); state.settings.setupComplete = true; state.machines.push({ uuid, name: "probe", online: true }); store.write(state);
  const response = { body: "", setHeader() {}, end(value) { this.body = value; } };
  const submit = api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify({ action: "machine.discover", machineUuid: uuid, idempotencyKey: "queued" }) }, response);
  await started; await api.syncMachines(); releasePresence({ [uuid]: { online: true } }); await submit;
  assert.equal(execCalls, 0);
  assert.equal(JSON.parse(response.body).job.state, "cancelled");
});

test("plugin update maintenance lock blocks new actions until explicitly released", async (t) => {
  const { api, store } = runtime(t);
  const state = store.read(); state.settings.setupComplete = true; store.write(state);
  const act = async (body) => {
    const res = { body: "", setHeader() {}, end(value) { this.body = value; } };
    await api.handleAction({ headers: { "content-type": "application/json", host: "monitor.example", origin: "https://monitor.example" }, context: { principal: { roles: ["admin"] } }, body: JSON.stringify(body) }, res);
    return JSON.parse(res.body);
  };
  const locked = await act({ action: "plugin.update.prepare" });
  assert.ok(locked.token);
  await assert.rejects(act({ action: "settings.update" }), (error) => error.code === "maintenance_in_progress");
  await assert.rejects(act({ action: "plugin.update.unlock", token: "incorrect" }), (error) => error.code === "invalid_update_lock");
  assert.equal((await act({ action: "plugin.update.unlock", token: locked.token })).ok, true);
  assert.equal((await act({ action: "plugin.update.prepare" })).ok, true);
});
