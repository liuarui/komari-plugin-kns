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
    module.exports = { publicState, ensureInstance, handleAction, save, syncMachines, subscriptionSourceHash, refreshHealth, refreshEndpoints, refreshSubscriptionSnapshots, readSubscriptionSnapshot, subscriptionSnapshotKey, serveSubscription, recordTokenUsage, flushTokenUsage, pollPendingJobs, assertNoActiveJobs, jobRetryable, encryptedBackupEnvelope, decryptBackupEnvelope, handleAction, readBody, unload };
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
  assert.equal(calls[0][0], "admin:exec");
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
