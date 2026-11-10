"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../pages/admin.html"), "utf8");
function between(start, end) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }

function requestContext(fetch) {
  const context = vm.createContext({ fetch, AbortController, setTimeout, clearTimeout, api: "/api/kns" });
  vm.runInContext(between("  async function request(", "  function setStatus("), context);
  return context;
}

test("admin request timeout remains active while reading the response body", async () => {
  const context = requestContext(async (_url, options) => ({
    ok: true,
    headers: { get: () => "application/json" },
    json: () => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), { once: true });
    }),
  }));
  await assert.rejects(context.request("/admin/state", { timeoutMs: 10 }), (error) => error.code === "request_timeout");
});

test("admin requests preserve structured server errors", async () => {
  const context = requestContext(async () => ({
    ok: false, status: 409,
    headers: { get: () => "application/json" },
    json: async () => ({ error: { message: "conflict", code: "state_revision_conflict", currentRevision: 3, expectedRevision: 2 } }),
  }));
  await assert.rejects(context.request("/admin/action"), (error) => error.code === "state_revision_conflict" && error.currentRevision === 3 && error.expectedRevision === 2);
});

test("connection loss and unreadable responses are reported as an unknown submission", async () => {
  for (const fetch of [async () => { throw new TypeError("connection lost"); }, async () => ({ ok: true, headers: { get: () => "application/json" }, json: async () => { throw new SyntaxError("truncated"); } })]) {
    const context = requestContext(fetch);
    await assert.rejects(context.request("/admin/action", { method: "POST" }), (error) => error.code === "request_response_unknown");
  }
});

test("concurrent admin refreshes queue one fresh read without overlapping or losing drafts", async () => {
  const pending = [];
  const rendered = [];
  let active = 0;
  let maxActive = 0;
  const context = vm.createContext({
    request: () => {
      active += 1; maxActive = Math.max(maxActive, active);
      return new Promise((resolve) => pending.push((value) => { active -= 1; resolve(value); }));
    },
    setStatus() {}, refreshDeploymentJobs() {}, updateDraftControls() {},
    render: () => rendered.push(context.state.revision),
    draftScopes: new Map(), state: null, latestServerSnapshot: null,
    lastSuccessfulRefreshAt: null, draftConflict: null,
  });
  vm.runInContext(between("  let refreshPromise = null;", "  function showSecret("), context);
  const first = context.refresh();
  assert.equal(context.refresh(), first);
  assert.equal(context.refresh(), first);
  assert.equal(pending.length, 1);
  pending.shift()({ revision: 1 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(pending.length, 1);
  pending.shift()({ revision: 2 });
  await first;
  assert.equal(maxActive, 1);
  assert.deepEqual(rendered, [1, 2]);
  context.draftScopes.set("settings", 2);
  const next = context.refresh();
  pending.shift()({ revision: 3 });
  await next;
  assert.equal(context.state.revision, 2);
  assert.equal(context.latestServerSnapshot.revision, 3);
  assert.deepEqual(rendered, [1, 2]);
});

test("legacy HTTP converter settings render as empty so unrelated settings remain saveable", () => {
  const context = vm.createContext({ URL });
  vm.runInContext(between("  function safeConverterUrlInput(", "  function renderSettings("), context);
  for (const value of [
    "http://23.146.156.234:25500/sub",
    "https://user:pass@converter.example/sub",
    "https://converter.example/not-sub",
    "https://converter.example/sub#fragment",
    "not a URL",
  ]) assert.equal(context.safeConverterUrlInput(value), "", value);
  assert.equal(context.safeConverterUrlInput("https://converter.example/sub?keep=1"), "https://converter.example/sub?keep=1");
});

function conflictContext() {
  const latest = { revision: 2, settings: { publicBaseUrl: "https://server.example" }, machines: [], profiles: [] };
  const sent = [];
  const dialogs = [];
  const context = vm.createContext({
    state: { revision: 1 }, latestServerSnapshot: null, draftConflict: null,
    draftScopes: new Map([["settings:connection", 1], ["profile:other", 1]]),
    updateDraftControls() {}, setStatus() {}, trackOperationResult() {},
    showInfoDialog: async (...args) => dialogs.push(args),
    askOperation: async (spec) => { dialogs.push(spec); return {}; },
    request: async (url, options) => {
      if (url === "/admin/state") return latest;
      const body = JSON.parse(options.body);
      sent.push(body);
      if (body.expectedRevision !== latest.revision) throw Object.assign(new Error("conflict"), { code: "state_revision_conflict" });
      return { ok: true };
    },
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  vm.runInContext(between("  async function safeRevisionConflictAction(", "  function renderSetupStep("), context);
  return { context, latest, sent, dialogs };
}

test("confirmed conflict comparison rebases only its draft and next save keeps current input", async () => {
  const { context, sent, dialogs } = conflictContext();
  const body = { action: "settings.update", publicBaseUrl: "https://draft.example" };
  await assert.rejects(context.postAction(body, "settings:connection"));
  await assert.rejects(context.postAction(body, "settings:connection"));
  assert.deepEqual(sent.map((item) => item.expectedRevision), [1, 1], "no automatic overwrite");
  await context.safeRevisionConflictAction();
  assert.equal(context.draftScopes.get("settings:connection"), 2);
  assert.equal(context.draftScopes.get("profile:other"), 1);
  assert.equal(context.state.revision, 1, "other forms keep their original baseline");
  assert.match(dialogs[0].description, /server\.example/);
  assert.match(dialogs[0].description, /draft\.example/);
  assert.equal(sent.length, 2, "confirmation does not submit stale captured fields");
  await context.postAction({ ...body, publicBaseUrl: "https://edited.example" }, "settings:connection");
  assert.equal(sent[2].expectedRevision, 2);
  assert.equal(sent[2].publicBaseUrl, "https://edited.example");
});

test("cancelled comparisons and server changes during confirmation preserve conflict protection", async () => {
  const { context, latest } = conflictContext();
  const body = { action: "settings.update", privateSite: true };
  await assert.rejects(context.postAction(body, "settings:connection"));
  context.askOperation = async () => null;
  await context.safeRevisionConflictAction();
  assert.equal(context.draftScopes.get("settings:connection"), 1);
  context.askOperation = async () => { latest.revision = 3; return {}; };
  await context.safeRevisionConflictAction();
  assert.equal(context.draftScopes.get("settings:connection"), 2, "only the displayed revision is approved");
  await assert.rejects(context.postAction(body, "settings:connection"));
  assert.equal(context.draftConflict.currentRevision, 3);
});

test("a superseded conflict cannot rebase an unrelated or already saved draft", async () => {
  const { context } = conflictContext();
  await assert.rejects(context.postAction({ action: "profile.update", profileId: "other" }, "profile:other"));
  context.askOperation = async () => { context.draftConflict = null; return {}; };
  await context.safeRevisionConflictAction();
  assert.equal(context.draftScopes.get("profile:other"), 1);
});

function installContext() {
  const context = vm.createContext({ URL, Set, state: { jobs: [] }, latestServerSnapshot: null });
  vm.runInContext(between("  const protocolCatalog =", "  function selectedProtocolIds("), context);
  vm.runInContext(between("  function formatEndpointHost(", "  function currentInstallNetwork("), context);
  vm.runInContext(between("  function machineHasUnconfirmedDispatch(", "  function runtimeStateLabel("), context);
  return context;
}
const machineFixture = (uuid = "a") => ({ uuid, name: uuid, online: true, ipv4: "8.8.8.8", ipv6: "2606:4700:4700::1111", policy: { deployAllowed: true, addressMode: "auto" } });
const planFixture = () => ({ machines: [machineFixture()], instances: [], jobs: [] });
const networkFixture = () => ({ nat: false, endpointHost: "", listenAddress: "::" });

test("auto ports ignore unrelated/deleted nodes and reserve stopped registered nodes", () => {
  const api = installContext();
  const used = api.occupiedListenPorts([
    { machineUuid: "a", enabled: false, listen: { port: 443 } },
    { machineUuid: "a", deletedAt: "yesterday", listen: { port: 444 } },
    { machineUuid: "b", listen: { port: 445 } },
  ], ["a"]);
  assert.deepEqual([...used], [443]);
  assert.equal(api.allocatePort(443, used), 444);
  used.add(444);
  assert.equal(api.allocatePort(443, used), 445);
  assert.equal(api.allocatePort(65535, new Set([65535])), 65535, "preflight rejects exhaustion rather than overflowing");
});

test("auto ports share TCP/UDP listeners and only skip overlapping transports", () => {
  const api = installContext();
  const instances = [{ machineUuid: "a", listen: { port: 443, transport: "tcp" } }];
  assert.deepEqual([...api.occupiedListenPorts(instances, ["a"], "tcp")].sort(), [443]);
  assert.deepEqual([...api.occupiedListenPorts(instances, ["a"], "udp")], []);
  const occupancy = api.listenPortOccupancy(instances, ["a"]);
  const assigned = (...args) => JSON.parse(JSON.stringify(api.assignAutoPorts(...args)));
  assert.deepEqual(assigned(443, [{ id: "hysteria2", transport: "udp" }], occupancy), { hysteria2: 443 });
  assert.equal(api.installPreflight({ machines: [machineFixture()], instances, jobs: [] }, ["a"], [{ id: "hysteria2", listenPort: 443 }], networkFixture()).length, 0);
  assert.deepEqual(assigned(443, [{ id: "vless", transport: "tcp" }], occupancy), { vless: 444 });
  assert.deepEqual(assigned(443, [{ id: "vless", transport: "tcp" }, { id: "hysteria2", transport: "udp" }], { tcp: new Set(), udp: new Set() }), { vless: 443, hysteria2: 443 });
  assert.deepEqual(assigned(443, [{ id: "vless", transport: "tcp" }, { id: "trojan", transport: "tcp" }], { tcp: new Set(), udp: new Set() }), { vless: 443, trojan: 444 });
  assert.deepEqual(assigned(443, [{ id: "hysteria2", transport: "udp" }], api.listenPortOccupancy([{ machineUuid: "a", listen: { port: 443, transport: "tcp+udp" } }], ["a"])), { hysteria2: 444 });
  assert.deepEqual(assigned(443, [{ id: "vless", transport: "tcp", manual: 445 }, { id: "trojan", transport: "tcp" }], { tcp: new Set([443]), udp: new Set() }), { vless: 445, trojan: 444 });
});

test("preflight blocks registered/planned transport conflicts but permits TCP and UDP separation", () => {
  const api = installContext(); const state = planFixture();
  state.instances.push({ machineUuid: "a", listen: { port: 443, transport: "tcp" } });
  assert.match(api.installPreflight(state, ["a"], [{ id: "vless", listenPort: 443 }], networkFixture()).join(), /已登记节点冲突/);
  assert.equal(api.installPreflight(state, ["a"], [{ id: "hysteria2", listenPort: 443 }], networkFixture()).length, 0);
  state.instances = [];
  assert.match(api.installPreflight(state, ["a"], [{ id: "vless", listenPort: 443 }, { id: "trojan", listenPort: 443 }], networkFixture()).join(), /监听端口冲突/);
  assert.equal(api.installPreflight(state, ["a"], [{ id: "vless", listenPort: 443 }, { id: "hysteria2", listenPort: 443 }], networkFixture()).length, 0);
});

test("preflight catches NAT conflicts across machines and equivalent IPv6 spellings", () => {
  const api = installContext(); const state = planFixture();
  state.machines.push(machineFixture("b"));
  const net = { ...networkFixture(), nat: true, endpointHost: "shared.example" };
  assert.match(api.installPreflight(state, ["a", "b"], [{ id: "vless", listenPort: 443, externalPort: 30443 }], net).join(), /公网地址/);
  state.instances.push({ machineUuid: "other", listen: { port: 99, transport: "tcp" }, nat: { externalPort: 30443, publicHosts: ["2606:4700:4700:0:0:0:0:1111"] } });
  net.endpointHost = "2606:4700:4700::1111";
  assert.match(api.installPreflight(state, ["a"], [{ id: "vless", listenPort: 443, externalPort: 30443 }], net).join(), /公网地址/);
});

test("preflight blocks missing family, IPv4-only listener, stale machine and active runtime", () => {
  const api = installContext(); const state = planFixture(); const protocol = [{ id: "vless", listenPort: 443 }];
  state.machines[0].policy.addressMode = "ipv6"; state.machines[0].ipv6 = "";
  assert.match(api.installPreflight(state, ["a"], protocol, networkFixture()).join(), /地址族没有可用地址/);
  state.machines[0].ipv6 = "2606:4700:4700::1111";
  assert.match(api.installPreflight(state, ["a"], protocol, { ...networkFixture(), listenAddress: "0.0.0.0" }).join(), /仅 IPv4 监听/);
  state.jobs.push({ machineUuid: "a", state: "verifying" });
  assert.match(api.installPreflight(state, ["a"], protocol, networkFixture()).join(), /未完成任务/);
  assert.match(api.installPreflight(state, ["gone"], protocol, networkFixture()).join(), /已不存在/);
  assert.match(api.installPreflight(state, ["a"], protocol, { ...networkFixture(), nat: true, endpointHost: "https://bad.example/path" }).join(), /不要包含协议/);
});

test("preflight blocks new installs while a remote dispatch needs reconciliation", () => {
  const api = installContext(); const state = planFixture();
  state.jobs.push({ machineUuid: "a", action: "install", state: "needs_reconcile", dispatchUncertain: true });
  const errors = api.installPreflight(state, ["a"], [{ id: "vless", listenPort: 443 }], networkFixture());
  assert.match(errors.join(), /上一条远程命令是否送达尚未确认/);
});

test("install review skips offline targets while checking online targets", () => {
  let checked = null; const statuses = [];
  const context = vm.createContext({
    state: { machines: [{ uuid: "online", online: true }, { uuid: "offline", online: false }] }, latestServerSnapshot: null,
    selectedMachineIds: () => ["online", "offline"], currentProtocolFields: () => [], currentInstallNetwork: () => ({}),
    machineInstallAllowed: (machine) => machine.online === true,
    machineHasUnconfirmedDispatch: () => false,
    installPreflight: (_snapshot, ids) => { checked = Array.from(ids); return []; },
    setStatus: (_id, message) => statuses.push(message),
  });
  vm.runInContext(between("  function showInstallPreflight(", "  function updateConnectionPreview("), context);
  assert.equal(context.showInstallPreflight(), true);
  assert.deepEqual(checked, ["online"]);
  context.state.machines[0].online = false;
  assert.equal(context.showInstallPreflight(), false);
  assert.match(statuses.at(-1), /都不能安装/);
});

test("inline results advance only with actual backend job states even without a deployment batch", () => {
  const statuses = new Map();
  const context = vm.createContext({ operationJobs: new Map(), deploymentBatch: [],
    setMachineStatus: (id, message, kind) => statuses.set(`machine:${id}`, { message, kind }),
    setInstanceStatus: (id, message, kind) => statuses.set(`instance:${id}`, { message, kind }),
  });
  vm.runInContext(between("  function trackOperationResult(", "  function healthLabel("), context);
  vm.runInContext(between("  function friendlyJobMessage(", "  async function updatePolicy("), context);
  vm.runInContext(between("  function refreshDeploymentJobs(", "  async function waitForInstallBatch("), context);
  context.trackOperationResult({ instanceId: "node" }, { job: { id: "job", instanceId: "node" } });
  for (const state of ["dispatched", "running", "verifying", "needs_reconcile", "failed", "succeeded"]) {
    context.refreshDeploymentJobs({ jobs: [{ id: "job", state }] });
    const result = statuses.get("instance:node");
    assert.equal(result.kind === "success", state === "succeeded");
    assert.match(result.message, /任务编号 job/);
    if (state === "needs_reconcile") assert.match(result.message, /尚未取得完整结果/);
  }
});

test("setup gate never re-enables offline machine or stale maintenance buttons", () => {
  const controls = new Map(); const offline = { disabled: true }; const stale = { disabled: true };
  const context = vm.createContext({ state: { settings: { setupComplete: true } }, installPlanRunning: true, batchClaimRunning: false, legacyScanRunning: false,
    $: (id) => { if (!controls.has(id)) controls.set(id, {}); return controls.get(id); },
    document: { querySelectorAll: (selector) => selector.includes("button") ? [offline, stale] : [] },
  });
  vm.runInContext(between("  function applySetupGate(", "  let protocolCardsReady="), context);
  context.applySetupGate();
  assert.equal(offline.disabled, true); assert.equal(stale.disabled, true);
  assert.equal(controls.get("installBatch").disabled, true);
});

test("install.batch uses the latest server revision instead of a frozen deploy draft", async () => {
  const posts = [];
  const context = vm.createContext({
    request: async (url, options) => {
      if (url === "/admin/action") { posts.push(JSON.parse(options.body)); return { ok: true }; }
      throw new Error("unexpected " + url);
    },
    trackOperationResult() {}, setStatus() {}, updateDraftControls() {},
    draftScopes: new Map([["deploy", 1]]), state: { revision: 1 }, latestServerSnapshot: { revision: 4 },
    draftConflict: null,
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  await context.postAction({ action: "install.batch", machineUuids: ["machine"], protocol: "vless", confirm: true }, "deploy");
  assert.equal(posts[0].expectedRevision, 4);
  assert.equal(context.draftScopes.has("deploy"), false);
  context.draftScopes.set("settings:connection", 1);
  context.draftScopes.set("settings:connection", 1);
  await context.postAction({ action: "settings.update", publicBaseUrl: "https://monitor.example" }, "settings:connection");
  assert.equal(posts[1].expectedRevision, 1, "settings drafts still use the frozen revision");
});

test("profile edits send their own version despite unrelated global changes", async () => {
  const sent = [];
  const context = vm.createContext({
    state: { revision: 1, profiles: [{ id: "p", editVersion: "original-profile" }] },
    latestServerSnapshot: { revision: 7, profiles: [{ id: "p", editVersion: "original-profile" }] },
    draftScopes: new Map([["profile:p", 1]]), draftConflict: null,
    trackOperationResult() {}, updateDraftControls() {},
    request: async (_url, options) => { sent.push(JSON.parse(options.body)); return { ok: true }; },
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  await context.postAction({ action: "profile.update", profileId: "p", name: "edited" }, "profile:p");
  assert.equal(sent[0].expectedEditVersion, "original-profile");
  assert.equal(sent[0].expectedRevision, 1);
});

test("saving a draft temporarily locks its controls and restores their prior state", async () => {
  let finish;
  const fields = [{ disabled: false }, { disabled: true }, { disabled: false }];
  const context = vm.createContext({
    document: { querySelectorAll: () => fields },
    state: { revision: 1, profiles: [{ id: "p", editVersion: "v1" }] }, latestServerSnapshot: null,
    draftScopes: new Map([["profile:p", 1]]), draftConflict: null,
    request: () => new Promise((resolve) => { finish = resolve; }), trackOperationResult() {}, updateDraftControls() {},
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  const saving = context.postAction({ action: "profile.update", profileId: "p" }, "profile:p");
  assert.deepEqual(fields.map((field) => field.disabled), [true, true, true]);
  finish({ ok: true }); await saving;
  assert.deepEqual(fields.map((field) => field.disabled), [false, true, false]);
});


test("setup.complete uses the latest revision while connection settings keep their draft baseline", async () => {
  const sent = [];
  const context = vm.createContext({
    state: { revision: 1 }, latestServerSnapshot: { revision: 4 }, draftConflict: null,
    draftScopes: new Map([["setup", 1], ["settings:connection", 1]]),
    trackOperationResult() {}, updateDraftControls() {},
    request: async (url, options) => {
      assert.equal(url, "/admin/action");
      const body = JSON.parse(options.body);
      sent.push(body);
      return { ok: true };
    },
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  await context.postAction({ action: "setup.complete", publicBaseUrl: "https://monitor.example", autoProvisionNewProbes: false }, "setup");
  assert.equal(sent[0].expectedRevision, 4);
  assert.equal(sent[0].autoProvisionNewProbes, false);
  assert.equal(context.draftScopes.has("setup"), false);
  assert.equal(context.draftScopes.get("settings:connection"), 1);
  await context.postAction({ action: "settings.update", publicBaseUrl: "https://draft.example" }, "settings:connection");
  assert.equal(sent[1].expectedRevision, 1);
  assert.equal(context.state.revision, 1, "setup submission must not rebase other forms");
});

function policyConflictContext() {
  const policy = { deployAllowed: false, addressMode: "auto", manualAddress: "8.8.8.8", ddnsHostname: "", tags: [] };
  let server = { revision: 2, machines: [{ uuid: "machine", name: "node", policy }], profiles: [], settings: {} };
  const sent = [], statuses = [], dialogs = [];
  let confirm;
  const context = vm.createContext({
    state: { revision: 1, machines: [{ uuid: "machine" }] }, latestServerSnapshot: null, draftConflict: null,
    draftScopes: new Map([["machine:machine", 1]]), lastSuccessfulRefreshAt: null,
    trackOperationResult() {}, updateDraftControls() {}, refreshDeploymentJobs() {}, setStatus() {},
    render() { throw new Error("drafts must not be redrawn while confirmation is pending"); },
    setMachineStatus: (_id, message, kind) => statuses.push({ message, kind }),
    askOperation: (spec) => { dialogs.push(spec); return new Promise((resolve) => { confirm = resolve; }); },
    request: async (url, options) => {
      if (url === "/admin/state") return structuredClone(server);
      const body = JSON.parse(options.body);
      sent.push(body);
      if (body.expectedRevision !== server.revision) throw Object.assign(new Error("conflict"), { code: "state_revision_conflict" });
      server.machines[0].policy = body.policy;
      server.revision += 1;
      return { ok: true };
    },
  });
  vm.runInContext(between("  const remoteTaskActions = new Set(", "  function idempotencyKey("), context);
  vm.runInContext(between("  async function updatePolicy(", "  async function discoverLegacyNodes("), context);
  vm.runInContext(between("  let refreshPromise = null;", "  function showSecret("), context);
  const controls = {
    deploy: { checked: true }, mode: { value: "ipv4" }, manual: { value: "1.1.1.1" },
    ddns: { value: "draft.example" }, tags: { value: "draft" }, unmanaged: { checked: false },
  };
  const row = { querySelector: (selector) => controls[selector.match(/=([^\]]+)/)[1]] };
  return {
    context, sent, statuses, dialogs, row,
    confirm: (answer) => confirm(answer),
    server: () => server,
    changeServer: () => { server.revision = 3; server.machines[0].policy.manualAddress = "9.9.9.9"; },
  };
}

for (const scenario of ["refresh during confirmation", "no concurrent update", "cancel"]) {
  test("machine policy conflict: " + scenario, async () => {
    const fixture = policyConflictContext();
    const { context, sent, dialogs, row, statuses } = fixture;
    const saving = context.updatePolicy("machine", row);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(dialogs.length, 1);
    assert.match(dialogs[0].description, /8\.8\.8\.8/);
    assert.match(dialogs[0].description, /1\.1\.1\.1/);
    if (scenario === "refresh during confirmation") {
      fixture.changeServer();
      await context.refresh();
      assert.equal(context.latestServerSnapshot.revision, 3);
      assert.doesNotMatch(dialogs[0].description, /9\.9\.9\.9/);
    }
    // After a successful retry, rendering is allowed; pending drafts must still be protected above.
    context.render = () => {};
    fixture.confirm(scenario === "cancel" ? null : {});
    await saving;
    if (scenario === "cancel") {
      assert.deepEqual(sent.map((body) => body.expectedRevision), [1]);
      assert.equal(fixture.server().machines[0].policy.manualAddress, "8.8.8.8");
    } else {
      assert.deepEqual(sent.map((body) => body.expectedRevision), [1, 2]);
      if (scenario === "refresh during confirmation") {
        assert.equal(fixture.server().machines[0].policy.manualAddress, "9.9.9.9");
        assert.equal(context.draftConflict.currentRevision, 3);
        assert.equal(context.draftConflict.relevant.policy.manualAddress, "9.9.9.9");
        assert.equal(context.draftScopes.get("machine:machine"), 1);
        assert.ok(!statuses.some((status) => status.kind === "success"));
      } else {
        assert.equal(fixture.server().machines[0].policy.manualAddress, "1.1.1.1");
        assert.equal(context.draftScopes.has("machine:machine"), false);
        assert.ok(statuses.some((status) => status.kind === "success"));
      }
    }
  });
}


test("admin page follows the Komari host theme instead of only the system color scheme", () => {
  const css = between("<style>", "</style>");
  assert.match(css, /html\[data-kns-theme="dark"\]/);
  assert.match(css, /html\[data-kns-theme="light"\]/);
  assert.match(css, /background: Canvas/);
  assert.doesNotMatch(css, /\.qr-panel \{[^}]*background:#fff/);
  assert.match(css, /\.qr-panel svg \{[^}]*background:#fff/);

  function themeContext(options) {
    const parentRoot = {
      className: options.parentClass || "",
      attributes: { "data-theme": options.parentDataTheme || "" },
      getAttribute(name) { return this.attributes[name] || ""; },
      style: {},
    };
    parentRoot.classList = { contains(name) { return (" " + parentRoot.className + " ").includes(" " + name + " "); } };
    const observers = [];
    const mediaListeners = [];
    const iframeRoot = { dataset: {}, style: {} };
    const parentWin = {
      document: { documentElement: parentRoot },
      getComputedStyle() { return { colorScheme: options.parentColorScheme || "" }; },
    };
    const win = {
      parent: options.standalone ? null : parentWin,
      document: { documentElement: iframeRoot },
      matchMedia(query) {
        return {
          matches: options.systemDark === true && query.includes("prefers-color-scheme: dark"),
          addEventListener(_type, listener) { mediaListeners.push(listener); },
          addListener(listener) { mediaListeners.push(listener); },
        };
      },
    };
    if (options.standalone) win.parent = win;
    const context = vm.createContext({ window: win, document: win.document, MutationObserver: class {
      constructor(callback) { this.callback = callback; observers.push(this); }
      observe(target, spec) { this.target = target; this.spec = spec; }
    } });
    const start = source.lastIndexOf("  function hostTheme(win) {");
    const end = source.indexOf("  watchHostTheme();", start);
    vm.runInContext(source.slice(start, end), context);
    return { context, iframeRoot, parentRoot, observers, mediaListeners, win };
  }

  const darkHost = themeContext({ parentClass: "dark", systemDark: false });
  assert.equal(darkHost.context.hostTheme(darkHost.win), "dark");
  assert.equal(darkHost.context.applyHostTheme(darkHost.win), "dark");
  assert.equal(darkHost.iframeRoot.dataset.knsTheme, "dark");
  assert.equal(darkHost.iframeRoot.style.colorScheme, "dark");

  const lightHost = themeContext({ parentClass: "light", parentDataTheme: "light", systemDark: true });
  assert.equal(lightHost.context.hostTheme(lightHost.win), "light", "Komari light theme wins over system dark");

  const schemeHost = themeContext({ parentColorScheme: "dark", systemDark: false });
  assert.equal(schemeHost.context.hostTheme(schemeHost.win), "dark");

  const standaloneDark = themeContext({ standalone: true, systemDark: true });
  assert.equal(standaloneDark.context.hostTheme(standaloneDark.win), "dark");
  const standaloneLight = themeContext({ standalone: true, systemDark: false });
  assert.equal(standaloneLight.context.hostTheme(standaloneLight.win), "light");

  const watched = themeContext({ parentClass: "", systemDark: false });
  watched.context.watchHostTheme(watched.win);
  assert.equal(watched.iframeRoot.dataset.knsTheme, "light");
  assert.equal(watched.observers.length, 1);
  assert.equal(Array.from(watched.observers[0].spec.attributeFilter).join(","), "class,data-theme,style");
  watched.parentRoot.className = "dark";
  watched.observers[0].callback();
  assert.equal(watched.iframeRoot.dataset.knsTheme, "dark");
  assert.equal(watched.iframeRoot.style.colorScheme, "dark");
});


test("attention todos render above the machine list and the metric can jump to them", () => {
  const todosAt = source.indexOf('id="overviewTodosCard"');
  const machinesAt = source.indexOf('id="machineRows"');
  const metricsAt = source.indexOf('id="metrics"');
  assert.ok(metricsAt > 0 && todosAt > metricsAt && todosAt < machinesAt, "todos card must sit after metrics and before the machine list");
  assert.match(source, /box.id="attentionMetric"/);
  assert.match(source, /card.scrollIntoView/);
  assert.match(source, /todosCard.hidden = !hasAttention/);
});


test("subscription tab keeps the profile list and opens a separate editor", () => {
  const start = source.indexOf('id="subscriptions"');
  const end = source.indexOf('id="settings"');
  const section = source.slice(start, end);
  assert.match(section, /id="profileRows"/);
  assert.match(section, /id="openProfileDrawer"/);
  assert.doesNotMatch(section, /id="profileName"/);
  assert.match(source, /id="profileDrawer"/);
  assert.match(source, /id="profileName"[^>]*placeholder="新订阅"/);
  assert.match(source, /包含机器/);
  assert.match(source, /排除机器/);
  assert.match(source, /搜索机器名称或 UUID/);
  assert.ok(source.indexOf('id="overviewTodosCard"') < source.indexOf('id="machineRows"'), "todo card order from UX-0002 must remain");
});


test("reconcile job details offer a check action and info dialogs hide cancel", async () => {
  const asked = [];
  const actions = [];
  const context = vm.createContext({
    state: {
      instances: [{ id: "node", machineUuid: "machine" }],
      machines: [{ uuid: "machine", name: "probe" }],
    },
    draftScopes: new Map(),
    document: { querySelector() { return { querySelector() { return { open: false }; }, scrollIntoView() {}, classList: { add() {}, remove() {} } }; } },
    CSS: { escape: (value) => value },
    instanceAction: async (instance, action) => { actions.push([instance.id, action]); },
    askOperation: async (spec) => { asked.push(spec); return {}; },
    setStatus() {},
    jobNextStep: () => "next",
    renderMachines() {},
    $: () => ({ value: "", checked: false, classList: { contains: () => true } }),
    setTimeout,
  });
  vm.runInContext(source.slice(source.indexOf("  function focusMachine(uuid){"), source.indexOf("  function renderJobs(){")), context);

  await context.showJobDetail({ id: "job", instanceId: "node", machineUuid: "machine", state: "needs_reconcile", action: "machine.import" });
  assert.equal(asked[0].confirmLabel, "核查该机器");
  assert.equal(asked[0].hideCancel, undefined);
  assert.deepEqual(actions, [["node", "status"]]);

  asked.length = 0; actions.length = 0;
  await context.showJobDetail({ id: "job2", machineUuid: "machine", state: "timed_out", action: "machine.import" });
  assert.equal(asked[0].confirmLabel, "转到该机器");
  assert.deepEqual(actions, []);

  asked.length = 0;
  await context.showJobDetail({ id: "job3", machineUuid: "machine", state: "succeeded", action: "install" });
  assert.equal(asked[0].confirmLabel, "关闭");
  assert.equal(asked[0].hideCancel, true);

  assert.match(source, /hideCancel: true/);
  const section = source.slice(source.indexOf('id="subscriptions"'), source.indexOf('id="settings"'));
  assert.match(section, /id="profileRows"/);
  assert.match(section, /id="openProfileDrawer"/);
});


test("legacy imported node cards expose a status check without lifecycle actions", () => {
  const start = source.indexOf('const controls=el("div",null,"row-actions node-actions")');
  const block = source.slice(start, source.indexOf("card.append(controls);", start));
  const checkAt = block.indexOf('actionButton("核查"');
  const gateAt = block.indexOf('managedBy!=="legacy_import"');
  assert.ok(checkAt >= 0 && checkAt < gateAt, "status check must be available for imported nodes");
  assert.match(block.slice(gateAt), /卸载/);
  assert.doesNotMatch(block.slice(0, gateAt), /卸载/);
});


test("install wizard defaults to authorized online machines and explains an empty list", () => {
  assert.match(source, /id="onlyAllowedMachines"[^>]*\bchecked\b/);
  const rows = [];
  const host = { replaceChildren() { rows.length = 0; }, append(...nodes) { rows.push(...nodes); } };
  const checkbox = { checked: true };
  const search = { value: "" };
  const context = vm.createContext({
    state: { machines: [
      { uuid: "ok", name: "free", online: true, policy: { deployAllowed: true } },
      { uuid: "offline", name: "offline", online: false, policy: { deployAllowed: true } },
      { uuid: "denied", name: "denied", online: true, policy: { deployAllowed: false } },
    ] },
    $: (id) => id === "installMachines" ? host : id === "onlyAllowedMachines" ? checkbox : search,
    el: (tag, text, cls) => ({ tag, text, cls, children: [], prepend(...nodes) { this.children.unshift(...nodes); }, append(...nodes) { this.children.push(...nodes); } }),
    document: { createElement(tag) { return { tag, type: "", value: "", checked: false, disabled: false, dataset: {}, addEventListener() {} }; } },
    installMachineSelection: new Set(),
    draftScopes: new Map(),
    machineHasUnconfirmedDispatch: () => false,
    machineInstallBlockReason(machine) { return machine.online !== true ? "机器离线或状态未知。" : machine.policy && machine.policy.deployAllowed ? "" : "此机器尚未授权远程安装。"; },
    machineInstallAllowed(machine) { return machine.online === true && !!(machine.policy && machine.policy.deployAllowed); },
    updateDraftControls() {},
    recomputeAutoPorts() {},
    updateConnectionPreview() {},
  });
  vm.runInContext(between("  function renderInstallMachineOptions(){", "  function wait(milliseconds)"), context);
  context.renderInstallMachineOptions();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].children.some((child) => child.text === "free"), true);
  checkbox.checked = true;
  context.state.machines.forEach((machine) => { machine.online = false; });
  context.renderInstallMachineOptions();
  assert.equal(rows.length, 1);
  assert.match(rows[0].text, /没有可安装机器/);
  checkbox.checked = false;
  search.value = "no-match";
  context.state.machines[0].online = true;
  context.renderInstallMachineOptions();
  assert.match(rows[0].text, /没有符合搜索条件/);
  const start = source.indexOf('const controls=el("div",null,"row-actions node-actions")');
  const block = source.slice(start, source.indexOf("card.append(controls);", start));
  assert.ok(block.indexOf('actionButton("核查"') < block.indexOf('managedBy!=="legacy_import"'), "legacy import check button from UX-0005 must remain");
});

test("attention todos skip resolved import jobs and duplicate reconcile rows", () => {
  const context = vm.createContext({});
  vm.runInContext(between("  function attentionJobs(", "  function renderOverview("), context);
  const selected = context.attentionJobs({
    instances: [{ id: "imported", machineUuid: "m", legacyTag: "tag-a" }],
    jobs: [
      { id: "new-fail", action: "install", state: "failed", machineUuid: "x" },
      { id: "import-resolved", action: "machine.import", state: "needs_reconcile", machineUuid: "m", legacyTag: "tag-a" },
      { id: "import-open", action: "machine.import", state: "needs_reconcile", machineUuid: "m", legacyTag: "tag-b" },
      { id: "import-dup", action: "machine.import", state: "needs_reconcile", machineUuid: "m", legacyTag: "tag-b" },
      { id: "import-done", action: "machine.import", state: "succeeded", machineUuid: "m", legacyTag: "tag-c" },
      { id: "import-old", action: "machine.import", state: "needs_reconcile", machineUuid: "m", legacyTag: "tag-c" },
      { id: "scan-fail", action: "machine.discover", state: "failed", machineUuid: "m" },
    ],
  });
  assert.equal(Array.from(selected, (job) => job.id).join(","), "new-fail,import-open");
});

test("acknowledging a task or health incident hides only that occurrence", () => {
  const context = vm.createContext({});
  vm.runInContext(between("  function attentionJobs(", "  function renderOverview("), context);
  const snapshot = { instances: [], jobs: [
    { id: "old", action: "install", state: "failed", machineUuid: "m", createdAt: "2026-11-10T00:00:00Z" },
    { id: "new", action: "install", state: "failed", machineUuid: "m", createdAt: "2026-11-10T01:00:00Z", attentionAcknowledgedAt: "now", attentionAcknowledgedState: "failed" },
  ] };
  assert.equal(context.attentionJobs(snapshot).length, 0, "acknowledging the latest failure does not reveal an older failure");
  snapshot.jobs.push({ id: "later", action: "install", state: "failed", machineUuid: "m", createdAt: "2026-11-10T02:00:00Z" });
  assert.equal(context.attentionJobs(snapshot)[0].id, "later");
  const node = { id: "n", health: { state: "unhealthy" } };
  assert.equal(context.attentionHealth(node), true);
  node.health.attentionIncidentId = "first"; node.health.attentionAcknowledgedIncidentId = "first";
  assert.equal(context.attentionHealth(node), false);
  node.health.attentionIncidentId = "second";
  assert.equal(context.attentionHealth(node), true);
});


test("admin footer binds the running plugin version instead of a hardcoded 1.3.0 tag", () => {
  assert.doesNotMatch(source, /Komari KNS v1\.3\.0/);
  assert.match(source, /id="pluginVersionLabel"/);
  assert.match(source, /id="pluginSourceLink"/);
  assert.match(source, /id="checkPluginUpdate"/);
  assert.match(source, /action:"plugin.update.check"/);
  const context = vm.createContext({
    state: { pluginVersion: "9.9.9", sourceUrl: "https://github.com/liuarui/komari-plugin-kns/tree/v9.9.9", settings: {}, backups: [] },
    $: (id) => context.nodes[id] || (context.nodes[id] = { id, textContent: "", href: "", value: "", checked: false, replaceChildren() {}, disabled: false }),
    nodes: {},
    el: (tag, text) => ({ tag, text }),
    safeConverterUrlInput: (value) => value || "",
  });
  const start = source.indexOf("  function renderSettings(){");
  const end = source.indexOf("  function renderAudit(){");
  vm.runInContext(source.slice(start, end), context);
  context.renderSettings();
  assert.equal(context.nodes.pluginVersionLabel.textContent, "Komari KNS v9.9.9");
  assert.equal(context.nodes.pluginSourceLink.href, "https://github.com/liuarui/komari-plugin-kns/tree/v9.9.9");
  assert.equal(context.nodes.runningVersion.textContent, "当前运行版本 v9.9.9");
});


test("format change keeps copy and QR disabled before setup is complete", () => {
  const copy = { disabled: true };
  const qr = { disabled: true };
  const context = vm.createContext({
    state: { settings: { setupComplete: false }, profiles: [{ id: "profile", name: "默认订阅", formats: ["uri"] }] },
    $: (id) => id === "copyHomeSubscription" ? copy : qr,
    homeSubscriptionProfile() { return context.state.profiles[0]; },
  });
  const start = source.indexOf("  function homeSubscriptionActionsDisabled(profile){");
  const end = source.indexOf("  async function createHomeSubscriptionLink");
  vm.runInContext(source.slice(start, end), context);
  context.updateHomeSubscriptionActions(context.homeSubscriptionProfile());
  assert.equal(copy.disabled, true);
  assert.equal(qr.disabled, true);
  context.state.settings.setupComplete = true;
  context.updateHomeSubscriptionActions(context.homeSubscriptionProfile());
  assert.equal(copy.disabled, false);
  assert.equal(qr.disabled, false);
  context.updateHomeSubscriptionActions(null);
  assert.equal(copy.disabled, true);
  assert.match(source, /homeSubscriptionFormat"\)\.addEventListener\("change",\(\)=>updateHomeSubscriptionActions\(homeSubscriptionProfile\(\)\)\)/);
});


test("check-update control exists before the page script binds it so refresh still runs", () => {
  const footerAt = source.indexOf('id="checkPluginUpdate"');
  const bindAt = source.indexOf('const checkPluginUpdate=$("checkPluginUpdate")');
  const refreshAt = source.lastIndexOf("refresh();setInterval");
  const scriptEnd = source.indexOf("</script>", bindAt);
  assert.ok(footerAt > 0 && footerAt < bindAt, "footer button must exist in DOM before the listener is attached");
  assert.ok(bindAt < refreshAt && refreshAt < scriptEnd, "refresh() must remain reachable after the optional listener");
  assert.match(source.slice(bindAt, refreshAt), /if\(checkPluginUpdate\)checkPluginUpdate\.addEventListener/);
});


test("check-update copy distinguishes equal, older, and newer GitHub latest tags", () => {
  const context = vm.createContext({});
  const start = source.indexOf("  function pluginUpdateStatusMessage(result){");
  const end = source.indexOf("  const checkPluginUpdate=$(\"checkPluginUpdate\");");
  vm.runInContext(source.slice(start, end), context);
  const older = context.pluginUpdateStatusMessage({ updateAvailable: false, currentVersion: "1.3.0", latestVersion: "1.2.3" });
  assert.match(older, /v1\.2\.3/);
  assert.match(older, /v1\.3\.0/);
  assert.doesNotMatch(older, /一致/);
  const same = context.pluginUpdateStatusMessage({ updateAvailable: false, currentVersion: "1.3.0", latestVersion: "1.3.0" });
  assert.match(same, /一致/);
  const newer = context.pluginUpdateStatusMessage({ updateAvailable: true, currentVersion: "1.3.0", latestVersion: "1.3.1" });
  assert.match(newer, /发现新版本 v1\.3\.1/);
  assert.doesNotMatch(source, /function compareSemver/);
});

test("scan and claim all waits for this scan and skips offline or failed machines", async () => {
  const actions = [], status = [], rendered = [];
  const node = (tag) => ({ tag, protocol: "vless", importable: true, managed: false, listen: { port: 443, transport: "tcp" } });
  const machines = [
    { uuid: "a", name: "online", online: true, policy: { tags: [] }, discoveredNodes: [node("first"), node("second")] },
    { uuid: "b", name: "scan failure", online: true, policy: {}, discoveredNodes: [node("stale")] },
    { uuid: "c", name: "offline", online: false, policy: {}, discoveredNodes: [node("offline")] },
    { uuid: "d", name: "unmanaged", online: true, policy: { managementTags: ["不纳管"] }, discoveredNodes: [node("excluded")] },
  ];
  const snapshot = { machines, instances: [], jobs: [] };
  const elements = { batchClaimResults: { replaceChildren() {}, append(value) { rendered.push(value.text); } }, scanAndClaimAll: {}, scanLegacySelected: {} };
  const context = vm.createContext({
    state: snapshot, latestServerSnapshot: null, lastSuccessfulRefreshAt: null, draftScopes: new Map(), installPlanRunning: false, batchClaimRunning: false, legacyScanRunning: false,
    $: (id) => elements[id], el: (_tag, text) => ({ text }), setStatus: (_id, text) => status.push(text),
    askOperation: async () => ({}), request: async () => snapshot, wait: async () => {}, refresh: async () => {}, idempotencyKey: () => "fixture",
    postAction: async (body) => {
      actions.push(body);
      const job = { id: "job-" + actions.length, state: body.action === "machine.discover" && body.machineUuid === "b" ? "failed" : "succeeded", message: "scan failed" };
      snapshot.jobs.push(job);
      return { ok: true, job };
    },
  });
  vm.runInContext(between("  async function waitForBatchClaimJob(", "  function selectOnlineLegacyScanMachines("), context);
  await context.scanAndClaimAll();
  assert.deepEqual(actions.map((item) => [item.action, item.machineUuid, item.legacyTag]), [
    ["machine.discover", "a", undefined], ["machine.import", "a", "first"], ["machine.import", "a", "second"], ["machine.discover", "b", undefined],
  ]);
  assert.ok(actions.filter((item) => item.action === "machine.import").every((item) => !("name" in item)));
  assert.ok(rendered.some((text) => text.includes("已接管 2")));
  assert.ok(rendered.some((text) => text.includes("scan failed")));
  assert.match(status.at(-1), /已接管 2 个节点/);
});

test("a node's own endpoint draft can be submitted during takeover", async () => {
  const scope = "machine-import:machine:old-tag", sent = [];
  const context = vm.createContext({
    draftScopes: new Map([[scope, 1]]), state: { instances: [] },
    setMachineStatus() {}, askOperation: async () => ({}), idempotencyKey: () => "claim-key",
    postAction: async (body, draftScope) => { sent.push({ body, draftScope }); return { ok: true, job: { id: "job" } }; }, refresh: async () => {},
  });
  vm.runInContext(between("  async function importLegacyNode(", "  async function updateOneBoxScript("), context);
  await context.importLegacyNode({ uuid: "machine", policy: {}, discoveredAt: new Date().toISOString() }, { tag: "old-tag" }, { endpointHost: "2001:4860:4860::8888", externalPort: "" });
  assert.equal(sent.length, 1); assert.equal(sent[0].draftScope, scope);
  assert.equal(sent[0].body.endpointHost, "2001:4860:4860::8888");
  assert.equal("name" in sent[0].body, false);
  context.draftScopes.set("settings:connection", 1);
  await context.importLegacyNode({ uuid: "machine", policy: {}, discoveredAt: new Date().toISOString() }, { tag: "old-tag" }, {});
  assert.equal(sent.length, 1, "a different unsaved draft blocks takeover");
});
