"use strict";

// Optional real-browser acceptance: KNS_PLAYWRIGHT_MODULE=/absolute/path/to/playwright node --test tests/admin.browser.test.js
// Serves the real plugin page, but all API responses and tokens are isolated test fixtures.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");

const driver = process.env.KNS_PLAYWRIGHT_MODULE;
test("machine-centered admin browser acceptance with isolated API fixtures", { skip: !driver }, async (t) => {
  const { chromium } = require(driver);
  const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/admin.html": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8");
    res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const machine = { uuid: "machine-a", name: "Test machine", online: true, ipv4: "8.8.8.8", ipv6: "2606:4700:4700::1111", policy: { deployAllowed: true, addressMode: "dual" } };
  const state = { revision: 1, settings: { setupComplete: true, maxBatch: 10, defaultNode: { listenPort: 443 } }, machines: [machine, { ...machine, uuid: "offline", name: "Offline machine", online: false }],
    instances: [{ id: "node-a", machineUuid: machine.uuid, name: "Existing node", protocol: "vless", listen: { port: 443, transport: "tcp", address: "::" }, endpoint: { host: "8.8.8.8", port: 443 }, publish: true, enabled: true, health: { state: "healthy", level: "L1-TCP" }, remoteStatus: { installed: true, enabled: true, serviceState: "active", checkedAt: new Date().toISOString() } }],
    jobs: [], profiles: [{ id: "profile-a", name: "默认订阅", formats: ["uri", "mihomo-full"], tokens: [{ id: "existing-token" }] }], audit: [], backups: [] };
  const sent = [];
  await page.route("**/api/kns/**", async (route) => {
    if (route.request().method() === "GET") { await route.fulfill({ json: state }); return; }
    const body = route.request().postDataJSON(); sent.push(body);
    if (body.action === "profile.token.show") {
      await route.fulfill({ status: 201, json: { subscriptionUrls: { uri: "https://fixture.invalid/sub?token=synthetic-uri", "mihomo-full": "https://fixture.invalid/sub?token=synthetic-mihomo" } } }); return;
    }
    const job = { id: "job-" + sent.length, machineUuid: machine.uuid, instanceId: body.instanceId || "new-node", action: body.action, protocol: body.protocol, state: "dispatched", message: "fixture dispatch", batchId: body.batchId };
    state.jobs.unshift(job);
    await route.fulfill({ status: 202, json: body.action === "install.batch" ? { results: [{ machineUuid: machine.uuid, accepted: true, job }] } : { job } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.locator('[data-panel="machines"]').click();
  await page.getByRole("heading", { name: "Test machine", exact: true }).waitFor();
  const node = page.locator('[data-instance-id="node-a"]');
  assert.match(await node.textContent(), /运行：运行正常/);
  assert.match(await node.textContent(), /网络：TCP 可达（非代理握手）/);
  assert.match(await node.textContent(), /订阅：允许发布/);
  assert.equal(await page.locator('[data-machine-uuid="offline"]').getByRole("button", { name: "安装节点", exact: true }).isDisabled(), true);

  // Expansion survives real-page refresh; no switching into separate instance/task pages.
  await page.locator('[data-machine-uuid="machine-a"] .machine-nodes > summary').click();
  await page.locator('[data-panel="overview"]').click();
  await page.locator("#refresh").click();
  await page.waitForFunction(() => document.getElementById("globalStatus").textContent.includes("刷新成功"));
  await page.locator('[data-panel="machines"]').click();
  assert.equal(await page.locator('[data-machine-uuid="machine-a"] .machine-nodes').evaluate((node) => node.open), true);

  // Three steps, auto allocation and multi-protocol selection.
  await page.locator('[data-machine-uuid="machine-a"]').getByRole("button", { name: "安装节点", exact: true }).click();
  assert.equal(await page.locator("#installWizard").isVisible(), true);
  assert.equal(await page.locator('[data-machine-select][value="machine-a"]').isChecked(), true);
  await page.locator("#deployNext").click();
  assert.equal(await page.locator('[data-protocol-port="vless"]').inputValue(), "444");
  await page.locator('[data-protocol-select][value="shadowsocks"]').check();
  assert.equal(await page.locator('[data-protocol-port="shadowsocks"]').inputValue(), "445");
  await page.locator("#entryMode").selectOption("nat");
  await page.locator("#endpointHost").fill("shared.example");
  await page.locator('[data-protocol-external-port="vless"]').fill("30443");
  assert.match(await page.locator("#connectionPreview").textContent(), /shared\.example:30443/);
  await page.locator("#entryMode").selectOption("machine");
  assert.equal(await page.locator("#endpointHost").inputValue(), "");
  assert.equal(await page.locator('[data-protocol-external-port="vless"]').inputValue(), "");
  await page.locator("#deployNext").click();
  assert.equal(await page.locator("#deployStep3").isVisible(), true);
  await page.locator("#installBatch").click();
  await page.locator("#operationConfirm").click();
  await page.waitForFunction(() => document.getElementById("deploymentResultRows").textContent.includes("已发送到机器"));
  assert.equal(await page.locator("#installBatch").isDisabled(), true);
  assert.equal(sent.filter((body) => body.action === "install.batch").length, 1);
  state.jobs[0].state = "needs_reconcile";
  await page.waitForFunction(() => document.getElementById("deploymentResultRows").textContent.includes("尚未提交"));
  assert.equal(sent.filter((body) => body.action === "install.batch").length, 1, "unverified first protocol stops subsequent protocols");
  assert.match(await page.locator("#deploymentResultRows").textContent(), /需要核查机器状态/);
  await page.locator("#cancelInstall").click();
  await page.locator("#operationConfirm").click();

  // Status check outcome stays on the initiating node.
  await page.locator('[data-panel="machines"]').click();
  if (!await page.locator('[data-machine-uuid="machine-a"] .machine-nodes').evaluate((item) => item.open)) await page.locator('[data-machine-uuid="machine-a"] .machine-nodes > summary').click();
  await node.getByRole("button", { name: "核查", exact: true }).click();
  await page.locator("#operationConfirm").click();
  state.jobs[0].state = "succeeded"; state.jobs[0].message = "fixture verified";
  await page.locator('[data-panel="overview"]').click();
  await page.locator("#refresh").click();
  await page.locator('[data-panel="machines"]').click();
  await page.waitForFunction(() => document.querySelector('[data-instance-id="node-a"] [data-instance-status]').textContent.includes("fixture verified"));

  // One-time selected-format links, clipboard, QR, cleanup and cancellation.
  await page.locator('[data-panel="overview"]').click();
  await page.locator("#homeSubscriptionFormat").selectOption("mihomo-full");
  await page.locator("#copyHomeSubscription").click();
  await page.locator("#deliveryDialog").waitFor({ state: "visible" });
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "https://fixture.invalid/sub?token=synthetic-mihomo");
  assert.equal(await page.locator("#deliveryFormat").inputValue(), "mihomo-full");
  await page.locator("#deliveryFormat").selectOption("uri");
  await page.locator('[data-delivery-format="uri"]').getByRole("button", { name: "显示二维码" }).click();
  assert.equal(await page.locator(".qr-panel svg").isVisible(), true);
  await page.keyboard.press("Escape");
  await page.locator("#deliveryDialog").waitFor({ state: "hidden" });
  assert.equal(await page.locator("#deliveryLinks").textContent(), "");
  assert.equal(await page.locator("#converterDeliveryLinks").textContent(), "");
  assert.doesNotMatch(await page.evaluate(() => JSON.stringify(localStorage)), /synthetic-(uri|mihomo)/);
  const count = sent.filter((item) => item.action === "profile.token.create").length;
  await page.locator("#copyHomeSubscription").click(); await page.locator("#deliveryDialog").waitFor({ state: "visible" }); await page.keyboard.press("Escape");
  assert.equal(sent.filter((item) => item.action === "profile.token.create").length, count, "viewing a link does not create another token");

  for (const width of [360, 390, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 800 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `no page overflow at ${width}px`);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.setViewportSize({ width: 360, height: 800 });
  await page.locator("#copyHomeSubscription").click();
  await page.locator("#deliveryDialog").waitFor({ state: "visible" });
  const bounds = await page.locator("#deliveryDialog").boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 360);
  await page.keyboard.press("Escape");
  await page.locator('[data-panel="machines"]').click();
  await page.locator("#homeMachineSearch").fill("no-match");
  await page.getByText("没有匹配的机器。", { exact: true }).waitFor();
  assert.deepEqual(errors, []);
});

test("install drawer keeps a long machine list usable and protects its draft", { skip: !driver }, async (t) => {
  const { chromium } = require(driver);
  const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8"); res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true }); t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 390, height: 700 } });
  const machines = Array.from({ length: 40 }, (_, index) => ({ uuid: "machine-" + index, name: "Machine " + index, online: true, ipv4: "8.8.8.8", policy: { deployAllowed: true, addressMode: "ipv4" } }));
  const state = { revision: 1, settings: { setupComplete: true, defaultNode: { listenPort: 443 } }, machines, instances: [], jobs: [], profiles: [], audit: [], backups: [] };
  await page.route("**/api/kns/**", (route) => route.fulfill({ json: state }));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.waitForFunction(() => document.getElementById("globalStatus").textContent.includes("刷新成功"));
  await page.locator("#startInstall").click();
  assert.equal(await page.locator("#installWizard").evaluate((dialog) => dialog.open), true);
  assert.equal(await page.locator("#overview").evaluate((panel) => panel.classList.contains("active")), true);
  const list = await page.locator("#installMachines").evaluate((element) => ({ height: element.clientHeight, scroll: element.scrollHeight }));
  assert.ok(list.height <= 360 && list.scroll > list.height, "the list scrolls within the drawer");
  assert.equal(await page.locator("#deployNext").isVisible(), true);
  await page.locator("#installMachineSearch").fill("Machine 39");
  await page.locator("#installMachines .machine-select-card").click();
  await page.locator("#installMachineSearch").fill("");
  assert.equal(await page.locator('[data-machine-select][value="machine-39"]').isChecked(), true);
  await page.keyboard.press("Escape");
  await page.locator("#operationDialog").waitFor({ state: "visible" });
  await page.locator("#operationCancel").click();
  assert.equal(await page.locator("#installWizard").evaluate((dialog) => dialog.open), true);
  assert.equal(await page.locator('[data-machine-select][value="machine-39"]').isChecked(), true);
  await page.keyboard.press("Escape"); await page.locator("#operationConfirm").click();
  assert.equal(await page.locator("#installWizard").evaluate((dialog) => dialog.open), false);
});

test("handled alerts disappear but a new task or health incident is shown", { skip: !driver }, async (t) => {
  const { chromium } = require(driver); const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8"); res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve)); t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true }); t.after(() => browser.close());
  const page = await browser.newPage();
  const state = { revision: 1, settings: { setupComplete: true, defaultNode: {} }, machines: [{ uuid: "m", name: "机器", online: true, policy: { deployAllowed: true } }],
    jobs: [{ id: "old-job", machineUuid: "m", action: "install", state: "failed", createdAt: "2026-11-10T00:00:00Z" }],
    instances: [{ id: "node", machineUuid: "m", name: "测试节点", protocol: "vless", enabled: true, health: { state: "unhealthy" } }], profiles: [], audit: [], backups: [] };
  await page.route("**/api/kns/**", async (route) => {
    if (route.request().method() === "GET") return route.fulfill({ json: state });
    const body = route.request().postDataJSON(); assert.equal(body.action, "attention.acknowledge");
    if (body.kind === "job") { const job = state.jobs.find((item) => item.id === body.jobId); job.attentionAcknowledgedAt = "now"; job.attentionAcknowledgedState = job.state; }
    else { const health = state.instances[0].health; health.attentionIncidentId = body.incidentId; health.attentionAcknowledgedIncidentId = body.incidentId; }
    return route.fulfill({ json: { ok: true, acknowledgedAt: "now" } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const todos = page.locator("#overviewTodos");
  await todos.getByText("任务编号 old-job").waitFor();
  await todos.locator(".result-item").filter({ hasText: "old-job" }).getByRole("button", { name: "我已处理" }).click();
  await todos.locator(".result-item").filter({ hasText: "测试节点" }).getByRole("button", { name: "我已处理" }).click();
  await page.locator("#refresh").click();
  await page.waitForFunction(() => document.getElementById("overviewTodosCard").hidden);
  assert.equal(state.jobs[0].state, "failed", "history remains available");
  state.jobs.push({ id: "new-job", machineUuid: "m", action: "install", state: "failed", createdAt: "2026-11-10T02:00:00Z" });
  state.instances[0].health.attentionIncidentId = "new-incident";
  await page.locator("#refresh").click();
  await todos.getByText("任务编号 new-job").waitFor();
  assert.equal(await todos.locator(".result-item").filter({ hasText: "测试节点" }).isVisible(), true);
});

test("subscription drawer creates, edits and protects unsaved changes", { skip: !driver }, async (t) => {
  const { chromium } = require(driver);
  const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8");
    res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  const profile = { id: "p1", name: "已有订阅", formats: ["uri"], tokens: [], machineUuids: [], excludeMachineUuids: [], protocols: [], includeTags: [] };
  const state = { revision: 1, settings: { setupComplete: true, defaultNode: {} }, machines: [], instances: [], jobs: [], profiles: [profile], audit: [], backups: [] };
  const sent = [];
  await page.route("**/api/kns/**", async (route) => {
    if (route.request().method() === "GET") return route.fulfill({ json: state });
    const body = route.request().postDataJSON(); sent.push(body);
    if (body.action === "profile.update") { Object.assign(profile, body); state.revision++; return route.fulfill({ json: { ok: true } }); }
    if (body.action === "profile.create") return route.fulfill({ json: { profile: { id: "new" }, subscriptionUrls: { uri: "https://fixture.invalid/sub?token=synthetic" } } });
    return route.fulfill({ json: { ok: true } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.locator('[data-panel="subscriptions"]').click();
  await page.locator('#openProfileDrawer').click();
  assert.equal(await page.locator('#profileDrawer').isVisible(), true);
  await page.locator('#profileName').fill('草稿');
  await page.locator('#cancelProfileDrawer').click();
  assert.equal(await page.locator('#operationDialog').isVisible(), true);
  await page.locator('#operationCancel').click();
  assert.equal(await page.locator('#profileName').inputValue(), '草稿');
  await page.locator('#cancelProfileDrawer').click();
  await page.locator('#operationConfirm').click();
  assert.equal(await page.locator('#profileDrawer').isVisible(), false);
  await page.locator('#openProfileDrawer').click();
  assert.equal(await page.locator('#profileName').inputValue(), '');
  await page.locator('#profileName').fill('新档案');
  await page.locator('#createProfile').click();
  await page.locator('#deliveryDialog').waitFor({ state: 'visible' });
  assert.equal(sent.at(-1).action, 'profile.create');
  assert.equal(sent.at(-1).name, '新档案');
  await page.locator('#closeDelivery').click();
  await page.getByRole('button', { name: '编辑订阅' }).click();
  assert.equal(await page.locator('#profileName').inputValue(), '已有订阅');
  await page.locator('#profileName').fill('修改后的订阅');
  await page.locator('#createProfile').click();
  await page.locator('#profileDrawer').waitFor({ state: 'hidden' });
  assert.equal(sent.at(-1).action, 'profile.update');
  assert.equal(sent.at(-1).profileId, 'p1');
  assert.equal(sent.at(-1).name, '修改后的订阅');
  await page.setViewportSize({ width: 360, height: 700 });
  await page.locator('#openProfileDrawer').click();
  const bounds = await page.locator('#profileDrawer').boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 360 && bounds.height <= 700);
  assert.equal(await page.locator('#createProfile').isVisible(), true);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#profileDrawer').isVisible(), false);
  assert.deepEqual(errors, []);
});

test("plugin update checks, downloads and uses Komari chunk upload", { skip: !driver }, async (t) => {
  const { chromium } = require(driver);
  const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8");
    res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  const state = { revision: 1, pluginVersion: "1.0.1", settings: { setupComplete: true, defaultNode: {} }, machines: [], instances: [], jobs: [], profiles: [], audit: [], backups: [] };
  const calls = [];
  await page.route("**/api/kns/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/admin/update-package")) { calls.push("download:" + url.searchParams.get("version")); return route.fulfill({ body: Buffer.from([0x50, 0x4b, 3, 4]), contentType: "application/zip" }); }
    if (route.request().method() === "GET") return route.fulfill({ json: state });
    const body = route.request().postDataJSON();
    if (body.action === "plugin.update.prepare") return route.fulfill({ json: { ok: true, token: "fixture-lock" } });
    return route.fulfill({ json: { ok: true, currentVersion: "1.0.1", latestVersion: "1.0.2", updateAvailable: true } });
  });
  await page.route("**/api/admin/upload/**", async (route) => {
    const step = new URL(route.request().url()).pathname.split("/").pop(); calls.push(step);
    if (step === "init") { assert.equal(route.request().postDataJSON().purpose, "plugin"); return route.fulfill({ json: { status: "success", data: { upload_id: "fixture", chunk_size: 5 * 1024 * 1024 } } }); }
    if (step === "chunk") { assert.match(route.request().postData(), /upload_id/); return route.fulfill({ json: { status: "success", data: { received: true, chunk_index: 0 } } }); }
    if (step === "merge") { assert.equal(route.request().postDataJSON().upload_id, "fixture"); return route.fulfill({ json: { status: "success", data: { version: "1.0.2" } } }); }
    return route.fulfill({ json: { status: "success", data: {} } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.locator('[data-panel="settings"]').click();
  await page.locator('#checkPluginUpdate').click();
  await page.locator('#installPluginUpdate').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#installPluginUpdate').textContent(), '安装 v1.0.2');
  await page.locator('#installPluginUpdate').click();
  await page.locator('#operationConfirm').click();
  await page.waitForResponse((response) => response.url().endsWith('/api/admin/upload/merge'));
  assert.deepEqual(calls, ['download:1.0.2', 'init', 'chunk', 'merge']);
  assert.deepEqual(errors, []);
});

test("one-click batch scan only claims freshly scanned online machines", { skip: !driver }, async (t) => {
  const { chromium } = require(driver);
  const root = path.resolve(__dirname, "../pages");
  const server = http.createServer((req, res) => {
    const file = ({ "/": "admin.html", "/qrcode-generator.js": "qrcode-generator.js", "/qrcode-generator-utf8.js": "qrcode-generator-utf8.js" })[req.url];
    if (!file) { res.writeHead(404); res.end(); return; }
    res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/html;charset=utf-8"); res.end(fs.readFileSync(path.join(root, file)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const browser = await chromium.launch({ channel: "chrome", headless: true }); t.after(() => browser.close());
  const page = await browser.newPage(); const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  const machine = { uuid: "online", name: "Online probe", online: true, ipv4: "8.8.8.8", policy: { deployAllowed: true, tags: [] } };
  const state = { revision: 1, settings: { setupComplete: true, defaultNode: {} }, machines: [machine, { uuid: "offline", name: "Offline probe", online: false, policy: {} }], instances: [], jobs: [], profiles: [], audit: [], backups: [] };
  const actions = [];
  await page.route("**/api/kns/**", async (route) => {
    if (route.request().method() === "GET") return route.fulfill({ json: state });
    const body = route.request().postDataJSON(); actions.push(body);
    const job = { id: "job-" + actions.length, action: body.action, state: "succeeded", machineUuid: body.machineUuid, legacyTag: body.legacyTag };
    if (body.action === "machine.discover") { machine.discoveredAt = new Date().toISOString(); machine.discoveredNodes = [{ tag: "old-node", protocol: "vless", importable: true, managed: false, listen: { port: 443, transport: "tcp" } }]; }
    if (body.action === "machine.import") state.instances.push({ id: "claimed", machineUuid: "online", name: "claimed", legacyTag: body.legacyTag, protocol: "vless", enabled: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", port: 443 } });
    state.jobs.unshift(job); state.revision++; return route.fulfill({ json: { ok: true, job } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.locator('[data-panel="machines"]').click();
  await page.locator('#scanAndClaimAll').click();
  assert.match(await page.locator('#operationDescription').textContent(), /重载共享服务/);
  await page.locator('#operationConfirm').click();
  await page.waitForFunction(() => document.querySelector('#batchClaimStatus').textContent.includes('批量处理结束'), { timeout: 15000 });
  assert.deepEqual(actions.map((item) => [item.action, item.machineUuid]), [["machine.discover", "online"], ["machine.import", "online"]]);
  assert.equal(actions[1].legacyTag, "old-node");
  assert.match(await page.locator('#batchClaimStatus').textContent(), /已接管 1 个节点/);
  assert.deepEqual(errors, []);
});
