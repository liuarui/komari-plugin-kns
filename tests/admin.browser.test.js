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
    if (body.action === "profile.token.create") {
      await route.fulfill({ status: 201, json: { subscriptionUrls: { uri: "https://fixture.invalid/sub?token=synthetic-uri", "mihomo-full": "https://fixture.invalid/sub?token=synthetic-mihomo" } } }); return;
    }
    const job = { id: "job-" + sent.length, machineUuid: machine.uuid, instanceId: body.instanceId || "new-node", action: body.action, protocol: body.protocol, state: "dispatched", message: "fixture dispatch", batchId: body.batchId };
    state.jobs.unshift(job);
    await route.fulfill({ status: 202, json: body.action === "install.batch" ? { results: [{ machineUuid: machine.uuid, accepted: true, job }] } : { job } });
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.getByRole("heading", { name: "Test machine", exact: true }).waitFor();
  const node = page.locator('[data-instance-id="node-a"]');
  assert.match(await node.textContent(), /运行：运行正常/);
  assert.match(await node.textContent(), /网络：TCP 可达（非代理握手）/);
  assert.match(await node.textContent(), /订阅：允许发布/);
  assert.equal(await page.locator('[data-machine-uuid="offline"]').getByRole("button", { name: "安装节点", exact: true }).isDisabled(), true);

  // Expansion survives real-page refresh; no switching into separate instance/task pages.
  await page.locator('[data-machine-uuid="machine-a"] .machine-nodes > summary').click();
  await page.locator("#refresh").click();
  await page.waitForFunction(() => document.getElementById("globalStatus").textContent.includes("刷新成功"));
  assert.equal(await page.locator('[data-machine-uuid="machine-a"] .machine-nodes').evaluate((node) => node.open), false);
  await page.locator('[data-machine-uuid="machine-a"] .machine-nodes > summary').click();

  // Three steps, auto allocation and multi-protocol selection.
  await page.locator("#startInstall").click();
  await page.locator('[data-machine-select][value="machine-a"]').check();
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

  // Status check outcome stays on the initiating node, including optional host 2FA field.
  await node.getByRole("button", { name: "核查", exact: true }).click();
  await page.locator("#operationDialog details summary").click();
  assert.equal(await page.locator('input[name="twoFactorCode"]').isVisible(), true);
  await page.locator("#operationConfirm").click();
  state.jobs[0].state = "succeeded"; state.jobs[0].message = "fixture verified";
  await page.locator("#refresh").click();
  await page.waitForFunction(() => document.querySelector('[data-instance-id="node-a"] [data-instance-status]').textContent.includes("fixture verified"));

  // One-time selected-format links, clipboard, QR, cleanup and cancellation.
  await page.locator("#homeSubscriptionFormat").selectOption("mihomo-full");
  await page.locator("#copyHomeSubscription").click();
  await page.locator("#operationConfirm").click();
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
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  const count = sent.length;
  await page.locator("#copyHomeSubscription").click(); await page.locator("#operationCancel").click();
  assert.equal(sent.length, count, "cancel does not create another token");

  for (const width of [360, 390, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 800 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `no page overflow at ${width}px`);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.setViewportSize({ width: 360, height: 800 });
  await page.locator("#copyHomeSubscription").click();
  const bounds = await page.locator("#operationDialog").boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 360);
  await page.keyboard.press("Escape");
  await page.locator("#homeMachineSearch").fill("no-match");
  await page.getByText("没有匹配的机器。", { exact: true }).waitFor();
  assert.deepEqual(errors, []);
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
