"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createStore } = require("../kns/store");
const secrets = require("../kns/crypto");

test("store writes atomically and restores the daily state/key backup", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-store-"));
  try {
    const store = createStore(root);
    const state = store.initialState();
    store.write(state);
    fs.mkdirSync(store.root, { recursive: true });
    fs.writeFileSync(path.join(store.root, "master.key"), Buffer.alloc(32, 3), { mode: 0o600 });
    const next = store.read(); next.settings.privateSite = true; store.write(next);
    assert.equal(store.listBackups().length, 1);
    assert.equal(fs.statSync(store.stateFile).mode & 0o777, 0o600);
    const restored = store.restoreBackup(store.listBackups()[0]);
    assert.equal(restored.settings.privateSite, false);
    assert.equal(fs.statSync(path.join(store.root, "master.key")).mode & 0o777, 0o600);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("master key creation tolerates Komari's lstat error for a missing key", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-master-key-"));
  const keyPath = path.join(root, "kns", "master.key");
  const compatFs = new Proxy(fs, {
    get(target, property) {
      if (property === "readFileSync") return (filename, ...args) => {
        if (filename === keyPath && !fs.existsSync(filename)) throw new Error("lstat " + filename + ": no such file or directory");
        return fs.readFileSync(filename, ...args);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  try {
    const key = secrets.getMasterKey(root, compatFs);
    assert.equal(key.length, 32);
    assert.deepEqual(secrets.getMasterKey(root, compatFs), key);
    assert.deepEqual(fs.readFileSync(keyPath), key);
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("URL constructors fall back to node:url when the host does not expose globals", () => {
  const priorURL = globalThis.URL;
  const priorURLSearchParams = globalThis.URLSearchParams;
  globalThis.URL = undefined;
  globalThis.URLSearchParams = undefined;
  const modulePath = require.resolve("../kns/url");
  delete require.cache[modulePath];
  try {
    const url = require("../kns/url");
    assert.equal(new url.URL("https://example.com:8443/a").port, "8443");
    assert.equal(new url.URLSearchParams("token=x%2By").get("token"), "x+y");
  } finally {
    globalThis.URL = priorURL;
    globalThis.URLSearchParams = priorURLSearchParams;
    delete require.cache[modulePath];
  }
});

test("migration snapshots the complete plugin storage directory privately", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-migration-store-"));
  try {
    const store = createStore(root);
    fs.writeFileSync(path.join(root, "onebox-bridge.json"), JSON.stringify({ token: "legacy-secret" }), { mode: 0o600 });
    fs.mkdirSync(store.root, { recursive: true });
    fs.writeFileSync(path.join(store.root, "master.key"), Buffer.alloc(32, 8), { mode: 0o600 });
    fs.mkdirSync(path.join(root, "other-plugin-data"));
    fs.writeFileSync(path.join(root, "other-plugin-data", "state.json"), "preserve me");
    const backup = store.backupStorageBeforeChange("migration");
    assert.equal(fs.readFileSync(path.join(backup, "onebox-bridge.json"), "utf8"), JSON.stringify({ token: "legacy-secret" }));
    assert.deepEqual(fs.readFileSync(path.join(backup, "kns", "master.key")), Buffer.alloc(32, 8));
    assert.equal(fs.readFileSync(path.join(backup, "other-plugin-data", "state.json"), "utf8"), "preserve me");
    assert.equal(fs.statSync(backup).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(backup, "onebox-bridge.json")).mode & 0o777, 0o600);
    assert.equal(fs.existsSync(path.join(backup, "kns", "backups", path.basename(backup))), false);
    const nextBackup = store.backupStorageBeforeChange("migration");
    assert.equal(fs.existsSync(path.join(nextBackup, "kns", "backups", path.basename(backup))), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("plugin version updates snapshot state and refuse downgrades", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-upgrade-store-"));
  try {
    const store = createStore(root);
    const state = store.initialState();
    state.pluginVersion = "1.1.1";
    state.settings.privateSite = true;
    store.write(state);
    const upgraded = store.preparePluginVersion(store.read(), "1.1.2");
    assert.equal(upgraded.pluginVersion, "1.1.2");
    assert.equal(upgraded.settings.privateSite, true);
    const backupName = fs.readdirSync(store.backupDir).find((name) => name.startsWith("pre-upgrade-"));
    assert.ok(backupName);
    const oldState = JSON.parse(fs.readFileSync(path.join(store.backupDir, backupName, "kns", "state.json"), "utf8"));
    assert.equal(oldState.pluginVersion, "1.1.1");
    assert.equal(fs.statSync(path.join(store.backupDir, backupName)).mode & 0o777, 0o700);
    assert.throws(() => store.preparePluginVersion(store.read(), "1.1.0"), /newer plugin version/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("secret tokens are salted hashes and credential boxes authenticate", () => {
  const token = secrets.createToken();
  const record = secrets.tokenRecord(token);
  assert.equal(secrets.verifyToken(token, record), true);
  assert.equal(secrets.verifyToken(token + "x", record), false);
  const key = Buffer.alloc(32, 2);
  const box = secrets.encryptSecret("credential", key);
  assert.equal(secrets.decryptSecret(box, key), "credential");
  box.data = "00";
  assert.throws(() => secrets.decryptSecret(box, key));
});

test("subscription snapshots are replaceable private files and can be pruned", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-subscription-store-"));
  try {
    const store = createStore(root);
    const firstKey = "a".repeat(64);
    const secondKey = "b".repeat(64);
    const key = Buffer.alloc(32, 9);
    const box = secrets.encryptSecret(JSON.stringify({ body: "secret subscription" }), key);
    store.writeSubscriptionSnapshot(firstKey, box);
    assert.deepEqual(store.readSubscriptionSnapshot(firstKey), box);
    assert.equal(fs.statSync(path.join(store.subscriptionSnapshotDir, firstKey + ".json")).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(path.join(store.subscriptionSnapshotDir, firstKey + ".json"), "utf8").includes("secret subscription"), false);
    store.writeSubscriptionSnapshot(secondKey, secrets.encryptSecret("next", key));
    store.pruneSubscriptionSnapshots([secondKey]);
    assert.equal(store.readSubscriptionSnapshot(firstKey), null);
    assert.ok(store.readSubscriptionSnapshot(secondKey));
    assert.throws(() => store.writeSubscriptionSnapshot("../state", box));
    const blockedKey = "c".repeat(64);
    fs.mkdirSync(path.join(store.subscriptionSnapshotDir, blockedKey + ".json"));
    assert.throws(() => store.writeSubscriptionSnapshot(blockedKey, box));
    assert.deepEqual(fs.readdirSync(store.subscriptionSnapshotDir).filter((name) => name.startsWith(blockedKey + ".json.")), []);
    fs.rmdirSync(path.join(store.subscriptionSnapshotDir, blockedKey + ".json"));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
