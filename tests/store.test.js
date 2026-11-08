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

test("daily backup publishes the key before the matching state and retries a partial attempt", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-daily-backup-pair-"));
  const priorEnvKey = process.env.KNS_MASTER_KEY;
  delete process.env.KNS_MASTER_KEY;
  const originalRead = fs.readFileSync;
  try {
    const store = createStore(root);
    store.write(store.initialState());
    const keyPath = path.join(store.root, "master.key");
    fs.writeFileSync(keyPath, Buffer.alloc(32, 5), { mode: 0o600 });
    const next = store.read(); next.settings.privateSite = true;
    fs.readFileSync = function (filename, ...args) {
      if (filename === keyPath) throw new Error("simulated key backup read failure");
      return originalRead.call(this, filename, ...args);
    };
    assert.throws(() => store.write(next), /simulated key backup read failure/);
    const day = new Date().toISOString().slice(0, 10);
    assert.equal(fs.existsSync(path.join(store.backupDir, "state-" + day + ".json")), false);
    assert.equal(fs.existsSync(path.join(store.backupDir, "master-" + day + ".key")), false);
    fs.readFileSync = originalRead;
    store.write(next);
    assert.equal(fs.existsSync(path.join(store.backupDir, "state-" + day + ".json")), true);
    assert.deepEqual(fs.readFileSync(path.join(store.backupDir, "master-" + day + ".key")), Buffer.alloc(32, 5));
  } finally {
    fs.readFileSync = originalRead;
    if (priorEnvKey === undefined) delete process.env.KNS_MASTER_KEY;
    else process.env.KNS_MASTER_KEY = priorEnvKey;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("failed daily restore rolls back the previous state and master key", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-restore-rollback-"));
  const priorEnvKey = process.env.KNS_MASTER_KEY;
  delete process.env.KNS_MASTER_KEY;
  const originalRename = fs.renameSync;
  try {
    const store = createStore(root);
    store.write(store.initialState());
    const keyPath = path.join(store.root, "master.key");
    fs.writeFileSync(keyPath, Buffer.alloc(32, 3), { mode: 0o600 });
    const current = store.read(); current.settings.privateSite = true; store.write(current);
    const backupName = store.listBackups()[0];
    fs.writeFileSync(keyPath, Buffer.alloc(32, 4), { mode: 0o600 });
    let failOnce = true;
    fs.renameSync = function (source, destination) {
      if (destination === store.stateFile && failOnce) { failOnce = false; throw new Error("simulated state commit failure"); }
      return originalRename.call(this, source, destination);
    };
    assert.throws(() => store.restoreBackup(backupName), /simulated state commit failure/);
    assert.equal(store.read().settings.privateSite, true);
    assert.deepEqual(fs.readFileSync(keyPath), Buffer.alloc(32, 4));
    assert.equal(fs.existsSync(path.join(store.backupDir, "restore-transaction.json")), false);
  } finally {
    fs.renameSync = originalRename;
    if (priorEnvKey === undefined) delete process.env.KNS_MASTER_KEY;
    else process.env.KNS_MASTER_KEY = priorEnvKey;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("startup recovery reverts a restore transaction interrupted between file commits", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-restore-recovery-"));
  const priorEnvKey = process.env.KNS_MASTER_KEY;
  delete process.env.KNS_MASTER_KEY;
  try {
    const store = createStore(root);
    store.write(store.initialState());
    const keyPath = path.join(store.root, "master.key");
    const oldKey = Buffer.alloc(32, 6);
    fs.writeFileSync(keyPath, oldKey, { mode: 0o600 });
    const current = store.read(); current.settings.privateSite = true; store.write(current);
    const priorState = fs.readFileSync(store.stateFile);
    const suffix = "1234567890-abcdef012345";
    const stateBackup = "pre-restore-" + suffix + ".json";
    const keyBackup = "pre-restore-" + suffix + ".key";
    fs.writeFileSync(path.join(store.backupDir, stateBackup), priorState, { mode: 0o600 });
    fs.writeFileSync(path.join(store.backupDir, keyBackup), oldKey, { mode: 0o600 });
    fs.writeFileSync(keyPath, Buffer.alloc(32, 7), { mode: 0o600 });
    const interrupted = JSON.parse(priorState.toString("utf8")); interrupted.settings.privateSite = false;
    fs.writeFileSync(store.stateFile, JSON.stringify(interrupted), { mode: 0o600 });
    fs.writeFileSync(path.join(store.backupDir, "restore-transaction.json"), JSON.stringify({ format: "KNS-RESTORE-TRANSACTION-v1", stateBackup, keyBackup, hadState: true, hadKey: true, keyChanged: true }), { mode: 0o600 });
    assert.equal(store.recoverInterruptedRestore(), true);
    assert.equal(store.read().settings.privateSite, true);
    assert.deepEqual(fs.readFileSync(keyPath), oldKey);
    assert.equal(fs.existsSync(path.join(store.backupDir, "restore-transaction.json")), false);
  } finally {
    if (priorEnvKey === undefined) delete process.env.KNS_MASTER_KEY;
    else process.env.KNS_MASTER_KEY = priorEnvKey;
    fs.rmSync(root, { recursive: true, force: true });
  }
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

test("schema 1 state migrates without losing settings and keeps auto deployment off", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-schema-migration-"));
  try {
    const store = createStore(root);
    const legacy = store.initialState();
    legacy.schemaVersion = 1;
    legacy.pluginVersion = "";
    legacy.settings = { publicBaseUrl: "https://monitor.example", converterTarget: "loon", privateSite: true };
    legacy.machines = [{ uuid: "123e4567-e89b-42d3-a456-426614174000", policy: { deployAllowed: true, manualAddress: "edge.example" } }];
    fs.mkdirSync(store.root, { recursive: true });
    fs.writeFileSync(store.stateFile, JSON.stringify(legacy), { mode: 0o600 });

    const migrated = store.read();
    assert.equal(migrated.schemaVersion, 2);
    assert.equal(migrated.settings.setupComplete, true);
    assert.equal(migrated.settings.autoProvisionNewProbes, false);
    assert.deepEqual(migrated.settings.autoProvisionBaselineUuids, []);
    assert.equal(migrated.settings.publicBaseUrl, "https://monitor.example");
    assert.equal(migrated.settings.converterTarget, "loon");
    assert.equal(migrated.settings.privateSite, true);
    assert.equal(migrated.machines[0].policy.manualAddress, "edge.example");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("store rejects a stale revision and previews matching daily backup metadata", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-revision-preview-"));
  const priorEnvKey = process.env.KNS_MASTER_KEY;
  delete process.env.KNS_MASTER_KEY;
  try {
    const store = createStore(root);
    store.write(store.initialState());
    const keyPath = path.join(store.root, "master.key");
    fs.writeFileSync(keyPath, Buffer.alloc(32, 11), { mode: 0o600 });
    const stale = store.read();
    const winner = store.read();
    winner.settings.privateSite = true;
    store.write(winner);

    assert.throws(() => store.write(stale), (error) => error.code === "state_revision_conflict" && error.currentRevision === stale.revision + 1);
    assert.equal(store.read().settings.privateSite, true);
    const preview = store.inspectBackup(store.listBackups()[0]);
    assert.equal(preview.keyAvailable, true);
    assert.equal(preview.requiresMasterKey, false);
    assert.deepEqual(preview.counts, { machines: 0, instances: 0, profiles: 0, jobs: 0 });
  } finally {
    if (priorEnvKey === undefined) delete process.env.KNS_MASTER_KEY;
    else process.env.KNS_MASTER_KEY = priorEnvKey;
    fs.rmSync(root, { recursive: true, force: true });
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

test("plugin upgrade backup stays inside Komari's confined storage root", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-confined-upgrade-store-"));
  const store = createStore(root);
  const state = store.initialState();
  state.pluginVersion = "1.1.3";
  store.write(state);

  const original = {};
  const confinedMethods = ["mkdirSync", "writeFileSync", "copyFileSync", "renameSync", "chmodSync", "unlinkSync", "rmSync", "openSync"];
  let rejectUpgradeBackupPublish = false;
  function assertInsideStorageRoot(target) {
    const resolved = path.resolve(String(target));
    assert.ok(resolved === root || resolved.startsWith(root + path.sep), "plugin file operation escaped __storageDir__: " + resolved);
  }
  try {
    for (const method of confinedMethods) {
      original[method] = fs[method];
      fs[method] = function confinedFilesystemOperation(...args) {
        if (method === "renameSync") {
          assertInsideStorageRoot(args[0]);
          assertInsideStorageRoot(args[1]);
          if (rejectUpgradeBackupPublish && path.resolve(String(args[1])).startsWith(path.join(store.backupDir, "pre-upgrade-"))) {
            throw new Error("simulated backup publish failure");
          }
        } else if (method === "copyFileSync") {
          assertInsideStorageRoot(args[0]);
          assertInsideStorageRoot(args[1]);
        } else {
          assertInsideStorageRoot(args[0]);
        }
        return original[method].apply(this, args);
      };
    }
    rejectUpgradeBackupPublish = true;
    assert.throws(() => store.preparePluginVersion(store.read(), "1.1.4"), /simulated backup publish failure/);
    rejectUpgradeBackupPublish = false;
    assert.equal(store.read().pluginVersion, "1.1.3");
    assert.equal(fs.readdirSync(root).some((name) => name.startsWith(".pre-upgrade-") && name.endsWith(".tmp")), false);
    const upgraded = store.preparePluginVersion(store.read(), "1.1.4");
    assert.equal(upgraded.pluginVersion, "1.1.4");
    assert.ok(fs.readdirSync(store.backupDir).some((name) => name.startsWith("pre-upgrade-")));
  } finally {
    for (const method of confinedMethods) if (original[method]) fs[method] = original[method];
    fs.rmSync(root, { recursive: true, force: true });
  }
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
