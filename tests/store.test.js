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
