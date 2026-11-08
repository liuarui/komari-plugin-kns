"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createAuditLog } = require("../kns/audit-log");
const { createStore } = require("../kns/store");

function event(id, at) {
  return { id, at: at || new Date().toISOString(), action: "test.action", actor: "admin", details: { id } };
}

test("audit events append to private segments and return in chronological order", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-log-"));
  try {
    const audit = createAuditLog(root, { segmentBytes: 180, maxBytes: 16 * 1024 * 1024 });
    audit.append(event("one"));
    audit.append(event("two"));
    const result = audit.list(10);
    assert.deepEqual(result.events.map((record) => record.id), ["one", "two"]);
    const filename = fs.readdirSync(audit.root).find((name) => name.endsWith(".jsonl"));
    assert.ok(filename);
    assert.equal(fs.statSync(path.join(audit.root, filename)).mode & 0o777, 0o600);
    assert.equal(result.retention.retentionDays, 365);
    assert.equal(result.retention.prunedRecords, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("retention prunes oldest segments and reports a visible checkpoint", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-retention-"));
  try {
    const audit = createAuditLog(root, { segmentBytes: 120, maxBytes: 250 });
    for (let index = 1; index <= 5; index += 1) audit.append(event("event-" + index));
    const result = audit.list(10);
    assert.deepEqual(result.events.map((record) => record.id), ["event-4", "event-5"]);
    assert.equal(result.retention.prunedRecords, 3);
    assert.ok(result.retention.prunedBytes > 0);
    assert.ok(result.retention.prunedFrom);
    assert.ok(result.retention.prunedThrough);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("audit pages continue from the oldest event in the previous page", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-pages-"));
  try {
    const audit = createAuditLog(root);
    for (let index = 1; index <= 5; index += 1) audit.append(event("page-" + index));
    const newest = audit.list(2);
    assert.deepEqual(newest.events.map((record) => record.id), ["page-4", "page-5"]);
    assert.equal(newest.hasMore, true);
    const older = audit.list(2, newest.nextCursor);
    assert.deepEqual(older.events.map((record) => record.id), ["page-2", "page-3"]);
    assert.equal(older.hasMore, true);
    const oldest = audit.list(2, older.nextCursor);
    assert.deepEqual(oldest.events.map((record) => record.id), ["page-1"]);
    assert.equal(oldest.hasMore, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("legacy audit import is idempotent", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-migration-"));
  try {
    const audit = createAuditLog(root);
    const legacy = [event("legacy-1"), event("legacy-2")];
    assert.equal(audit.importLegacy(legacy), 2);
    assert.equal(audit.importLegacy(legacy), 0);
    assert.deepEqual(audit.list(10).events.map((record) => record.id), ["legacy-1", "legacy-2"]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("state restore keeps current audit history and imports backup history", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-restore-"));
  try {
    const store = createStore(root);
    store.write(store.initialState());
    store.appendAudit(event("live-before-restore"));
    const restored = store.initialState();
    restored.audit = [event("from-backup")];
    const backupName = "state-2000-01-01.json";
    fs.writeFileSync(path.join(store.backupDir, backupName), JSON.stringify(restored), { mode: 0o600 });
    store.restoreBackup(backupName);
    const result = store.listAudit(10);
    assert.deepEqual(new Set(result.events.map((record) => record.id)), new Set(["live-before-restore", "from-backup"]));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("interrupted retention deletion resumes from its visible checkpoint", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kns-audit-pending-"));
  const originalUnlink = fs.unlinkSync;
  try {
    const audit = createAuditLog(root, { segmentBytes: 120, maxBytes: 130 });
    audit.append(event("before"));
    let failOnce = true;
    fs.unlinkSync = function (filename) {
      if (failOnce && String(filename).endsWith(".jsonl")) { failOnce = false; throw new Error("simulated retention delete failure"); }
      return originalUnlink.call(this, filename);
    };
    assert.throws(() => audit.append(event("after")), /simulated retention delete failure/);
    fs.unlinkSync = originalUnlink;
    assert.equal(audit.retention().pending, false);
    const result = audit.list(10);
    assert.deepEqual(result.events.map((record) => record.id), ["after"]);
    assert.equal(result.retention.prunedRecords, 1);
  } finally {
    fs.unlinkSync = originalUnlink;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
