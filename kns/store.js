"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CURRENT_SCHEMA = 1;

function initialState() {
  const now = new Date().toISOString();
  return {
    schemaVersion: CURRENT_SCHEMA,
    pluginVersion: "",
    revision: 0,
    createdAt: now,
    updatedAt: now,
    settings: {
      publicBaseUrl: "",
      converterUrl: "http://23.146.156.234:25500/sub",
      converterTarget: "clash",
      oneboxScriptUrl: "https://raw.githubusercontent.com/liuarui/onebox/d9b98f0fd00fe3c9687697baff5c99e398a020b2/install.sh",
      oneboxScriptSha256: "f5b4a1fde9b773f7963f558411a11003a71183ddb8201fce55801461f5faa65e",
      healthIntervalSeconds: 300,
      addressSyncIntervalSeconds: 60,
      privateSite: false,
      maxBatch: 10,
    },
    machines: [],
    runtimes: [],
    instances: [],
    jobs: [],
    profiles: [],
    audit: [],
    legacyNodes: [],
    lastSnapshotAt: "",
    snapshotPending: false,
  };
}

function validateState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("KNS state must be a JSON object.");
  if (!Number.isInteger(value.schemaVersion) || value.schemaVersion < 1 || value.schemaVersion > CURRENT_SCHEMA) {
    throw new Error("Unsupported KNS state schema version.");
  }
  const defaults = initialState();
  const state = Object.assign(defaults, value);
  state.settings = Object.assign({}, defaults.settings, value.settings || {});
  for (const field of ["machines", "runtimes", "instances", "jobs", "profiles", "audit", "legacyNodes"]) {
    if (!Array.isArray(state[field])) throw new Error("KNS state field is invalid: " + field);
  }
  if (!state.settings || typeof state.settings !== "object" || Array.isArray(state.settings)) throw new Error("KNS settings are invalid.");
  return state;
}

function createStore(storageDir) {
  const storageRoot = path.resolve(storageDir);
  const root = path.join(storageRoot, "kns");
  const stateFile = path.join(root, "state.json");
  const backupDir = path.join(root, "backups");
  const snapshotDir = path.join(root, "snapshots");
  const subscriptionSnapshotDir = path.join(root, "subscriptions");

  function ensureDirectories() {
    fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(snapshotDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(subscriptionSnapshotDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(root, 0o700); fs.chmodSync(backupDir, 0o700); fs.chmodSync(snapshotDir, 0o700); fs.chmodSync(subscriptionSnapshotDir, 0o700); } catch (_) {}
  }

  function syncFile(filename) {
    const fd = fs.openSync(filename, "r");
    try { fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  }

  function backupStorageBeforeChange(reason) {
    if (!["migration", "upgrade"].includes(reason)) throw new Error("Invalid storage snapshot reason.");
    const suffix = new Date().toISOString().replace(/[:.]/g, "-") + "-" + crypto.randomBytes(5).toString("hex");
    const destination = path.join(backupDir, "pre-" + reason + "-" + suffix);
    const temporary = path.join(path.dirname(storageRoot), "." + path.basename(storageRoot) + "-pre-" + reason + "-" + suffix + ".tmp");
    const rootStat = fs.lstatSync(storageRoot);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("Migration snapshot refuses a non-directory storage root.");
    fs.mkdirSync(temporary, { mode: 0o700 });
    let copyComplete = false;
    try {
      function copyDirectory(source, target) {
        for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
          const sourcePath = path.join(source, entry.name);
          if (path.resolve(source) === path.resolve(backupDir) && (entry.name.startsWith("pre-migration-") || entry.name.startsWith("pre-upgrade-"))) continue;
          const targetPath = path.join(target, entry.name);
          if (entry.isSymbolicLink()) throw new Error("Migration backup refuses symbolic links: " + sourcePath);
          if (entry.isDirectory()) {
            fs.mkdirSync(targetPath, { mode: 0o700 });
            copyDirectory(sourcePath, targetPath);
          } else if (entry.isFile()) {
            fs.copyFileSync(sourcePath, targetPath, fs.constants.COPYFILE_EXCL);
            try { fs.chmodSync(targetPath, 0o600); } catch (_) {}
          } else {
            throw new Error("Migration backup encountered an unsupported file: " + sourcePath);
          }
        }
      }
      copyDirectory(storageRoot, temporary);
      copyComplete = true;
      ensureDirectories();
      fs.renameSync(temporary, destination);
      return destination;
    } catch (error) {
      if (!copyComplete) try { fs.rmSync(temporary, { recursive: true, force: true }); } catch (_) {}
      throw error;
    }
  }

  function subscriptionSnapshotPath(name) {
    if (!/^[a-f0-9]{64}$/.test(String(name))) throw new Error("Invalid subscription snapshot key.");
    return path.join(subscriptionSnapshotDir, String(name) + ".json");
  }

  function readSubscriptionSnapshot(name) {
    const filename = subscriptionSnapshotPath(name);
    if (!fs.existsSync(filename)) return null;
    try { return JSON.parse(fs.readFileSync(filename, "utf8")); }
    catch (error) {
      if (error && error.code === "ENOENT") return null;
      throw new Error("Subscription snapshot could not be read: " + (error.message || String(error)));
    }
  }

  function writeSubscriptionSnapshot(name, value) {
    ensureDirectories();
    const destination = subscriptionSnapshotPath(name);
    const temporary = destination + "." + crypto.randomBytes(8).toString("hex") + ".tmp";
    try {
      fs.writeFileSync(temporary, JSON.stringify(value), { mode: 0o600, flag: "wx" });
      try { fs.chmodSync(temporary, 0o600); } catch (_) {}
      syncFile(temporary);
      fs.renameSync(temporary, destination);
      try { fs.chmodSync(destination, 0o600); } catch (_) {}
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch (_) {}
      throw error;
    }
  }

  function pruneSubscriptionSnapshots(keep) {
    ensureDirectories();
    const names = new Set(Array.from(keep || []).map(String));
    for (const filename of fs.readdirSync(subscriptionSnapshotDir)) {
      const match = /^([a-f0-9]{64})\.json$/.exec(filename);
      if (match && !names.has(match[1])) fs.unlinkSync(path.join(subscriptionSnapshotDir, filename));
    }
  }

  function read() {
    if (!fs.existsSync(stateFile)) return null;
    try { return validateState(JSON.parse(fs.readFileSync(stateFile, "utf8"))); }
    catch (error) {
      if (error && error.code === "ENOENT") return null;
      throw new Error("KNS state could not be read; it was left untouched: " + (error.message || String(error)));
    }
  }

  function backupIfDue() {
    if (!fs.existsSync(stateFile)) return;
    const day = new Date().toISOString().slice(0, 10);
    const destination = path.join(backupDir, "state-" + day + ".json");
    if (fs.existsSync(destination)) return;
    const temp = destination + ".tmp";
    fs.copyFileSync(stateFile, temp);
    try { fs.chmodSync(temp, 0o600); } catch (_) {}
    fs.renameSync(temp, destination);
    const keyPath = path.join(root, "master.key");
    if (fs.existsSync(keyPath)) {
      const keyBackup = path.join(backupDir, "master-" + day + ".key");
      if (!fs.existsSync(keyBackup)) {
        fs.copyFileSync(keyPath, keyBackup);
        try { fs.chmodSync(keyBackup, 0o600); } catch (_) {}
      }
    }
    const backups = fs.readdirSync(backupDir).filter((name) => /^state-\d{4}-\d{2}-\d{2}\.json$/.test(name)).sort();
    while (backups.length > 7) {
      const oldest = backups.shift();
      const dayKey = oldest.slice("state-".length, -".json".length);
      fs.unlinkSync(path.join(backupDir, oldest));
      const keyBackup = path.join(backupDir, "master-" + dayKey + ".key");
      if (fs.existsSync(keyBackup)) fs.unlinkSync(keyBackup);
    }
  }

  function write(state) {
    const value = validateState(state);
    ensureDirectories();
    backupIfDue();
    value.schemaVersion = CURRENT_SCHEMA;
    value.revision = Math.max(0, Number(value.revision) || 0) + 1;
    value.updatedAt = new Date().toISOString();
    const makeSnapshot = value.snapshotPending === true || !value.lastSnapshotAt || Date.now() - Date.parse(value.lastSnapshotAt) >= 5 * 60 * 1000;
    value.snapshotPending = false;
    if (makeSnapshot) value.lastSnapshotAt = value.updatedAt;
    const temp = stateFile + "." + crypto.randomBytes(8).toString("hex") + ".tmp";
    let snapshotTemp = "";
    let snapshotPath = "";
    let snapshotPublished = false;
    try {
      fs.writeFileSync(temp, JSON.stringify(value, null, 2), { mode: 0o600, flag: "wx" });
      try { fs.chmodSync(temp, 0o600); } catch (_) {}
      syncFile(temp);
      if (makeSnapshot) {
        const snapshotName = "snapshot-" + value.updatedAt.replace(/[:.]/g, "-") + "-r" + value.revision + ".json";
        snapshotTemp = path.join(snapshotDir, "." + snapshotName + "." + crypto.randomBytes(6).toString("hex") + ".tmp");
        snapshotPath = path.join(snapshotDir, snapshotName);
        fs.writeFileSync(snapshotTemp, JSON.stringify(value, null, 2), { mode: 0o600, flag: "wx" });
        try { fs.chmodSync(snapshotTemp, 0o600); } catch (_) {}
        syncFile(snapshotTemp);
        fs.renameSync(snapshotTemp, snapshotPath);
        snapshotPublished = true;
      }
      fs.renameSync(temp, stateFile);
    } catch (error) {
      try { fs.unlinkSync(temp); } catch (_) {}
      if (snapshotTemp) try { fs.unlinkSync(snapshotTemp); } catch (_) {}
      if (snapshotPublished) try { fs.unlinkSync(snapshotPath); } catch (_) {}
      throw error;
    }
    try { fs.chmodSync(stateFile, 0o600); } catch (_) {}
    if (makeSnapshot) {
      try {
        const snapshots = fs.readdirSync(snapshotDir).filter((name) => /^snapshot-.*\.json$/.test(name)).sort();
        while (snapshots.length > 288) fs.unlinkSync(path.join(snapshotDir, snapshots.shift()));
      } catch (_) {}
    }
    Object.assign(state, value);
    return value;
  }

  function preparePluginVersion(state, currentVersion) {
    const requested = String(currentVersion || "");
    const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
    const requestedMatch = versionPattern.exec(requested);
    if (!requestedMatch) throw new Error("Current plugin version is invalid.");
    const previous = String(state.pluginVersion || "");
    if (previous === requested) return state;
    if (previous) {
      const previousMatch = versionPattern.exec(previous);
      if (!previousMatch) throw new Error("Stored plugin version is invalid.");
      for (let index = 1; index <= 3; index += 1) {
        const before = Number(previousMatch[index]); const after = Number(requestedMatch[index]);
        if (before > after) throw new Error("KNS state belongs to a newer plugin version.");
        if (before < after) break;
      }
    }
    backupStorageBeforeChange("upgrade");
    state.pluginVersion = requested;
    return write(state);
  }

  function listBackups() {
    ensureDirectories();
    return fs.readdirSync(backupDir).filter((name) => /^state-\d{4}-\d{2}-\d{2}\.json$/.test(name)).sort().reverse();
  }

  function restoreBackup(name) {
    ensureDirectories();
    if (!/^state-\d{4}-\d{2}-\d{2}\.json$/.test(String(name))) throw new Error("Invalid backup name.");
    const source = path.join(backupDir, name);
    const restored = validateState(JSON.parse(fs.readFileSync(source, "utf8")));
    const dayKey = String(name).slice("state-".length, -".json".length);
    const keyBackup = path.join(backupDir, "master-" + dayKey + ".key");
    if (fs.existsSync(keyBackup)) {
      const keyPath = path.join(root, "master.key");
      const keyTemp = keyPath + ".restore";
      fs.copyFileSync(keyBackup, keyTemp);
      try { fs.chmodSync(keyTemp, 0o600); } catch (_) {}
      fs.renameSync(keyTemp, keyPath);
    }
    if (fs.existsSync(stateFile)) {
      const preRestore = path.join(backupDir, "pre-restore-" + Date.now() + ".json");
      fs.copyFileSync(stateFile, preRestore);
      try { fs.chmodSync(preRestore, 0o600); } catch (_) {}
    }
    return write(restored);
  }

  function importBackup(value, key) {
    ensureDirectories();
    const restored = validateState(value);
    const importedKey = Buffer.from(key || []);
    if (importedKey.length !== 32) throw new Error("Imported KNS master key has an invalid length.");
    backupIfDue();
    const keyPath = path.join(root, "master.key");
    const configuredKey = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
    const priorKey = fs.existsSync(keyPath) ? fs.readFileSync(keyPath) : null;
    if (fs.existsSync(stateFile)) {
      const preState = path.join(backupDir, "pre-import-" + Date.now() + ".json");
      fs.copyFileSync(stateFile, preState);
      try { fs.chmodSync(preState, 0o600); } catch (_) {}
    }
    if (priorKey) {
      const preKey = path.join(backupDir, "pre-import-" + Date.now() + ".key");
      fs.copyFileSync(keyPath, preKey);
      try { fs.chmodSync(preKey, 0o600); } catch (_) {}
    }
    let keyChanged = false;
    if (!configuredKey) {
      const keyTemp = keyPath + ".import-" + crypto.randomBytes(6).toString("hex");
      fs.writeFileSync(keyTemp, importedKey, { mode: 0o600, flag: "wx" });
      try { fs.chmodSync(keyTemp, 0o600); } catch (_) {}
      fs.renameSync(keyTemp, keyPath);
      keyChanged = true;
    }
    try {
      return write(restored);
    } catch (error) {
      let committed = false;
      try {
        const current = read();
        committed = !!current && current.revision === restored.revision && current.updatedAt === restored.updatedAt;
      } catch (_) {}
      if (!committed && keyChanged) {
        if (priorKey) {
          const rollback = keyPath + ".rollback";
          fs.writeFileSync(rollback, priorKey, { mode: 0o600 });
          try { fs.chmodSync(rollback, 0o600); } catch (_) {}
          fs.renameSync(rollback, keyPath);
        } else {
          try { fs.unlinkSync(keyPath); } catch (_) {}
        }
      }
      if (committed) return restored;
      throw error;
    }
  }

  return { backupDir, backupStorageBeforeChange, ensureDirectories, importBackup, initialState, listBackups, preparePluginVersion, pruneSubscriptionSnapshots, read, readSubscriptionSnapshot, restoreBackup, root, snapshotDir, stateFile, subscriptionSnapshotDir, write, writeSubscriptionSnapshot };
}

module.exports = { CURRENT_SCHEMA, createStore, initialState, validateState };
