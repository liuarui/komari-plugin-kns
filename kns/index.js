"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const server = require("server");
const { createStore, initialState, validateState } = require("./store");
const secrets = require("./crypto");
const subscriptions = require("./subscription");

const API = "/api/kns";
const LEGACY_API = "/api/onebox-bridge";
const INSTALLER_URL = "https://raw.githubusercontent.com/liuarui/onebox/7c70c71957f6f96a3deca983745f7414fe1e490e/install.sh";
const INSTALLER_SHA256 = "9c803f549eb6c579fed8a9e385e43d9a872235ab804e99da01e44eb361b458fa";
const ONEBOX_ADAPTER_VERSION = "1.2.0";
const SUBSCRIPTION_RULES_VERSION = "kns-subscription-v1";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PROTOCOLS = {
  vless: { transport: "tcp", security: "reality" },
  trojan: { transport: "tcp", security: "tls" },
  vmess: { transport: "tcp", security: "tls" },
  shadowsocks: { transport: "tcp+udp", security: "none" },
  hysteria2: { transport: "udp", security: "tls" },
  tuic: { transport: "udp", security: "tls" },
  anytls: { transport: "tcp", security: "tls" },
};
const FORMATS = new Set(["uri", "mihomo-full", "mihomo-provider", "singbox-full", "singbox-outbounds"]);
const store = createStore(__storageDir__);
let masterKey = secrets.getMasterKey(__storageDir__);

let pollBusy = false;
let syncBusy = false;
let healthBusy = false;
let endpointBusy = false;
let lastLiveSync = 0;
let stateCache = null;
let subscriptionRefreshBusy = false;
let subscriptionRefreshPending = false;
let subscriptionRefreshTimer = null;
let subscriptionRefreshStopped = false;
const pendingTokenUsage = new Map();

function now() { return new Date().toISOString(); }
function randomId(prefix) { return prefix + "-" + Date.now().toString(36) + "-" + crypto.randomBytes(5).toString("hex"); }
function deepClone(value) { return JSON.parse(JSON.stringify(value)); }
function fail(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status || 400;
  throw error;
}

function json(res, status, value) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(value));
}

function encryptedBackupEnvelope(state, passphrase) {
  const secret = String(passphrase || "");
  if (secret.length < 12 || secret.length > 256) fail("invalid_export_passphrase", "加密备份口令长度必须在 12 至 256 个字符之间。", 400);
  const iterations = 310000;
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(secret, salt, iterations, 32, "sha256");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from("KNS-ENCRYPTED-EXPORT-v1", "utf8"));
  const payload = JSON.stringify({ format: "KNS-ENCRYPTED-EXPORT", schemaVersion: 1, createdAt: now(), masterKey: masterKey.toString("hex"), state: deepClone(state) });
  const data = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
  return {
    format: "KNS-ENCRYPTED-EXPORT",
    schemaVersion: 1,
    kdf: { name: "PBKDF2-SHA256", iterations, salt: salt.toString("hex") },
    cipher: { name: "AES-256-GCM", aad: "KNS-ENCRYPTED-EXPORT-v1", iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), data: data.toString("base64") },
  };
}

function decryptBackupEnvelope(envelope, passphrase) {
  const secret = String(passphrase || "");
  if (secret.length < 12 || secret.length > 256) fail("invalid_export_passphrase", "加密备份口令长度必须在 12 至 256 个字符之间。", 400);
  if (!envelope || envelope.format !== "KNS-ENCRYPTED-EXPORT" || envelope.schemaVersion !== 1 || !envelope.kdf || envelope.kdf.name !== "PBKDF2-SHA256" || envelope.kdf.iterations !== 310000 || !/^[a-f0-9]{32}$/i.test(String(envelope.kdf.salt || "")) || !envelope.cipher || envelope.cipher.name !== "AES-256-GCM" || envelope.cipher.aad !== "KNS-ENCRYPTED-EXPORT-v1" || !/^[a-f0-9]{24}$/i.test(String(envelope.cipher.iv || "")) || !/^[a-f0-9]{32}$/i.test(String(envelope.cipher.tag || "")) || typeof envelope.cipher.data !== "string") fail("invalid_backup_envelope", "加密备份结构或版本无效。", 400);
  try {
    const key = crypto.pbkdf2Sync(secret, Buffer.from(envelope.kdf.salt, "hex"), envelope.kdf.iterations, 32, "sha256");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.cipher.iv, "hex"));
    decipher.setAAD(Buffer.from(envelope.cipher.aad, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.cipher.tag, "hex"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.cipher.data, "base64")), decipher.final()]).toString("utf8");
    const payload = JSON.parse(plaintext);
    const importedKey = Buffer.from(String(payload.masterKey || ""), "hex");
    if (payload.format !== "KNS-ENCRYPTED-EXPORT" || payload.schemaVersion !== 1 || importedKey.length !== 32) fail("invalid_backup_payload", "加密备份正文结构无效。", 400);
    return { key: importedKey, state: validateState(payload.state) };
  } catch (error) {
    if (error && error.code && error.status) throw error;
    fail("backup_decrypt_failed", "无法解密加密备份；请检查口令和文件完整性。", 400);
  }
}

function isAdmin(req) {
  const principal = (req.context || {}).principal || {};
  const roles = Array.isArray(principal.roles) ? principal.roles : [];
  return roles.includes("admin") || principal.role === "admin";
}

function requireAdmin(req, res) {
  if (isAdmin(req)) return true;
  json(res, req.context && req.context.principal ? 403 : 401, { error: { code: "admin_required", message: "需要 Komari 管理员权限。" } });
  return false;
}

function checkOrigin(req) {
  const headers = req.headers || {};
  const origin = String(headers.origin || "");
  if (!origin) {
    if (String(headers.authorization || "").startsWith("Bearer ") || String(headers["sec-fetch-site"] || "") === "same-origin") return;
    fail("csrf_origin", "管理写入请求必须带同源 Origin 或 Bearer API 身份。", 403);
  }
  const host = String(headers.host || "").toLowerCase();
  let originHost = "";
  try { originHost = new URL(origin).host.toLowerCase(); } catch (_) { fail("csrf_origin", "请求来源无效。", 403); }
  if (!host || originHost !== host) fail("csrf_origin", "跨站管理请求已拒绝。", 403);
}

function readBody(req, maxBytes) {
  const type = String((req.headers || {})["content-type"] || "").toLowerCase();
  const body = String(req.body || "");
  const limit = Number(maxBytes) || 1024 * 1024;
  if (body.length > limit) fail("body_too_large", "请求正文超过允许大小。", 413);
  if (!type.includes("application/json")) fail("unsupported_media_type", "请求必须使用 application/json。", 415);
  let value;
  try { value = JSON.parse(body); } catch (_) { fail("invalid_json", "JSON 格式无效。", 400); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_json", "请求正文必须是 JSON 对象。", 400);
  return value;
}

function safeText(value, max) { return String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max || 160); }

function profileList(value, field, allowed, maxItems) {
  if (!Array.isArray(value)) fail("invalid_profile_filter", field + " 必须是数组。", 400);
  const values = Array.from(new Set(value.map((item) => safeText(item, 128)).filter(Boolean)));
  if (values.length > maxItems || values.some((item) => !allowed(item))) fail("invalid_profile_filter", field + " 含有无效或过多的值。", 400);
  return values;
}

function profileFilterFields(body, current) {
  const next = Object.assign({}, current || {});
  if (Object.prototype.hasOwnProperty.call(body, "instanceIds")) {
    const ids = profileList(body.instanceIds, "instanceIds", (item) => ID_RE.test(item), 500);
    next.instanceIds = ids.length ? ids : null;
  }
  if (Object.prototype.hasOwnProperty.call(body, "machineUuids")) {
    const ids = profileList(body.machineUuids, "machineUuids", (item) => UUID_RE.test(item), 500);
    next.machineUuids = ids.length ? ids : null;
  }
  if (Object.prototype.hasOwnProperty.call(body, "excludeMachineUuids")) {
    next.excludeMachineUuids = profileList(body.excludeMachineUuids, "excludeMachineUuids", (item) => UUID_RE.test(item), 500);
  }
  if (Object.prototype.hasOwnProperty.call(body, "protocols")) {
    const protocols = profileList(body.protocols, "protocols", (item) => Object.prototype.hasOwnProperty.call(PROTOCOLS, item), Object.keys(PROTOCOLS).length);
    next.protocols = protocols.length ? protocols : null;
  }
  if (Object.prototype.hasOwnProperty.call(body, "includeTags")) {
    next.includeTags = profileList(body.includeTags, "includeTags", (item) => item.length <= 32, 100);
  }
  if (Object.prototype.hasOwnProperty.call(body, "formats")) {
    const formats = profileList(body.formats, "formats", (item) => FORMATS.has(item), FORMATS.size);
    if (!formats.length) fail("invalid_formats", "至少选择一种有效订阅格式。", 400);
    next.formats = formats;
  }
  if (Object.prototype.hasOwnProperty.call(body, "addressMode")) {
    if (!["auto", "ipv4", "ipv6", "dual"].includes(body.addressMode)) fail("invalid_profile_filter", "订阅地址模式无效。", 400);
    next.addressMode = body.addressMode;
  }
  if (Object.prototype.hasOwnProperty.call(body, "sortBy")) {
    if (!["name", "protocol", "endpoint", "machine"].includes(body.sortBy)) fail("invalid_profile_filter", "订阅排序方式无效。", 400);
    next.sortBy = body.sortBy;
  }
  if (Object.prototype.hasOwnProperty.call(body, "excludeUnhealthy")) next.excludeUnhealthy = body.excludeUnhealthy !== false;
  if (Object.prototype.hasOwnProperty.call(body, "expiresAt")) next.expiresAt = body.expiresAt ? validateFutureDate(body.expiresAt) : "";
  return next;
}

function getState() {
  let state = store.read();
  if (state) return state;
  state = initialState();
  const legacyPath = path.join(__storageDir__, "onebox-bridge.json");
  if (fs.existsSync(legacyPath)) {
    let legacy;
    try { legacy = JSON.parse(fs.readFileSync(legacyPath, "utf8")); }
    catch (_) { fail("legacy_state_corrupt", "旧版数据文件损坏，已保留原文件；请从备份恢复后再升级。", 500); }
    if (legacy && typeof legacy === "object") migrateLegacy(state, legacy);
  }
  return store.write(state);
}

function migrateLegacy(state, legacy) {
  if (legacy.settings && typeof legacy.settings === "object") {
    if (legacy.settings.converterUrl) state.settings.converterUrl = safeText(legacy.settings.converterUrl, 300);
    if (["clash", "singbox"].includes(legacy.settings.converterTarget)) state.settings.converterTarget = legacy.settings.converterTarget;
  }
  const oldToken = typeof legacy.token === "string" ? legacy.token : "";
  if (oldToken.length >= 32) {
    const token = secrets.tokenRecord(oldToken);
    state.profiles.push({ id: "legacy-default", name: "旧版默认订阅", ...token, createdAt: now(), formats: ["uri", "mihomo-full", "singbox-full"], instanceIds: [], includeTags: [], excludeUnhealthy: false, legacy: true });
  }
  for (const record of Array.isArray(legacy.records) ? legacy.records : []) {
    const uuid = String(record.clientUuid || "");
    if (UUID_RE.test(uuid) && !state.machines.some((machine) => machine.uuid === uuid)) {
      state.machines.push({ uuid, name: safeText(record.clientName || uuid), online: null, lastSeen: null, ipv4: "", ipv6: "", sourceIp: "", policy: { deployAllowed: false, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [] }, updatedAt: now() });
    }
    if (typeof record.link === "string" && record.link) {
      state.legacyNodes.push({ id: randomId("legacy"), machineUuid: uuid, name: safeText(record.clientName || uuid), ciphertext: secrets.encryptSecret(record.link, masterKey), enabled: record.state === "published", migratedAt: now() });
    }
  }
  state.audit.push({ id: randomId("audit"), at: now(), action: "state.migrated", actor: "system", details: { from: "onebox-bridge", records: state.legacyNodes.length } });
}

function save(state) {
  stateCache = null;
  const saved = store.write(state);
  scheduleSubscriptionRefresh();
  return saved;
}

function subscriptionSnapshotKey(profileId, format) {
  return crypto.createHash("sha256").update(String(profileId) + "\n" + String(format)).digest("hex");
}

function subscriptionSourceHash(state, profile, format) {
  const projection = {
    format,
    profile: {
      id: profile.id,
      legacy: profile.legacy === true,
      instanceIds: profile.instanceIds || null,
      machineUuids: profile.machineUuids || null,
      excludeMachineUuids: profile.excludeMachineUuids || [],
      protocols: profile.protocols || null,
      includeTags: profile.includeTags || [],
      excludeUnhealthy: profile.excludeUnhealthy !== false,
      addressMode: profile.addressMode || "auto",
      sortBy: profile.sortBy || "name",
    },
    machines: (state.machines || []).map((machine) => ({ uuid: machine.uuid, name: machine.name })),
    instances: state.instances || [],
    legacyNodes: profile.legacy ? (state.legacyNodes || []) : [],
  };
  return crypto.createHash("sha256").update(JSON.stringify(projection)).digest("hex");
}

function readSubscriptionSnapshot(profileId, format) {
  const box = store.readSubscriptionSnapshot(subscriptionSnapshotKey(profileId, format));
  if (!box) return null;
  const record = JSON.parse(secrets.decryptSecret(box, masterKey));
  if (!record || record.schemaVersion !== 1 || record.profileId !== profileId || record.format !== format || record.rulesVersion !== SUBSCRIPTION_RULES_VERSION || typeof record.body !== "string" || typeof record.contentType !== "string" || !/^[a-f0-9]{64}$/.test(record.contentHash || "") || !/^[a-f0-9]{64}$/.test(record.sourceHash || "") || !Number.isSafeInteger(record.successCount) || !Number.isSafeInteger(record.skippedCount) || !Number.isFinite(Date.parse(record.generatedAt || "")) || crypto.createHash("sha256").update(record.body).digest("hex") !== record.contentHash) {
    throw new Error("Subscription snapshot is invalid.");
  }
  return record;
}

function activeSubscriptionProfile(profile) {
  return profile && !profile.revokedAt && (!profile.expiresAt || Date.parse(profile.expiresAt) > Date.now());
}

async function refreshSubscriptionSnapshots() {
  if (subscriptionRefreshBusy || subscriptionRefreshStopped) { subscriptionRefreshPending = true; return; }
  subscriptionRefreshBusy = true;
  subscriptionRefreshPending = false;
  try {
    const initial = getState();
    const queue = [];
    for (const profile of initial.profiles) {
      if (!activeSubscriptionProfile(profile)) continue;
      for (const format of Array.isArray(profile.formats) ? profile.formats : []) {
        if (FORMATS.has(format)) queue.push({ profileId: profile.id, format });
      }
    }
    for (const item of queue) {
      if (subscriptionRefreshStopped) break;
      const current = getState();
      const profile = current.profiles.find((candidate) => candidate.id === item.profileId);
      if (!activeSubscriptionProfile(profile) || !Array.isArray(profile.formats) || !profile.formats.includes(item.format)) continue;
      const sourceHash = subscriptionSourceHash(current, profile, item.format);
      try {
        const existing = readSubscriptionSnapshot(profile.id, item.format);
        if (existing && existing.sourceHash === sourceHash) continue;
      } catch (_) {}
      try {
        const built = subscriptions.buildSubscription(current, profile, item.format, (box) => secrets.decryptSecret(box, masterKey));
        const record = {
          schemaVersion: 1,
          profileId: profile.id,
          format: item.format,
          sourceHash,
          rulesVersion: SUBSCRIPTION_RULES_VERSION,
          generatedAt: now(),
          successCount: built.successCount,
          skippedCount: built.skippedCount,
          contentType: built.contentType,
          contentHash: crypto.createHash("sha256").update(built.body).digest("hex"),
          body: built.body,
        };
        const encrypted = secrets.encryptSecret(JSON.stringify(record), masterKey);
        store.writeSubscriptionSnapshot(subscriptionSnapshotKey(profile.id, item.format), encrypted);
      } catch (error) {
        console.error("[KNS] subscription snapshot refresh failed:", safeText(error && error.message || error, 200));
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    if (!subscriptionRefreshStopped) {
      const latest = getState();
      const keep = [];
      for (const profile of latest.profiles) {
        if (!activeSubscriptionProfile(profile)) continue;
        for (const format of Array.isArray(profile.formats) ? profile.formats : []) if (FORMATS.has(format)) keep.push(subscriptionSnapshotKey(profile.id, format));
      }
      store.pruneSubscriptionSnapshots(keep);
    }
  } catch (error) {
    console.error("[KNS] subscription snapshot refresh failed:", safeText(error && error.message || error, 200));
  } finally {
    subscriptionRefreshBusy = false;
    if (subscriptionRefreshPending && !subscriptionRefreshStopped) scheduleSubscriptionRefresh();
  }
}

function scheduleSubscriptionRefresh() {
  subscriptionRefreshPending = true;
  if (subscriptionRefreshBusy || subscriptionRefreshTimer || subscriptionRefreshStopped) return;
  subscriptionRefreshTimer = setTimeout(() => {
    subscriptionRefreshTimer = null;
    refreshSubscriptionSnapshots();
  }, 0);
}

function audit(state, req, action, details) {
  const principal = req && req.context && req.context.principal ? req.context.principal : {};
  state.audit.push({ id: randomId("audit"), at: now(), action, actor: safeText(principal.username || principal.name || principal.id || "admin", 80), details: details || {} });
  state.snapshotPending = true;
  if (state.audit.length > 1000) state.audit = state.audit.slice(-1000);
}

function profileTokenRecords(profile) {
  if (Array.isArray(profile && profile.tokens)) return profile.tokens;
  if (profile && profile.salt && profile.hash) {
    return [{ id: "legacy-token", salt: profile.salt, hash: profile.hash, createdAt: profile.createdAt || "", expiresAt: profile.expiresAt || "", revokedAt: "", graceUntil: "", accessCount: Number(profile.accessCount || 0), lastUsedAt: profile.lastUsedAt || "" }];
  }
  return [];
}

function ensureProfileTokens(profile) {
  if (!Array.isArray(profile.tokens)) {
    profile.tokens = profileTokenRecords(profile).map((record) => Object.assign({}, record));
    delete profile.salt;
    delete profile.hash;
    delete profile.accessCount;
    delete profile.lastUsedAt;
  }
  return profile.tokens;
}

function createProfileToken(profile, token, expiresAt) {
  const credentials = secrets.tokenRecord(token);
  const record = Object.assign({ id: randomId("token"), createdAt: now(), expiresAt: expiresAt || "", revokedAt: "", graceUntil: "", accessCount: 0, lastUsedAt: "" }, credentials);
  ensureProfileTokens(profile).push(record);
  return record;
}

function safeProfileToken(token) {
  return {
    id: safeText(token.id || "legacy-token", 80),
    createdAt: token.createdAt || "",
    expiresAt: token.expiresAt || "",
    revokedAt: token.revokedAt || "",
    graceUntil: token.graceUntil || "",
    accessCount: Math.max(0, Number(token.accessCount) || 0),
    lastUsedAt: token.lastUsedAt || "",
  };
}

function recordTokenUsage(profileId, tokenId) {
  const key = String(profileId) + "\n" + String(tokenId);
  const current = pendingTokenUsage.get(key) || { profileId: String(profileId), tokenId: String(tokenId), count: 0 };
  current.count += 1;
  current.lastUsedAt = now();
  pendingTokenUsage.set(key, current);
}

function flushTokenUsage() {
  if (!pendingTokenUsage.size) return;
  const updates = Array.from(pendingTokenUsage.values());
  pendingTokenUsage.clear();
  const state = getState();
  let changed = false;
  for (const update of updates) {
    const profile = state.profiles.find((candidate) => candidate.id === update.profileId);
    if (!profile) continue;
    const token = ensureProfileTokens(profile).find((candidate) => (candidate.id || "legacy-token") === update.tokenId);
    if (!token) continue;
    token.accessCount = Math.max(0, Number(token.accessCount) || 0) + update.count;
    token.lastUsedAt = update.lastUsedAt;
    changed = true;
  }
  if (changed) save(state);
}

function nodesFrom(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.data)) return value.data;
  if (value && Array.isArray(value.clients)) return value.clients;
  return [];
}

function firstString(object, keys) {
  for (const key of keys) if (object && typeof object[key] === "string" && object[key]) return object[key];
  return "";
}

function normalizeMachine(raw) {
  const uuid = String(raw.uuid || raw.client_uuid || raw.clientUuid || "").toLowerCase();
  if (!UUID_RE.test(uuid)) return null;
  const ipv4 = firstString(raw, ["ipv4", "ip4", "ipv4_address"]);
  const ipv6 = firstString(raw, ["ipv6", "ip6", "ipv6_address"]);
  return {
    uuid,
    name: safeText(raw.name || raw.hostname || uuid, 100),
    region: safeText(raw.region || "", 100),
    os: safeText(raw.os || raw.platform || "", 80),
    arch: safeText(raw.arch || raw.architecture || "", 40),
    online: typeof raw.online === "boolean" ? raw.online : (typeof raw.is_online === "boolean" ? raw.is_online : null),
    lastSeen: firstString(raw, ["last_seen", "lastSeen", "last_report", "lastReport"]),
    ipv4,
    ipv6,
    sourceIp: firstString(raw, ["ip", "ip_address", "source_ip", "sourceIp"]),
    updatedAt: now(),
  };
}

async function syncMachines() {
  if (syncBusy) return;
  syncBusy = true;
  try {
    const live = nodesFrom(await server.call("admin:listClients")).map(normalizeMachine).filter(Boolean);
    const state = getState();
    const current = new Map(state.machines.map((machine) => [machine.uuid, machine]));
    const incoming = [];
    for (const node of live) {
      const old = current.get(node.uuid) || { policy: { deployAllowed: false, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [] } };
      const merged = Object.assign({}, old, node);
      merged.policy = Object.assign({ deployAllowed: false, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [] }, old.policy || {});
      const observed = preferredObservedAddress(merged);
      const prior = old.observedAddress || "";
      if (observed && observed !== prior) {
        merged.addressCandidate = observed === (old.addressCandidate || "") ? observed : observed;
        merged.addressCandidateCount = observed === (old.addressCandidate || "") ? Number(old.addressCandidateCount || 0) + 1 : 1;
        if (merged.addressCandidateCount >= 2) merged.observedAddress = observed;
      } else if (observed) {
        merged.addressCandidate = observed;
        merged.addressCandidateCount = Number(old.addressCandidateCount || 1);
      }
      incoming.push(merged);
    }
    const known = new Set(incoming.map((machine) => machine.uuid));
    state.machines = incoming.concat(state.machines.filter((machine) => !known.has(machine.uuid)).map((machine) => Object.assign({}, machine, { online: false })));
    lastLiveSync = Date.now();
    save(state);
  } finally { syncBusy = false; }
}

function preferredObservedAddress(machine) {
  const mode = machine.policy && machine.policy.addressMode || "auto";
  if (mode === "ipv4") return machine.ipv4 || "";
  if (mode === "ipv6") return machine.ipv6 || "";
  if (mode === "dual") return [machine.ipv4, machine.ipv6].filter(Boolean).join(",");
  return machine.ipv4 || machine.ipv6 || machine.sourceIp || "";
}

function safeMachine(machine) {
  return {
    uuid: machine.uuid, name: machine.name, region: machine.region, os: machine.os, arch: machine.arch,
    online: machine.online, lastSeen: machine.lastSeen, ipv4: machine.ipv4, ipv6: machine.ipv6, sourceIp: machine.sourceIp,
    observedAddress: machine.observedAddress || "", addressCandidate: machine.addressCandidate || "", policy: machine.policy,
  };
}

function safeInstance(instance) {
  const copy = deepClone(instance);
  delete copy.credential;
  delete copy.credentialCiphertext;
  delete copy.callbackToken;
  return copy;
}

function safeJob(job) {
  const copy = deepClone(job);
  delete copy.callbackTokenHash;
  delete copy.callbackTokenSalt;
  if (copy.callback) {
    if (copy.callback.instance) {
      delete copy.callback.instance.credential;
      delete copy.callback.instance.credentialCiphertext;
    }
  }
  return copy;
}

function publicState(state) {
  return {
    schemaVersion: state.schemaVersion,
    revision: state.revision,
    updatedAt: state.updatedAt,
    settings: Object.assign({}, state.settings, { oneboxScriptUrl: INSTALLER_URL, oneboxScriptSha256: INSTALLER_SHA256 }),
    machines: state.machines.map(safeMachine),
    runtimes: state.runtimes,
    instances: state.instances.map(safeInstance),
    jobs: state.jobs.slice(-200).reverse().map(safeJob),
    profiles: state.profiles.map((profile) => ({ id: profile.id, name: profile.name, createdAt: profile.createdAt, expiresAt: profile.expiresAt || "", revokedAt: profile.revokedAt || "", tokens: profileTokenRecords(profile).map(safeProfileToken), formats: profile.formats, instanceIds: profile.instanceIds || null, machineUuids: profile.machineUuids || null, excludeMachineUuids: profile.excludeMachineUuids || [], protocols: profile.protocols || null, includeTags: profile.includeTags || [], excludeUnhealthy: profile.excludeUnhealthy !== false, addressMode: profile.addressMode || "auto", sortBy: profile.sortBy || "name", legacy: !!profile.legacy })),
    backups: store.listBackups(),
    subscriptionFormats: Array.from(FORMATS),
    endpointPrecedence: ["instance endpoint override", "machine manual public address", "DDNS domain", "Komari-reported address"],
  };
}

function quoteShell(value) { return "'" + String(value).replace(/'/g, "'\"'\"'") + "'"; }

function validHostname(value) {
  const host = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  if (host.length > 253 || !host || host.includes(":") || host.includes("/") || host.includes("@")) return "";
  const labels = host.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return "";
  return host;
}

function normalizeHost(value, allowPrivate) {
  const host = String(value || "").trim().replace(/^\[|\]$/g, "");
  let net;
  try { net = require("net"); } catch (_) { net = null; }
  const family = net && net.isIP ? net.isIP(host) : (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ? 4 : host.includes(":") ? 6 : 0);
  if (family === 4) {
    const nums = host.split(".").map(Number);
    if (nums.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) fail("invalid_host", "IPv4 地址无效。", 400);
    if (nums[0] === 0 || nums[0] >= 224) fail("invalid_host", "Endpoint 不能使用未指定、组播或保留 IPv4 地址。", 400);
    const privateV4 = nums[0] === 10 || nums[0] === 127 || nums[0] === 0 || (nums[0] === 169 && nums[1] === 254) || (nums[0] === 172 && nums[1] >= 16 && nums[1] <= 31) || (nums[0] === 192 && nums[1] === 168) || nums[0] >= 224 || (nums[0] === 100 && nums[1] >= 64 && nums[1] <= 127) || (nums[0] === 192 && nums[1] === 0) || (nums[0] === 198 && (nums[1] === 18 || nums[1] === 19 || nums[1] === 51)) || (nums[0] === 203 && nums[1] === 0 && nums[2] === 113);
    if (privateV4 && !allowPrivate) fail("private_endpoint", "公网订阅不能使用私有、回环或保留 IPv4 地址。", 400);
    return host;
  }
  if (family === 6) {
    const lowered = host.toLowerCase();
    if (lowered === "::" || lowered.startsWith("ff")) fail("invalid_host", "Endpoint 不能使用未指定或组播 IPv6 地址。", 400);
    const privateV6 = lowered === "::1" || /^f[cd]/.test(lowered) || /^fe[89ab]/.test(lowered) || lowered.startsWith("2001:db8:") || lowered.includes("::ffff:") && /(?:::ffff:)(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(lowered);
    if (privateV6 && !allowPrivate) fail("private_endpoint", "公网订阅不能使用私有、回环或保留 IPv6 地址。", 400);
    return host;
  }
  const hostname = validHostname(host);
  if (!hostname) fail("invalid_host", "Endpoint 必须是有效公网 IP 或域名。", 400);
  return hostname;
}

function candidateAddress(machine, state, instance) {
  const override = instance.endpointOverride || {};
  const manual = override.host || (machine.policy && machine.policy.manualAddress);
  const mode = machine.policy && machine.policy.addressMode || "auto";
  if (!manual && !(machine.policy && machine.policy.ddnsHostname) && mode === "ipv4" && !machine.ipv4) return null;
  if (!manual && !(machine.policy && machine.policy.ddnsHostname) && mode === "ipv6" && !machine.ipv6) return null;
  let hosts = [];
  if (!manual && !(machine.policy && machine.policy.ddnsHostname) && mode === "dual") hosts = [machine.ipv4, machine.ipv6].filter(Boolean);
  if (!manual && !(machine.policy && machine.policy.ddnsHostname) && !hosts.length && machine.observedAddress) hosts = String(machine.observedAddress).split(",").filter(Boolean);
  let host = manual || (machine.policy && machine.policy.ddnsHostname) || hosts[0] || machine.ipv4 || machine.ipv6 || machine.sourceIp;
  let source = manual ? (override.host ? "profile_override" : "manual") : ((machine.policy && machine.policy.ddnsHostname) ? "ddns" : "komari");
  if (String(host).includes(",")) {
    const family = machine.policy && machine.policy.addressMode;
    const parts = String(host).split(",");
    host = family === "ipv6" ? parts[1] || parts[0] : parts[0];
  }
  if (!host) return null;
  host = normalizeHost(host, !!state.settings.privateSite);
  const port = Number(override.port || (instance.nat && instance.nat.externalPort) || (instance.listen || {}).port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (!hosts.length) hosts = [host];
  hosts = Array.from(new Set(hosts.map((item) => normalizeHost(item, !!state.settings.privateSite))));
  return { host, hosts, port, source, family: hosts.length > 1 ? "dual" : (host.includes(":") ? "ipv6" : "ipv4_or_domain"), updatedAt: now(), resolvedAddresses: [] };
}

function validatePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail("invalid_port", "Endpoint 端口必须是 1–65535 之间的整数。", 400);
  return port;
}

function makeEndpointOverride(host, port, allowPrivate) {
  if (!host) return null;
  const value = { host: normalizeHost(host, allowPrivate) };
  if (port !== undefined && port !== null && port !== "") value.port = validatePort(port);
  return value;
}

function endpointConfigFingerprint(machine, instance, endpoint) {
  return JSON.stringify({
    endpoint: { host: endpoint.host, hosts: endpoint.hosts || [], port: endpoint.port, source: endpoint.source, family: endpoint.family, resolvedAddresses: endpoint.resolvedAddresses || [] },
    policy: { addressMode: machine.policy && machine.policy.addressMode || "auto", manualAddress: machine.policy && machine.policy.manualAddress || "", ddnsHostname: machine.policy && machine.policy.ddnsHostname || "" },
    endpointOverride: instance.endpointOverride || null,
    nat: instance.nat || null,
    listen: instance.listen || null,
  });
}

function validateProtocolSettings(body) {
  const protocol = String(body.protocol || "").toLowerCase();
  const definition = PROTOCOLS[protocol];
  if (!definition) fail("unsupported_protocol", "不支持的协议。", 400);
  const port = Number(body.listenPort || body.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail("invalid_port", "监听端口必须在 1–65535 之间。", 400);
  const options = body.options && typeof body.options === "object" ? body.options : {};
  const allowedOptions = new Set(["security", "sni", "method"]);
  if (Object.keys(options).some((key) => !allowedOptions.has(key))) fail("invalid_options", "OneBox 适配器当前只接受 security、sni、method 选项。", 400);
  const sni = options.sni ? validHostname(options.sni) : "";
  if (options.sni && !sni) fail("invalid_sni", "SNI 必须是域名。", 400);
  if (["trojan", "vmess", "hysteria2", "tuic", "anytls"].includes(protocol) && !sni) fail("sni_required", "该协议需要配置 TLS SNI。", 400);
  if (protocol === "vless" && options.security !== "reality") fail("security_required", "当前 OneBox 适配器要求 VLESS 使用 Reality。", 400);
  if (protocol === "shadowsocks" && options.method && !["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].includes(String(options.method))) fail("invalid_method", "Shadowsocks 加密方法不受当前 OneBox 适配器支持。", 400);
  if (protocol === "shadowsocks" && !options.method) fail("method_required", "Shadowsocks 需要指定加密方法。", 400);
  const listenAddress = String(body.listenAddress || "::");
  if (!["::", "0.0.0.0", "127.0.0.1", "::1"].includes(listenAddress)) fail("invalid_listen_address", "监听地址只允许 ::、0.0.0.0、127.0.0.1 或 ::1。", 400);
  return { protocol, port, transport: definition.transport, options: Object.assign({}, options, { sni }), listenAddress };
}

function portConflicts(state, machineUuid, port, transport, ignoreId, listenAddress) {
  const wantsTcp = transport === "tcp" || transport === "tcp+udp";
  const wantsUdp = transport === "udp" || transport === "tcp+udp";
  const address = listenAddress || "::";
  return state.instances.some((instance) => {
    if (instance.machineUuid !== machineUuid || instance.id === ignoreId || instance.deletedAt) return false;
    const listen = instance.listen || {};
    if (Number(listen.port) !== port) return false;
    const existingAddress = listen.address || "::";
    const overlapsAddress = existingAddress === address || ["::", "0.0.0.0"].includes(existingAddress) || ["::", "0.0.0.0"].includes(address);
    if (!overlapsAddress) return false;
    const existing = listen.transport || "tcp";
    return (wantsTcp && (existing === "tcp" || existing === "tcp+udp")) || (wantsUdp && (existing === "udp" || existing === "tcp+udp"));
  });
}

function natMappingConflicts(state, externalPort, transport, publicHosts, ignoreId) {
  const wantsTcp = transport === "tcp" || transport === "tcp+udp";
  const wantsUdp = transport === "udp" || transport === "tcp+udp";
  const hosts = new Set((publicHosts || []).map((host) => String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")).filter(Boolean));
  return state.instances.some((instance) => {
    if (instance.id === ignoreId || instance.deletedAt || Number(instance.nat && instance.nat.externalPort) !== Number(externalPort)) return false;
    const existingTransport = (instance.listen || {}).transport || "tcp";
    if (!((wantsTcp && (existingTransport === "tcp" || existingTransport === "tcp+udp")) || (wantsUdp && (existingTransport === "udp" || existingTransport === "tcp+udp")))) return false;
    const existingHosts = (instance.nat && instance.nat.publicHosts) || [instance.nat && instance.nat.publicHost, instance.endpoint && instance.endpoint.host].filter(Boolean);
    return existingHosts.some((host) => hosts.has(String(host).trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")));
  });
}

function checkTwoFactor(value) {
  const code = String(value || "").trim();
  if (code && !/^\d{6,8}$/.test(code)) fail("invalid_2fa", "2FA 验证码必须是 6 或 8 位数字。", 400);
  return code;
}

function makeRemoteCommand(state, job, instance) {
  const callbackUrl = state.settings.publicBaseUrl.replace(/\/$/, "") + API + "/report";
  const request = {
    schema: 1,
    jobId: job.id,
    machineUuid: job.machineUuid,
    action: job.action,
    runtime: { engine: "sing-box", id: instance.runtimeId || "onebox-main" },
    instance: {
      id: instance.id,
      protocol: instance.protocol,
      listenPort: instance.listen.port,
      listenAddress: instance.listen.address || "::",
      transport: instance.listen.transport,
      options: instance.options || {},
    },
    idempotencyKey: job.idempotencyKey,
    report: { callback: callbackUrl, oneTimeToken: job._callbackToken },
  };
  const payload = Buffer.from(JSON.stringify(request), "utf8").toString("base64");
  const scriptUrl = INSTALLER_URL;
  const digest = INSTALLER_SHA256;
  const installer = quoteShell(scriptUrl);
  const statusId = quoteShell(instance.id);
  return [
    "set -u",
    "[ \"$(id -u)\" -eq 0 ] || { echo 'KNS requires a root Komari Agent.' >&2; exit 77; }",
    "command -v base64 >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 || { echo 'KNS requires base64 and sha256sum.' >&2; exit 127; }",
    "request_dir=/run/onebox/kns/requests; mkdir -p \"$request_dir\" && chmod 700 \"$request_dir\" || exit 1",
    "request_file=$(mktemp \"$request_dir/kns.XXXXXX\") || exit 1",
    "installer=$(mktemp) || { rm -f \"$request_file\"; exit 1; }",
    "trap 'rm -f \"$request_file\" \"$installer\"' EXIT",
    "printf %s " + quoteShell(payload) + " | base64 -d > \"$request_file\" && chmod 600 \"$request_file\" || exit 1",
    "if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 180 " + installer + " -o \"$installer\"; elif command -v wget >/dev/null 2>&1; then wget -qO \"$installer\" " + installer + "; else echo 'KNS requires curl or wget.' >&2; exit 127; fi",
    "printf '%s  %s\\n' " + quoteShell(digest) + " \"$installer\" | sha256sum -c - >/dev/null || { echo 'OneBox installer SHA256 mismatch.' >&2; exit 65; }",
    "bash \"$installer\" kns " + quoteShell(job.action) + " --request-file \"$request_file\"",
    "kns_rc=$?; [ \"$kns_rc\" -eq 0 ] || exit \"$kns_rc\"",
    "if [ " + quoteShell(job.action) + " = uninstall ]; then verify=$(bash \"$installer\" kns status --instance-id " + statusId + ") || exit 1; printf 'KNS_STATUS=%s\\n' \"$verify\"; else verify=$(bash \"$installer\" kns status --instance-id " + statusId + ") || exit 1; printf 'KNS_STATUS=%s\\n' \"$verify\"; fi",
  ].join("; ");
}

function makeRemoteStatusCommand(instance) {
  const installer = quoteShell(INSTALLER_URL);
  const digest = quoteShell(INSTALLER_SHA256);
  const instanceId = quoteShell(instance.id);
  return [
    "set -u",
    "[ \"$(id -u)\" -eq 0 ] || { echo 'KNS requires a root Komari Agent.' >&2; exit 77; }",
    "command -v sha256sum >/dev/null 2>&1 || exit 127",
    "installer=$(mktemp) || exit 1; trap 'rm -f \"$installer\"' EXIT",
    "if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 180 " + installer + " -o \"$installer\"; elif command -v wget >/dev/null 2>&1; then wget -qO \"$installer\" " + installer + "; else exit 127; fi",
    "printf '%s  %s\\n' " + digest + " \"$installer\" | sha256sum -c - >/dev/null || exit 65",
    "status=$(bash \"$installer\" kns status --instance-id " + instanceId + ") || exit $?",
    "printf 'KNS_STATUS=%s\\n' \"$status\"",
  ].join("; ");
}
function quoteShell(value) { return "'" + String(value).replace(/'/g, "'\"'\"'") + "'"; }

function exitCode(value) {
  if (!value || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    for (const item of value) { const code = exitCode(item); if (code !== undefined) return code; }
    return undefined;
  }
  for (const key of ["exit_code", "exitCode", "code"]) if (Number.isInteger(value[key])) return value[key];
  for (const key of Object.keys(value)) { const code = exitCode(value[key]); if (code !== undefined) return code; }
  return undefined;
}

function collectStrings(value, out, seen) {
  if (typeof value === "string") { out.push(value); return; }
  if (!value || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) value.forEach((item) => collectStrings(item, out, seen));
  else Object.keys(value).forEach((key) => collectStrings(value[key], out, seen));
}

function taskText(value) { const out = []; collectStrings(value, out, new Set()); return out.join("\n"); }

function extractStatus(value) {
  const text = taskText(value);
  const match = text.match(/KNS_STATUS=(\{[^\r\n]*\})/);
  if (!match) return null;
  try { return JSON.parse(match[1]); } catch (_) { return null; }
}

function checkRemoteStatus(job, status) {
  if (!status || status.schema !== 1 || !status.runtime || status.runtime.engine !== "sing-box") return false;
  if (job.action === "uninstall") {
    const missing = Array.isArray(status.instances) && status.instances.find((item) => item.id === job.instanceId);
    return !!missing && missing.installed === false;
  }
  const instance = status.instance;
  if (!instance || instance.id !== job.instanceId || instance.machineUuid !== job.machineUuid) return false;
  if (job.action === "disable") return instance.installed === true && instance.enabled === false;
  return instance.installed === true && instance.enabled !== false;
}

function validateCallbackInstance(job, body) {
  if (!body || body.schema !== 1 || body.status !== "succeeded" || !body.runtime || body.runtime.engine !== "sing-box" || !Array.isArray(body.instances) || body.artifactVersion !== ONEBOX_ADAPTER_VERSION) fail("invalid_callback", "回调结构、适配器版本或状态不符合 KNS schema 1。", 400);
  if (body.jobId !== job.id || body.machineUuid !== job.machineUuid || body.runtime.id !== "onebox-main") fail("callback_mismatch", "回调与任务目标不匹配。", 400);
  if (job.action === "uninstall") {
    if (body.instances.length !== 0) fail("invalid_callback", "卸载回调必须返回空实例数组。", 400);
    return null;
  }
  if (body.instances.length !== 1) fail("invalid_callback", "当前任务必须恰好返回一个实例。", 400);
  const node = body.instances[0];
  if (!node || node.id !== job.instanceId || node.protocol !== job.protocol || !node.listen || Number(node.listen.port) !== job.listenPort || node.listen.transport !== job.listenTransport) fail("invalid_callback", "回调实例与待处理任务不匹配。", 400);
  const credential = node.credential;
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) fail("invalid_callback", "回调缺少协议凭据。", 400);
  const secretString = (value) => typeof value === "string" && value.length > 0 && value.length <= 4096;
  if (["vless", "vmess"].includes(node.protocol) && (credential.type !== "uuid" || !UUID_RE.test(String(credential.value || "")))) fail("invalid_callback", "回调 UUID 凭据无效。", 400);
  if (["trojan", "hysteria2", "anytls"].includes(node.protocol) && (credential.type !== "password" || !secretString(credential.value))) fail("invalid_callback", "回调密码凭据无效。", 400);
  if (node.protocol === "shadowsocks" && (credential.type !== "shadowsocks" || !secretString(credential.value) || !["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].includes(String(credential.method || "")))) fail("invalid_callback", "回调 Shadowsocks 凭据无效。", 400);
  if (node.protocol === "tuic" && (credential.type !== "uuid_password" || !UUID_RE.test(String(credential.uuid || "")) || !secretString(credential.password))) fail("invalid_callback", "回调 TUIC 凭据无效。", 400);
  if (node.protocol !== "shadowsocks") {
    const tls = node.tls || {};
    const expectedSecurity = node.protocol === "vless" ? "reality" : "tls";
    if (tls.security !== expectedSecurity || !validHostname(tls.sni)) fail("invalid_callback", "回调 TLS 安全参数或 SNI 无效。", 400);
    if (node.protocol === "vless" && (!secretString(tls.publicKey) || !secretString(tls.shortId))) fail("invalid_callback", "回调 Reality 公钥或 Short ID 缺失。", 400);
    if (tls.alpn != null && (!Array.isArray(tls.alpn) || tls.alpn.length > 8 || !tls.alpn.every((item) => typeof item === "string" && /^[A-Za-z0-9._/-]{1,32}$/.test(item)))) fail("invalid_callback", "回调 ALPN 列表无效。", 400);
  }
  if (!Array.isArray(node.resources) || !node.resources.length || !node.resources.every((resource) => resource && resource.owned === true && resource.shared === false)) fail("invalid_callback", "回调资源所有权声明无效。", 400);
  if (!ID_RE.test(node.id) || !PROTOCOLS[node.protocol]) fail("invalid_callback", "回调实例标识或协议无效。", 400);
  return node;
}

function findTask(job) {
  return server.call("admin:getSpecificTaskResult", { task_id: job.taskId, uuid: job.machineUuid });
}

function ensureInstance(state, job, callbackInstance) {
  const existing = state.instances.find((item) => item.id === job.instanceId);
  if (job.action === "uninstall") {
    if (existing) {
      existing.deletedAt = now();
      existing.enabled = false;
      existing.publish = false;
      existing.health = Object.assign({}, existing.health, { state: "unverified", reason: "uninstalled" });
      delete existing.credentialCiphertext;
    }
    const runtime = state.runtimes.find((item) => item.machineUuid === job.machineUuid && item.id === (job.runtimeId || "onebox-main"));
    if (runtime) {
      runtime.references = state.instances.filter((item) => item.machineUuid === job.machineUuid && item.runtimeId === runtime.id && !item.deletedAt).length;
      if (!runtime.references) runtime.state = "unreferenced_shared_service";
      runtime.updatedAt = now();
    }
    return;
  }
  if (["enable", "disable"].includes(job.action)) {
    if (!existing) fail("instance_missing", "启停操作的实例记录不存在。", 409);
    if (callbackInstance) {
      existing.tls = callbackInstance.tls || existing.tls;
      existing.credentialCiphertext = secrets.encryptSecret(JSON.stringify(callbackInstance.credential), masterKey);
    }
    existing.enabled = job.action === "enable";
    existing.updatedAt = now();
    if (job.action === "disable") existing.health = Object.assign({}, existing.health, { state: "unverified", reason: "disabled" });
    return;
  }
  const machine = state.machines.find((item) => item.uuid === job.machineUuid);
  if (!machine) fail("machine_missing", "目标探针在 Komari 列表中不存在。", 409);
  const endpoint = candidateAddress(machine, state, { listen: { port: callbackInstance.listen.port }, endpointOverride: job.endpointOverride, nat: job.nat });
  if (!endpoint) fail("endpoint_missing", "无法为实例解析可用公网 Endpoint。", 409);
  if (endpoint.source === "ddns") {
    const observation = machine.ddnsObservation || {};
    const addresses = Array.isArray(observation.addresses) ? observation.addresses : [];
    if (Number(observation.count) < 2 || !addresses.length) fail("endpoint_missing", "等待 DDNS 完成两次稳定的 A/AAAA 解析。", 409);
    addresses.forEach((address) => normalizeHost(address, !!state.settings.privateSite));
    const families = new Set(addresses.map((address) => require("net").isIP(address)));
    const mode = machine.policy && machine.policy.addressMode || "auto";
    if ((mode === "ipv4" && !families.has(4)) || (mode === "ipv6" && !families.has(6)) || (mode === "dual" && !(families.has(4) && families.has(6)))) {
      fail("endpoint_missing", "DDNS 解析结果未满足所选 IPv4/IPv6 地址模式。", 409);
    }
    endpoint.resolvedAddresses = addresses.slice();
    if (mode === "dual") endpoint.hosts = addresses.slice();
  }
  const credentialCiphertext = secrets.encryptSecret(JSON.stringify(callbackInstance.credential), masterKey);
  const record = Object.assign(existing || {}, {
    id: callbackInstance.id,
    machineUuid: job.machineUuid,
    name: job.name,
    tags: job.tags || [],
    protocol: callbackInstance.protocol,
    runtimeId: job.runtimeId || "onebox-main",
    runtimeEngine: "sing-box",
    listen: { port: callbackInstance.listen.port, transport: callbackInstance.listen.transport, address: job.listenAddress || "::" },
    options: job.options || {},
    tls: callbackInstance.tls || {},
    credentialCiphertext,
    resources: callbackInstance.resources,
    endpoint,
    endpointOverride: job.endpointOverride || null,
    nat: job.nat || null,
    enabled: true,
    publish: true,
    health: existing && existing.health || { state: callbackInstance.listen.transport === "udp" ? "unverified" : "unknown", level: "L0", consecutiveFailures: 0, consecutiveSuccesses: 0, lastCheckedAt: "", reason: "awaiting_probe" },
    createdAt: existing && existing.createdAt || now(),
    updatedAt: now(),
    artifactVersion: safeText(job.artifactVersion || "", 80),
  });
  if (existing) { Object.assign(existing, record); delete existing.deletedAt; }
  else state.instances.push(record);
  state.runtimes = state.runtimes.filter((runtime) => !(runtime.machineUuid === job.machineUuid && runtime.id === record.runtimeId));
  state.runtimes.push({ machineUuid: job.machineUuid, id: record.runtimeId, engine: "sing-box", state: "shared", updatedAt: now(), references: state.instances.filter((item) => item.machineUuid === job.machineUuid && !item.deletedAt).length });
}

async function pollPendingJobs() {
  if (pollBusy) return;
  pollBusy = true;
  try {
    const candidates = getState().jobs.filter((job) => job.taskId && !["succeeded", "failed", "timed_out", "cancelled", "needs_reconcile"].includes(job.state)).slice(0, 20);
    const results = [];
    for (const snapshot of candidates) {
      if (Date.now() - Date.parse(snapshot.createdAt) > 30 * 60 * 1000) { results.push({ id: snapshot.id, timeout: true }); continue; }
      try { results.push({ id: snapshot.id, result: await findTask(snapshot) }); }
      catch (error) { results.push({ id: snapshot.id, errorCode: error && error.code != null ? safeText(error.code, 32) : "rpc_error" }); }
    }
    const state = getState();
    let changed = false;
    for (const polled of results) {
      const job = state.jobs.find((item) => item.id === polled.id);
      if (!job || ["succeeded", "failed", "timed_out", "cancelled", "needs_reconcile"].includes(job.state)) continue;
      if (polled.timeout) {
        job.state = "timed_out"; job.updatedAt = now(); job.message = "任务超过 30 分钟仍未完成。"; closeJob(job); changed = true; continue;
      }
      if (polled.errorCode) {
        if (job.pollErrorCode !== polled.errorCode) { job.pollErrorCode = polled.errorCode; changed = true; }
        if (["-32040", "-32041"].includes(polled.errorCode)) { job.state = "needs_reconcile"; job.message = "Komari 拒绝读取任务结果；请检查管理员认证和远程控制权限。"; job.updatedAt = now(); closeJob(job); changed = true; }
        continue;
      }
      const result = polled.result;
      const code = exitCode(result);
      if (code === undefined) { if (job.state === "dispatched") { job.state = "running"; changed = true; } continue; }
      if (code !== 0) {
        job.state = "failed"; job.updatedAt = now(); job.message = "远程任务退出码 " + code + "。敏感输出未保存。"; closeJob(job); changed = true; continue;
      }
      const status = extractStatus(result);
        if (job.action === "instance.status") {
          const instance = state.instances.find((item) => item.id === job.instanceId && item.machineUuid === job.machineUuid);
          if (!status || !instance || !status.runtime || status.runtime.engine !== "sing-box") {
            job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "远端状态结果无法与登记实例匹配。"; changed = true; continue;
          }
          if (status.instance && status.instance.id === job.instanceId) {
            const resources = Array.isArray(status.instance.resources) ? status.instance.resources.slice(0, 50).map((resource) => ({
              type: safeText(resource.type || "unknown", 40), id: safeText(resource.id || "", 120), owned: resource.owned === true, shared: resource.shared === true,
              present: resource.present === true, referenceCount: Math.max(0, Number(resource.referenceCount) || 0), action: safeText(resource.action || "unknown", 40),
            })) : [];
            const preview = status.instance.uninstallPreview || {};
            instance.remoteStatus = { installed: status.instance.installed === true, enabled: status.instance.enabled === true, serviceState: status.instance.serviceState || "unknown", healthLevel: status.instance.healthLevel || "L0", checkedAt: now(), installState: status.instance.installState || "unknown", resources, uninstallPreview: { complete: preview.complete === true, serviceImpact: safeText(preview.serviceImpact || "unknown", 40) } };
            if (status.instance.installed === true) instance.enabled = status.instance.enabled !== false;
          } else {
            const absent = Array.isArray(status.instances) && status.instances.find((item) => item.id === job.instanceId && item.installed === false);
            if (!absent) { job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "OneBox 未返回该实例的可识别状态。"; changed = true; continue; }
            instance.remoteStatus = { installed: false, enabled: false, serviceState: "unknown", healthLevel: "L0", checkedAt: now(), installState: "not_installed" };
          }
          job.state = "succeeded"; job.updatedAt = now(); job.message = "已读取 OneBox 远端实例状态。"; closeJob(job); changed = true;
          audit(state, null, "instance.status.checked", { jobId: job.id, machineUuid: job.machineUuid, instanceId: job.instanceId });
          continue;
        }
        if (!checkRemoteStatus(job, status)) {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "远程命令已成功，但 OneBox status 未能确认目标实例。"; changed = true; continue;
        }
        if (!job.callback || job.callback.status !== "succeeded") {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "远程命令已成功，但未收到已验证的 OneBox 回调。"; changed = true; continue;
        }
        if (!(["uninstall", "disable", "enable"].includes(job.action)) && status.instance.protocol !== job.protocol) {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "远程实例协议与任务不匹配。"; changed = true; continue;
        }
        try { ensureInstance(state, job, resolveCallbackNode(job)); }
        catch (error) {
          job.updatedAt = now();
          job.pollErrorCode = error && error.code ? safeText(error.code, 32) : "verification_error";
          job.state = error && error.code === "endpoint_missing" ? "verifying" : "needs_reconcile";
          job.message = error && error.code === "endpoint_missing" ? "OneBox 已完成；等待可验证的公网 Endpoint。" : "远端状态已收到，但本地登记核对失败；需要管理员复核。";
          changed = true; continue;
        }
        job.state = "succeeded"; job.updatedAt = now(); job.message = job.action === "uninstall" ? "已验证实例已卸载。" : "回调和远程实例状态均已验证。"; closeJob(job); changed = true;
        audit(state, null, "job.succeeded", { jobId: job.id, action: job.action, machineUuid: job.machineUuid, instanceId: job.instanceId });
    }
    if (changed) save(state);
  } finally { pollBusy = false; }
}

function createJob(state, req, action, machine, spec, existingInstance) {
  const token = secrets.createToken();
  const tokenRecord = secrets.tokenRecord(token);
  const instance = existingInstance || {
    id: spec.id || randomId("kns"), machineUuid: machine.uuid, name: safeText(spec.name || machine.name + " " + spec.protocol, 80),
    tags: Array.isArray(spec.tags) ? spec.tags.map((tag) => safeText(tag, 32)).filter(Boolean) : [], protocol: spec.protocol,
    runtimeId: "onebox-main", listen: { port: spec.port, address: spec.listenAddress, transport: spec.transport }, options: spec.options,
  };
  const idempotencyKey = safeText(spec.idempotencyKey || randomId("idem"), 256);
  const job = {
    id: randomId("job"), action, state: "authorized", machineUuid: machine.uuid, machineName: machine.name,
    instanceId: instance.id, protocol: instance.protocol, listenPort: instance.listen.port, listenAddress: instance.listen.address,
    listenTransport: instance.listen.transport,
    listenTransport: instance.listen.transport,
    runtimeId: instance.runtimeId || "onebox-main", options: instance.options || {}, name: instance.name, tags: instance.tags || [],
    endpointOverride: spec.endpointOverride || instance.endpointOverride || null, nat: spec.nat || instance.nat || null,
    idempotencyKey, callbackTokenSalt: tokenRecord.salt, callbackTokenHash: tokenRecord.hash, _callbackToken: token,
    callback: null, taskId: "", createdAt: now(), updatedAt: now(), actor: safeText(((req.context || {}).principal || {}).username || "admin", 80),
    message: "任务已授权，正在发送到探针。",
  };
  job.requestHash = String(spec.requestHash || "");
  state.jobs.push(job);
  const command = makeRemoteCommand(state, job, instance);
  const params = { command, clients: [machine.uuid] };
  const twoFactor = checkTwoFactor(spec.twoFactorCode);
  if (twoFactor) params["2fa_code"] = twoFactor;
  delete job._callbackToken;
  return { job, instance, params };
}

async function dispatchJob(state, job, params) {
  try {
    const result = await server.call("admin:exec", params);
    job.taskId = String(result && (result.task_id || result.taskId) || "");
    if (!job.taskId) { job.state = "failed"; job.message = "Komari 未返回远程任务编号。"; }
    else { job.state = "dispatched"; job.message = "已发送到 Komari Agent，等待执行与回调验证。"; }
  } catch (error) {
    job.state = "failed";
    const code = error && error.code != null ? safeText(error.code, 32) : "rpc_error";
    job.rpcErrorCode = code;
    job.message = code === "-32040" ? "Komari 拒绝远程命令：需要管理员重新认证。" : code === "-32041" ? "Komari 拒绝远程命令：权限不足或远程控制未启用。" : "Komari admin:exec 调用失败（" + code + "）；远程输出未保存。";
  }
  job.updatedAt = now();
}

async function finishDispatch(job, params) {
  await dispatchJob(null, job, params);
  const latest = getState();
  const current = latest.jobs.find((item) => item.id === job.id);
  if (!current) fail("job_lost", "任务记录在远程提交期间消失，请检查状态备份。", 500);
  for (const field of ["taskId", "state", "updatedAt", "message", "rpcErrorCode"]) current[field] = job[field];
  save(latest);
  return current;
}

function machineByUuid(state, uuid) {
  const machine = state.machines.find((item) => item.uuid === uuid);
  if (!machine) fail("machine_not_found", "Komari 中不存在这台探针。", 404);
  return machine;
}

function requirePolicy(machine) {
  if (!machine.policy || machine.policy.deployAllowed !== true) fail("deployment_not_allowed", "此探针尚未加入部署允许列表。请先在机器策略中显式启用。", 403);
}

function installAction(body) { return ["install", "reconfigure", "reinstall", "uninstall", "enable", "disable"].includes(String(body.action || "")); }

async function handleAction(req, res) {
  checkOrigin(req);
  const body = readBody(req);
  const state = getState();
  const action = String(body.action || "");
  if (action === "machine.policy.update") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    const policy = body.policy || {};
    const next = Object.assign({}, machine.policy || {});
    if (typeof policy.deployAllowed === "boolean") next.deployAllowed = policy.deployAllowed;
    if (policy.addressMode != null) {
      if (!["auto", "ipv4", "ipv6", "dual"].includes(policy.addressMode)) fail("invalid_address_mode", "地址模式无效。", 400);
      next.addressMode = policy.addressMode;
    }
    if (policy.manualAddress != null) next.manualAddress = policy.manualAddress ? normalizeHost(policy.manualAddress, !!state.settings.privateSite) : "";
    if (policy.ddnsHostname != null) next.ddnsHostname = policy.ddnsHostname ? validHostname(policy.ddnsHostname) : "";
    if (policy.ddnsHostname && !next.ddnsHostname) fail("invalid_ddns", "DDNS 必须是有效域名。", 400);
    if (policy.tags != null) next.tags = Array.isArray(policy.tags) ? Array.from(new Set(policy.tags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [];
    machine.policy = next; machine.updatedAt = now();
    audit(state, req, "machine.policy.updated", { machineUuid: machine.uuid, deployAllowed: next.deployAllowed, addressMode: next.addressMode });
    save(state); return json(res, 200, { ok: true, machine: safeMachine(machine) });
  }
  if (action === "settings.update") {
    const base = String(body.publicBaseUrl || "").trim().replace(/\/$/, "");
    let parsed;
    try { parsed = new URL(base); } catch (_) { fail("invalid_public_url", "Komari 公网地址必须是 HTTPS URL。", 400); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) fail("invalid_public_url", "KNS 回调需要不含账号、查询和片段的 HTTPS 地址。", 400);
    state.settings.publicBaseUrl = parsed.origin + parsed.pathname.replace(/\/$/, "");
    state.settings.privateSite = body.privateSite === true;
    if (body.converterUrl != null) {
      let converter;
      try { converter = new URL(String(body.converterUrl)); } catch (_) { fail("invalid_converter_url", "SubConverter 地址无效。", 400); }
      if (!["http:", "https:"].includes(converter.protocol) || converter.username || converter.password || converter.hash || !converter.pathname.endsWith("/sub")) fail("invalid_converter_url", "SubConverter 地址必须是以 /sub 结尾的 HTTP(S) URL。", 400);
      state.settings.converterUrl = converter.toString();
    }
    if (body.converterTarget != null) {
      if (!["clash", "singbox"].includes(String(body.converterTarget))) fail("invalid_converter_target", "SubConverter target 只支持 clash 或 singbox。", 400);
      state.settings.converterTarget = String(body.converterTarget);
    }
    audit(state, req, "settings.updated", { privateSite: state.settings.privateSite });
    save(state); return json(res, 200, { ok: true, settings: publicState(state).settings });
  }
  if (action === "backup.export") {
    const envelope = encryptedBackupEnvelope(state, body.passphrase);
    audit(state, req, "backup.exported", { format: envelope.format, schemaVersion: envelope.schemaVersion });
    save(state);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Disposition", "attachment; filename=kns-encrypted-export.json");
    res.end(JSON.stringify(envelope));
    return;
  }
  if (action === "profile.create" || action === "profile.rotate" || action === "profile.token.create") {
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址。", 409);
    if (action === "profile.create") {
      const profileId = randomId("profile");
      const name = safeText(body.name || "订阅档案", 80);
      const defaults = { instanceIds: null, machineUuids: null, excludeMachineUuids: [], protocols: null, includeTags: [], formats: ["mihomo-full", "uri"], excludeUnhealthy: true, addressMode: "auto", sortBy: "name", expiresAt: "" };
      const filters = profileFilterFields(body, defaults);
      const token = secrets.createToken();
      const profile = { id: profileId, name, createdAt: now(), tokens: [], ...filters, legacy: false };
      const tokenRecord = createProfileToken(profile, token, profile.expiresAt || "");
      state.profiles.push(profile);
      audit(state, req, "profile.created", { profileId, formats: filters.formats });
      save(state);
      const sourceUrl = profileUrl(state, profile.id, token, "uri");
      return json(res, 201, { ok: true, profile: { id: profile.id, name: profile.name }, tokenId: tokenRecord.id, tokenUrl: sourceUrl, nativeUrl: profileUrl(state, profile.id, token, "mihomo-full"), converterUrl: buildConverterUrl(state, sourceUrl) });
    }

    const profileId = String(body.profileId || "");
    const profile = state.profiles.find((item) => item.id === profileId);
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    if (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now()) fail("profile_expired", "订阅档案已过期，请先更新档案有效期。", 409);
    if (action === "profile.token.create" && profile.revokedAt) fail("profile_revoked", "订阅档案已撤销，请先轮换令牌恢复。", 409);
    const tokens = profileTokenRecords(profile);
    if (tokens.length >= 50) fail("token_limit_reached", "每个档案最多保留 50 个令牌记录，请清理旧档案。", 409);
    const token = secrets.createToken();
    let tokenExpiresAt = body.expiresAt ? validateFutureDate(body.expiresAt) : (profile.expiresAt || "");
    if (profile.expiresAt && (!tokenExpiresAt || Date.parse(profile.expiresAt) < Date.parse(tokenExpiresAt))) tokenExpiresAt = profile.expiresAt;
    if (action === "profile.rotate") {
      const graceSeconds = body.graceSeconds == null ? 0 : Number(body.graceSeconds);
      if (!Number.isInteger(graceSeconds) || graceSeconds < 0 || graceSeconds > 604800) fail("invalid_token_grace", "令牌轮换宽限秒数必须在 0 至 604800 之间。", 400);
      const graceAt = Date.now() + graceSeconds * 1000;
      for (const prior of ensureProfileTokens(profile)) {
        if (prior.revokedAt || (prior.expiresAt && Date.parse(prior.expiresAt) <= Date.now())) continue;
        let expiresAt = graceAt;
        if (prior.expiresAt && Date.parse(prior.expiresAt) < expiresAt) expiresAt = Date.parse(prior.expiresAt);
        if (profile.expiresAt && Date.parse(profile.expiresAt) < expiresAt) expiresAt = Date.parse(profile.expiresAt);
        prior.expiresAt = new Date(expiresAt).toISOString();
        prior.graceUntil = prior.expiresAt;
      }
      profile.revokedAt = "";
      profile.rotatedAt = now();
    }
    const tokenRecord = createProfileToken(profile, token, tokenExpiresAt);
    const auditAction = action === "profile.rotate" ? "profile.rotated" : "profile.token.created";
    audit(state, req, auditAction, { profileId, tokenId: tokenRecord.id, graceSeconds: action === "profile.rotate" ? Number(body.graceSeconds || 0) : 0 });
    save(state);
    const sourceUrl = profileUrl(state, profile.id, token, "uri");
    return json(res, action === "profile.token.create" ? 201 : 200, { ok: true, profileId, tokenId: tokenRecord.id, tokenUrl: sourceUrl, nativeUrl: profileUrl(state, profile.id, token, "mihomo-full"), converterUrl: buildConverterUrl(state, sourceUrl) });
  }
  if (action === "profile.token.revoke") {
    const profile = state.profiles.find((item) => item.id === String(body.profileId || ""));
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    const tokens = ensureProfileTokens(profile);
    const token = tokens.find((item) => item.id === String(body.tokenId || ""));
    if (!token) fail("token_not_found", "订阅令牌不存在。", 404);
    if (!token.revokedAt) token.revokedAt = now();
    audit(state, req, "profile.token.revoked", { profileId: profile.id, tokenId: token.id });
    save(state);
    return json(res, 200, { ok: true });
  }
  if (action === "profile.revoke") {
    const profile = state.profiles.find((item) => item.id === String(body.profileId || ""));
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    profile.revokedAt = now();
    for (const token of ensureProfileTokens(profile)) if (!token.revokedAt) token.revokedAt = profile.revokedAt;
    audit(state, req, "profile.revoked", { profileId: profile.id }); save(state); return json(res, 200, { ok: true });
  }
  if (action === "profile.update") {
    const profile = state.profiles.find((item) => item.id === String(body.profileId || ""));
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    if (body.name != null) profile.name = safeText(body.name, 80);
    Object.assign(profile, profileFilterFields(body, profile));
    audit(state, req, "profile.updated", { profileId: profile.id, formats: profile.formats }); save(state); return json(res, 200, { ok: true });
  }
  if (action === "instance.publish.update") {
    const instance = state.instances.find((item) => item.id === String(body.instanceId || ""));
    if (!instance || instance.deletedAt) fail("instance_not_found", "实例不存在。", 404);
    if (typeof body.publish !== "boolean") fail("invalid_publish", "publish 必须是布尔值。", 400);
    instance.publish = body.publish; instance.updatedAt = now();
    audit(state, req, body.publish ? "instance.published" : "instance.hidden", { instanceId: instance.id }); save(state); return json(res, 200, { ok: true });
  }
  if (action === "instance.deduplicate") {
    const keep = state.instances.find((item) => item.id === String(body.keepInstanceId || "") && !item.deletedAt);
    if (!keep) fail("instance_not_found", "需要选择保留的实例。", 404);
    if (body.confirm !== true) fail("confirmation_required", "去重需要确认。", 400);
    const keepSecret = keep.credentialCiphertext ? secrets.decryptSecret(keep.credentialCiphertext, masterKey) : "";
    const duplicates = state.instances.filter((item) => item.id !== keep.id && item.machineUuid === keep.machineUuid && !item.deletedAt && item.protocol === keep.protocol && item.listen.port === keep.listen.port && item.listen.transport === keep.listen.transport && item.endpoint && keep.endpoint && item.endpoint.host === keep.endpoint.host && item.credentialCiphertext && keepSecret && secrets.decryptSecret(item.credentialCiphertext, masterKey) === keepSecret);
    duplicates.forEach((item) => { item.publish = false; item.updatedAt = now(); });
    audit(state, req, "instances.deduplicated", { keepInstanceId: keep.id, hiddenInstanceIds: duplicates.map((item) => item.id) });
    save(state); return json(res, 200, { ok: true, kept: keep.id, hidden: duplicates.map((item) => item.id) });
  }
  if (action === "instance.metadata.update") {
    const instance = state.instances.find((item) => item.id === String(body.instanceId || ""));
    if (!instance || instance.deletedAt) fail("instance_not_found", "实例不存在。", 404);
    const nextOverride = body.endpointHost != null ? makeEndpointOverride(body.endpointHost, body.endpointPort, !!state.settings.privateSite) : instance.endpointOverride;
    const nextNat = body.externalPort != null ? (body.externalPort ? { externalPort: validatePort(body.externalPort) } : null) : instance.nat;
    const machine = machineByUuid(state, instance.machineUuid);
    const nextEndpoint = candidateAddress(machine, state, Object.assign({}, instance, { endpointOverride: nextOverride, nat: nextNat })) || instance.endpoint;
    if (nextNat && natMappingConflicts(state, nextNat.externalPort, instance.listen.transport, nextEndpoint && nextEndpoint.hosts || [nextEndpoint && nextEndpoint.host], instance.id)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 传输组合已被另一个 KNS 实例占用。", 409);
    if (body.name != null) instance.name = safeText(body.name, 80);
    if (body.tags != null) instance.tags = Array.isArray(body.tags) ? Array.from(new Set(body.tags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [];
    if (body.endpointHost != null) instance.endpointOverride = nextOverride;
    if (body.externalPort != null) instance.nat = nextNat;
    if (instance.nat && nextEndpoint) {
      instance.nat.publicHost = nextEndpoint.host;
      instance.nat.publicHosts = nextEndpoint.hosts || [nextEndpoint.host];
    }
    instance.endpoint = nextEndpoint;
    instance.updatedAt = now(); audit(state, req, "instance.metadata.updated", { instanceId: instance.id }); save(state); return json(res, 200, { ok: true });
  }
  if (action === "backup.restore") {
    const restored = store.restoreBackup(String(body.name || ""));
    masterKey = secrets.getMasterKey(__storageDir__);
    audit(restored, req, "backup.restored", { name: safeText(body.name, 80) }); save(restored); return json(res, 200, { ok: true, revision: restored.revision });
  }
  if (action === "instance.status") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    const instance = state.instances.find((item) => item.id === String(body.instanceId || "") && item.machineUuid === machine.uuid && !item.deletedAt);
    if (!instance) fail("instance_not_found", "实例不存在或不属于此探针。", 404);
    const key = safeText(body.idempotencyKey || "", 256);
    if (!key) fail("idempotency_key_required", "状态核查需要 idempotencyKey。", 400);
    const prior = state.jobs.find((item) => item.action === action && item.machineUuid === machine.uuid && item.instanceId === instance.id && item.idempotencyKey === key);
    if (prior) return json(res, 200, { ok: true, reused: true, job: safeJob(prior) });
    const job = { id: randomId("job"), action, state: "authorized", machineUuid: machine.uuid, machineName: machine.name, instanceId: instance.id, protocol: instance.protocol, runtimeId: instance.runtimeId || "onebox-main", idempotencyKey: key, requestHash: crypto.createHash("sha256").update(machine.uuid + ":" + instance.id + ":status").digest("hex"), taskId: "", callback: null, createdAt: now(), updatedAt: now(), message: "正在提交只读状态核查。" };
    state.jobs.push(job); audit(state, req, "instance.status.requested", { jobId: job.id, instanceId: instance.id, machineUuid: machine.uuid }); save(state);
    const params = { command: makeRemoteStatusCommand(instance), clients: [machine.uuid] };
    const code = checkTwoFactor(body.twoFactorCode); if (code) params["2fa_code"] = code;
    const submitted = await finishDispatch(job, params); return json(res, 202, { ok: submitted.state !== "failed", job: safeJob(submitted) });
  }
  if (!installAction(body)) fail("unknown_action", "不支持的管理动作。", 400);
  if (typeof body.confirm !== "boolean" || body.confirm !== true) fail("confirmation_required", "此操作需要显式确认。", 400);
  const machineUuid = String(body.machineUuid || "").toLowerCase();
  const machine = machineByUuid(state, machineUuid);
  if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址，以接收 OneBox 回调。", 409);
  const spec = body;
  const actionName = String(body.action);
  if (["install", "reconfigure", "reinstall", "enable"].includes(actionName)) requirePolicy(machine);
  const suppliedIdempotencyKey = safeText(body.idempotencyKey || "", 256);
  if (!suppliedIdempotencyKey) fail("idempotency_key_required", "每个远程动作都必须提供 idempotencyKey。", 400);
  let instance = null;
  if (["install", "reconfigure", "reinstall"].includes(actionName)) {
    const validated = actionName === "reinstall" ? null : validateProtocolSettings(body);
    const proposedId = actionName === "install" ? (body.instanceId || randomId("kns")) : String(body.instanceId || "");
    if (!ID_RE.test(proposedId)) fail("invalid_instance_id", "实例 ID 格式无效。", 400);
    instance = state.instances.find((item) => item.id === proposedId && item.machineUuid === machineUuid);
    if (actionName === "install" && instance && !instance.deletedAt) fail("instance_exists", "该实例已经登记，请选择重配置、重装或新建实例。", 409);
    if (actionName !== "install" && (!instance || instance.deletedAt)) fail("instance_not_found", "重配置或重装需要选择已登记实例。", 404);
    const targetPort = actionName === "reinstall" ? instance.listen.port : validated.port;
    const targetTransport = actionName === "reinstall" ? instance.listen.transport : validated.transport;
    if (portConflicts(state, machineUuid, targetPort, targetTransport, proposedId, actionName === "reinstall" ? instance.listen.address : validated.listenAddress)) fail("port_conflict", "该机器上的监听地址、端口和传输类型与另一实例冲突。", 409);
    if (actionName === "install") {
      const nat = body.externalPort ? { externalPort: validatePort(body.externalPort) } : null;
      instance = { id: proposedId, machineUuid, runtimeId: "onebox-main", name: safeText(body.name || machine.name + " " + validated.protocol, 80), tags: Array.isArray(body.tags) ? body.tags.map((tag) => safeText(tag, 32)).filter(Boolean) : [], protocol: validated.protocol, listen: { port: validated.port, transport: validated.transport, address: validated.listenAddress }, options: validated.options, endpointOverride: makeEndpointOverride(body.endpointHost, body.endpointPort, !!state.settings.privateSite), nat };
      if (instance.nat) {
        const publicEndpoint = candidateAddress(machine, state, instance);
        if (!publicEndpoint) fail("nat_endpoint_missing", "配置 NAT 外部端口时，必须提供公网 Endpoint 地址或先同步机器地址。", 409);
        instance.nat.publicHost = publicEndpoint.host;
        instance.nat.publicHosts = publicEndpoint.hosts || [publicEndpoint.host];
        if (natMappingConflicts(state, instance.nat.externalPort, validated.transport, instance.nat.publicHosts, proposedId)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 传输组合已被另一个 KNS 实例占用。", 409);
      }
    } else if (actionName === "reconfigure") {
      instance = Object.assign({}, instance, { protocol: validated.protocol, listen: { port: validated.port, transport: validated.transport, address: validated.listenAddress }, options: validated.options });
    }
    spec.id = proposedId; spec.port = actionName === "reinstall" ? instance.listen.port : validated.port; spec.listenAddress = actionName === "reinstall" ? instance.listen.address : validated.listenAddress; spec.transport = actionName === "reinstall" ? instance.listen.transport : validated.transport; spec.protocol = instance.protocol; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  } else {
    instance = state.instances.find((item) => item.id === String(body.instanceId || "") && item.machineUuid === machineUuid && !item.deletedAt);
    if (!instance) fail("instance_not_found", "目标实例不存在或不属于该探针。", 404);
    spec.id = instance.id; spec.protocol = instance.protocol; spec.port = instance.listen.port; spec.listenAddress = instance.listen.address; spec.transport = instance.listen.transport; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  }
  if (["enable", "disable"].includes(actionName)) {
    // These operations are translated into the OneBox adapter contract below.
    spec.protocol = instance.protocol; spec.id = instance.id; spec.port = instance.listen.port; spec.listenAddress = instance.listen.address; spec.transport = instance.listen.transport; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  }
  const requestHash = crypto.createHash("sha256").update(JSON.stringify({
    action: actionName, machineUuid, instanceId: body.instanceId || "", protocol: spec.protocol || "", port: spec.port || 0,
    transport: spec.transport || "", options: spec.options || {}, listenAddress: spec.listenAddress || "", endpointHost: body.endpointHost || "", endpointPort: body.endpointPort || 0, externalPort: body.externalPort || 0,
  })).digest("hex");
  const prior = state.jobs.find((item) => item.machineUuid === machineUuid && item.action === actionName && item.idempotencyKey === suppliedIdempotencyKey);
  if (prior) {
    if (prior.requestHash !== requestHash) fail("idempotency_conflict", "相同 idempotencyKey 已用于不同的远程动作。", 409);
    return json(res, 200, { ok: prior.state !== "failed", reused: true, job: safeJob(prior) });
  }
  spec.idempotencyKey = suppliedIdempotencyKey;
  spec.requestHash = requestHash;
  const conflictingJob = state.jobs.find((item) => item.machineUuid === machineUuid && item.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
  if (conflictingJob) fail("runtime_busy", "该机器的共享 OneBox Runtime 仍有未完成配置任务。", 409);
  const { job, instance: jobInstance, params } = createJob(state, req, actionName, machine, spec, instance);
  audit(state, req, "job.authorized", { jobId: job.id, action: actionName, machineUuid, instanceId: job.instanceId });
  // Persist the authorization record before dispatch so callbacks cannot precede it.
  save(state);
  const submitted = await finishDispatch(job, params);
  json(res, 202, { ok: submitted.state !== "failed", job: safeJob(submitted) });
}

function validateFutureDate(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) fail("invalid_expiry", "订阅过期时间必须是未来时间。", 400);
  return date.toISOString();
}

function profileUrl(state, profileId, token, format) {
  return state.settings.publicBaseUrl.replace(/\/$/, "") + API + "/sub?profile=" + encodeURIComponent(profileId) + "&format=" + encodeURIComponent(format || "mihomo-full") + "&token=" + encodeURIComponent(token);
}

function buildConverterUrl(state, sourceUrl) {
  try {
    const converter = new URL(state.settings.converterUrl || "http://23.146.156.234:25500/sub");
    converter.searchParams.set("target", state.settings.converterTarget || "clash");
    converter.searchParams.set("url", sourceUrl);
    return converter.toString();
  } catch (_) { return ""; }
}

function profileValid(profile, token) {
  if (!profile || profile.revokedAt || (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now())) return null;
  for (const record of profileTokenRecords(profile)) {
    if (!record || record.revokedAt || (record.expiresAt && Date.parse(record.expiresAt) <= Date.now())) continue;
    if (secrets.verifyToken(token, record)) return record;
  }
  return null;
}

function serveSubscription(req, res, legacy) {
  const state = getState();
  const query = req.query || {};
  const profileId = legacy ? "legacy-default" : String(query.profile || "");
  const profile = state.profiles.find((item) => item.id === profileId);
  const token = String(query.token || "");
  if (!profile) { res.statusCode = 404; res.setHeader("Cache-Control", "no-store"); res.end("Not found\n"); return; }
  if (profile.revokedAt || (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now())) { res.statusCode = 403; res.setHeader("Cache-Control", "no-store"); res.end("Subscription expired or revoked\n"); return; }
  const tokenRecord = profileValid(profile, token);
  if (!tokenRecord) { res.statusCode = 404; res.setHeader("Cache-Control", "no-store"); res.end("Not found\n"); return; }
  recordTokenUsage(profile.id, tokenRecord.id || "legacy-token");
  const format = legacy ? "uri" : String(query.format || "mihomo-full");
  if (!FORMATS.has(format) || (Array.isArray(profile.formats) && !profile.formats.includes(format))) { res.statusCode = 400; res.setHeader("Cache-Control", "no-store"); res.end("Unsupported subscription format\n"); return; }
  let snapshot;
  try { snapshot = readSubscriptionSnapshot(profile.id, format); }
  catch (_) { snapshot = null; }
  if (!snapshot || snapshot.sourceHash !== subscriptionSourceHash(state, profile, format)) {
    scheduleSubscriptionRefresh();
    res.statusCode = 503;
    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("Retry-After", "2");
    res.end("Subscription snapshot is being prepared\n");
    return;
  }
  const etag = '"' + snapshot.contentHash + '"';
  res.setHeader("Content-Type", snapshot.contentType);
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("ETag", etag);
  res.setHeader("X-KNS-Snapshot-Generated-At", snapshot.generatedAt);
  res.setHeader("X-KNS-Snapshot-Success", String(snapshot.successCount));
  res.setHeader("X-KNS-Snapshot-Skipped", String(snapshot.skippedCount));
  res.setHeader("Vary", "Authorization, Cookie");
  if (String((req.headers || {})["if-none-match"] || "") === etag) { res.statusCode = 304; res.end(); return; }
  res.statusCode = 200;
  res.end(snapshot.body);
}

async function handleReport(req, res) {
  const auth = String((req.headers || {}).authorization || "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  let body;
  try { body = readBody(req); } catch (_) { res.statusCode = 400; res.end("Invalid report\n"); return; }
  const state = getState();
  const job = state.jobs.find((item) => item.id === body.jobId);
  if (!job || job.machineUuid !== body.machineUuid) { res.statusCode = 404; res.end("Unknown job\n"); return; }
  const bodyDigest = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
  if (job.callback && job.callback.payloadHash === bodyDigest) { res.statusCode = 204; res.end(); return; }
  if (!token) { res.statusCode = 401; res.end("Unauthorized\n"); return; }
  const validToken = secrets.verifyToken(token, { salt: job.callbackTokenSalt, hash: job.callbackTokenHash });
  if (!validToken) { res.statusCode = 401; res.end("Unauthorized\n"); return; }
  if (job.callback || Date.now() - Date.parse(job.createdAt) > 15 * 60 * 1000) { res.statusCode = 409; res.end("Callback token consumed or expired\n"); return; }
  try {
    const node = validateCallbackInstance(job, body);
    job.artifactVersion = body.artifactVersion;
    job.callback = { status: body.status, receivedAt: now(), payloadHash: bodyDigest, instance: node ? Object.assign({}, node, { credentialCiphertext: secrets.encryptSecret(JSON.stringify(node.credential), masterKey) }) : null };
    if (job.callback.instance) delete job.callback.instance.credential;
    delete job.callbackTokenHash;
    delete job.callbackTokenSalt;
    job.state = "verifying"; job.updatedAt = now(); job.message = "回调已验签，正在核对 Agent 退出码与远程实例状态。";
    save(state);
    res.statusCode = 204; res.end();
  } catch (error) {
    res.statusCode = error.status || 400; res.end("Invalid callback\n");
  }
}

function safeNodeFromCallback(job, state) {
  const callback = job.callback && job.callback.instance;
  if (!callback) return null;
  const node = { ...callback, credential: JSON.parse(secrets.decryptSecret(callback.credentialCiphertext, masterKey)) };
  delete node.credentialCiphertext;
  return node;
}

function resolveCallbackNode(job, state) {
  const node = job.callback && job.callback.instance;
  if (!node) return null;
  const result = Object.assign({}, node);
  result.credential = JSON.parse(secrets.decryptSecret(node.credentialCiphertext, masterKey));
  return result;
}

function closeJob(job) {
  if (job.callback && job.callback.instance) delete job.callback.instance.credentialCiphertext;
  delete job.callbackTokenHash; delete job.callbackTokenSalt; delete job._callbackToken;
}

async function resolveDoh(host) {
  const hostname = validHostname(host);
  if (!hostname) return [];
  const result = [];
  for (const type of ["A", "AAAA"]) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      let response;
      try { response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(hostname) + "&type=" + type, { headers: { accept: "application/dns-json" }, signal: controller.signal }); }
      finally { clearTimeout(timer); }
      if (!response.ok) continue;
      const data = await response.json();
      for (const answer of Array.isArray(data.Answer) ? data.Answer : []) if ((type === "A" && answer.type === 1) || (type === "AAAA" && answer.type === 28)) result.push(String(answer.data || ""));
    } catch (_) {}
  }
  return Array.from(new Set(result));
}

function tcpProbe(host, port, tlsServername, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let socket;
    const finish = (ok) => { if (done) return; done = true; try { socket && socket.destroy(); } catch (_) {} resolve(ok); };
    try {
      const useTls = !!tlsServername;
      const mod = require(useTls ? "tls" : "net");
      socket = useTls ? mod.connect({ host, port, servername: tlsServername }) : mod.createConnection({ host, port });
      socket.setTimeout(timeoutMs || 3000);
      socket.once(useTls ? "secureConnect" : "connect", () => finish(true));
      socket.once("timeout", () => finish(false));
      socket.once("error", () => finish(false));
    } catch (_) { finish(false); }
  });
}

async function endpointReachable(host, port, tlsServername) {
  if (tlsServername && await tcpProbe(host, port, tlsServername, 3000)) return { ok: true, level: "L2-TLS", reason: "tls_verified" };
  if (await tcpProbe(host, port, "", 3000)) return { ok: true, level: "L1-TCP", reason: tlsServername ? "tcp_reachable_tls_unverified" : "reachable" };
  return { ok: false, level: tlsServername ? "L2-TLS" : "L1-TCP", reason: "connection_failed" };
}

async function refreshHealth() {
  if (healthBusy) return;
  healthBusy = true;
  try {
    const candidates = getState().instances.filter((instance) => instance.enabled && !instance.deletedAt).map((instance) => deepClone(instance));
    const results = [];
    for (let i = 0; i < candidates.length; i += 5) {
      const group = candidates.slice(i, i + 5);
      results.push(...await Promise.all(group.map(async (instance) => {
        const listen = instance.listen || {};
        if (listen.transport === "udp") {
          return { id: instance.id, endpoint: instance.endpoint, udp: true };
        }
        const endpoint = instance.endpoint || {};
        const sni = instance.tls && (instance.tls.sni || instance.tls.server_name) || "";
        const standardTls = instance.tls && instance.tls.security === "tls";
        const check = endpoint.host && endpoint.port ? await endpointReachable(endpoint.host, endpoint.port, standardTls ? sni || endpoint.host : "") : { ok: false, level: "L1-TCP", reason: "endpoint_missing" };
        return { id: instance.id, endpoint: instance.endpoint, check };
      })));
    }
    const state = getState();
    let changed = false;
    for (const result of results) {
      const instance = state.instances.find((item) => item.id === result.id && !item.deletedAt && item.enabled);
      if (!instance) continue;
      if (JSON.stringify(instance.endpoint || {}) !== JSON.stringify(result.endpoint || {})) continue;
      if (result.udp) {
        instance.health = Object.assign({}, instance.health, { state: "unverified", level: "L1-UDP", reason: "agent_listener_only", lastCheckedAt: now() });
        changed = true; continue;
      }
      const check = result.check;
      const health = Object.assign({ consecutiveFailures: 0, consecutiveSuccesses: 0 }, instance.health || {});
      if (check.ok) {
          health.consecutiveSuccesses += 1; health.consecutiveFailures = 0;
          if (health.consecutiveSuccesses >= 2) health.state = "healthy"; else if (health.state !== "healthy") health.state = "suspect";
          health.level = check.level; health.reason = check.reason;
      } else {
          health.consecutiveFailures += 1; health.consecutiveSuccesses = 0;
          if (health.consecutiveFailures >= 3) health.state = "unhealthy"; else health.state = "suspect";
          health.level = check.level; health.reason = check.reason;
      }
      health.lastCheckedAt = now(); instance.health = health; instance.updatedAt = now(); changed = true;
    }
    if (changed) save(state);
  } finally { healthBusy = false; }
}

async function refreshEndpoints() {
  if (endpointBusy) return;
  endpointBusy = true;
  try {
    const machineSnapshot = getState().machines.filter((machine) => machine.policy && machine.policy.ddnsHostname).map((machine) => ({ uuid: machine.uuid, hostname: machine.policy.ddnsHostname }));
    const dnsResults = [];
    for (let offset = 0; offset < machineSnapshot.length; offset += 5) {
      dnsResults.push(...await Promise.all(machineSnapshot.slice(offset, offset + 5).map(async (machine) => ({ ...machine, addresses: await resolveDoh(machine.hostname) }))));
    }
    let state = getState();
    let changed = false;
    const resolvedByMachine = new Map();
    for (const result of dnsResults) {
      const machine = state.machines.find((item) => item.uuid === result.uuid);
      if (!machine || !machine.policy || machine.policy.ddnsHostname !== result.hostname) continue;
      const current = machine.ddnsObservation || { addresses: [], count: 0 };
      const previous = (current.addresses || []).slice().sort();
      const nextAddresses = result.addresses.slice().sort();
      const same = JSON.stringify(nextAddresses) === JSON.stringify(previous);
      machine.ddnsObservation = { addresses: result.addresses, count: same ? current.count + 1 : 1, observedAt: now() };
      changed = true;
      if (result.addresses.length && machine.ddnsObservation.count >= 2) resolvedByMachine.set(machine.uuid, result.addresses);
    }
    if (changed) save(state);

    const candidates = [];
    for (const machine of state.machines) {
      for (const instance of state.instances.filter((item) => item.machineUuid === machine.uuid && item.enabled && !item.deletedAt)) {
        if (instance.endpointOverride && instance.endpointOverride.host) continue;
        let endpoint;
        try { endpoint = candidateAddress(machine, state, instance); } catch (_) { continue; }
        if (!endpoint) continue;
        if (endpoint.source === "ddns") {
          const resolved = resolvedByMachine.get(machine.uuid) || [];
          if (!resolved.length) continue;
          try { resolved.forEach((address) => normalizeHost(address, !!state.settings.privateSite)); } catch (_) { continue; }
          endpoint.resolvedAddresses = resolved;
          if (machine.policy.addressMode === "dual") endpoint.hosts = resolved.slice();
        }
        const current = instance.endpoint || {};
        const sameHost = current.host === endpoint.host && JSON.stringify(current.hosts || [current.host]) === JSON.stringify(endpoint.hosts || [endpoint.host]);
        const sameResolved = JSON.stringify((current.resolvedAddresses || []).slice().sort()) === JSON.stringify((endpoint.resolvedAddresses || []).slice().sort());
        if (!sameHost || !sameResolved) candidates.push({ id: instance.id, machineUuid: machine.uuid, endpoint, fingerprint: endpointConfigFingerprint(machine, instance, endpoint), listen: instance.listen, tls: instance.tls });
      }
    }
    const verified = [];
    for (let offset = 0; offset < candidates.length; offset += 5) {
      verified.push(...await Promise.all(candidates.slice(offset, offset + 5).map(async (candidate) => {
        const isUdp = candidate.listen && candidate.listen.transport === "udp";
        if (isUdp) return { ...candidate, reachable: true };
        for (const host of candidate.endpoint.hosts || [candidate.endpoint.host]) {
          const sni = candidate.tls && (candidate.tls.sni || candidate.tls.server_name) || "";
          const check = await endpointReachable(host, candidate.endpoint.port, candidate.tls && candidate.tls.security === "tls" ? sni || host : "");
          if (!check.ok) return { ...candidate, reachable: false };
        }
        return { ...candidate, reachable: true };
      })));
    }
    state = getState();
    changed = false;
    for (const result of verified) {
      if (!result.reachable) continue;
      const machine = state.machines.find((item) => item.uuid === result.machineUuid);
      const instance = state.instances.find((item) => item.id === result.id && item.machineUuid === result.machineUuid && !item.deletedAt && item.enabled);
      if (!machine || !instance) continue;
      let currentCandidate;
      try { currentCandidate = candidateAddress(machine, state, instance); } catch (_) { continue; }
      if (!currentCandidate || currentCandidate.host !== result.endpoint.host) continue;
      if (result.endpoint.source === "ddns") {
        const observation = machine.ddnsObservation;
        const addresses = observation && Array.isArray(observation.addresses) ? observation.addresses : [];
        if (!observation || observation.count < 2 || JSON.stringify(addresses.slice().sort()) !== JSON.stringify((result.endpoint.resolvedAddresses || []).slice().sort())) continue;
        currentCandidate.resolvedAddresses = addresses.slice();
        if (machine.policy && machine.policy.addressMode === "dual") currentCandidate.hosts = addresses.slice();
      }
      if (endpointConfigFingerprint(machine, instance, currentCandidate) !== result.fingerprint) continue;
      instance.endpoint = result.endpoint;
      if (instance.listen && instance.listen.transport === "udp") instance.health = Object.assign({}, instance.health, { state: "unverified", level: "L1-UDP", reason: "endpoint_updated_agent_listener_only" });
      instance.updatedAt = now(); changed = true;
    }
    if (changed) save(state);
  } finally { endpointBusy = false; }
}

function registerAdmin(method, suffix, handler) {
  server.route(method, API + suffix, async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try { await handler(req, res); }
    catch (error) { json(res, error.status || 400, { error: { code: error.code || "request_failed", message: safeText(error.message || error, 300) } }); }
  });
}

function registerRoutes() {
  registerAdmin("GET", "/admin/state", (_req, res) => json(res, 200, publicState(getState())));
  registerAdmin("POST", "/admin/action", handleAction);
  registerAdmin("GET", "/admin/logs", (req, res) => {
    const state = getState();
    const limit = Math.max(1, Math.min(500, Number((req.query || {}).limit) || 100));
    json(res, 200, { audit: state.audit.slice(-limit).reverse(), jobs: state.jobs.slice(-limit).reverse().map(safeJob) });
  });
  registerAdmin("GET", "/admin/export", (_req, res) => json(res, 405, { error: { code: "encrypted_export_required", message: "请在管理页输入独立口令，创建加密备份。" } }));
  registerAdmin("POST", "/admin/import", (req, res) => {
    checkOrigin(req);
    const body = readBody(req, 16 * 1024 * 1024);
    const imported = decryptBackupEnvelope(body.envelope, body.passphrase);
    const configured = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
    if (configured && (!/^[a-f0-9]{64}$/i.test(configured) || !crypto.timingSafeEqual(Buffer.from(configured, "hex"), imported.key))) fail("master_key_conflict", "导入备份的密钥与当前 KNS_MASTER_KEY 不匹配；请先协调宿主密钥配置。", 409);
    const restored = store.importBackup(imported.state, imported.key);
    masterKey = imported.key;
    pendingTokenUsage.clear();
    store.pruneSubscriptionSnapshots([]);
    audit(restored, req, "backup.imported", { format: "KNS-ENCRYPTED-EXPORT", schemaVersion: 1 });
    save(restored);
    json(res, 200, { ok: true, revision: restored.revision });
  });
  server.route("POST", API + "/report", handleReport);
  server.route("GET", API + "/sub", (req, res) => serveSubscription(req, res, false));
  server.route("GET", LEGACY_API + "/subscribe", (req, res) => serveSubscription(req, res, true));
  // Keep the legacy state endpoint read-only during upgrades; all writes use /api/kns/admin/action.
  server.route("GET", LEGACY_API + "/state", (req, res) => {
    if (!requireAdmin(req, res)) return;
    json(res, 200, publicState(getState()));
  });
}

async function cronTick() {
  try { await pollPendingJobs(); } catch (error) { console.error("[KNS] task polling failed:", safeText(error.message || error, 200)); }
}

function load() {
  subscriptionRefreshStopped = false;
  getState();
  registerRoutes();
  server.cron("@every 15s", () => { cronTick(); });
  server.cron("@every 1m", () => { syncMachines().then(refreshEndpoints).catch((error) => console.error("[KNS] machine sync failed:", safeText(error.message || error, 200))); });
  server.cron("@every 1m", () => { try { flushTokenUsage(); } catch (error) { console.error("[KNS] token usage save failed:", safeText(error.message || error, 200)); } });
  server.cron("@every 5m", () => { refreshHealth().catch((error) => console.error("[KNS] health check failed:", safeText(error.message || error, 200))); });
  server.cron("@every 5m", () => { scheduleSubscriptionRefresh(); });
  server.cron("0 3 * * *", () => { try { const state = getState(); store.write(state); } catch (_) {} });
  scheduleSubscriptionRefresh();
  try { syncMachines(); } catch (_) {}
}

function unload() {
  try { flushTokenUsage(); } catch (_) {}
  pollBusy = false; syncBusy = false; healthBusy = false;
  subscriptionRefreshStopped = true;
  subscriptionRefreshPending = false;
  if (subscriptionRefreshTimer) clearTimeout(subscriptionRefreshTimer);
  subscriptionRefreshTimer = null;
}

module.exports = { load, unload };
