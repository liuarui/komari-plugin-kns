"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const server = require("server");
const { createStore, initialState, validateState } = require("./store");
const secrets = require("./crypto");
const subscriptions = require("./subscription");
const { URL: URLConstructor } = require("./url");
const PLUGIN_VERSION = require("../komari-plugin.json").version;

const API = "/api/kns";
const LEGACY_API = "/api/onebox-bridge";
const SOURCE_URL = "https://github.com/liuarui/komari-plugin-kns/tree/v" + PLUGIN_VERSION;
const INSTALLER_URL = "https://raw.githubusercontent.com/liuarui/onebox/66c18c352dc591e58075b6c10468ff7bc3bba233/install.sh";
const INSTALLER_SHA256 = "9e83c464455d81162170c4e2d33a6b5d8c7e278c959959d86ad431c7ec55ec51";
const ONEBOX_SCRIPT_VERSION = "1.0.1";
const ONEBOX_ADAPTER_VERSION = "1.8.0";
const SUBSCRIPTION_RULES_VERSION = "kns-subscription-v5";
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
const FORMATS = new Set(["uri", "mihomo-full", "mihomo-provider", "singbox-full", "singbox-outbounds", "loon", "surge", "surfboard", "quanx", "quan", "shadowrocket", "stash", "mellow", "v2rayn", "v2rayng", "ss", "sssub", "ssd", "trojan", "vless", "hysteria2"]);
const CONVERTER_TARGETS = new Set(["clash", "clashr", "surge", "quan", "quanx", "loon", "surfboard", "stash", "mellow", "singbox", "ss", "ssd", "ssr", "sssub", "v2ray", "v2rayn", "v2rayng", "shadowrocket", "trojan", "vless", "hysteria2", "mixed"]);
const CONVERTER_RULE_PRESETS = Object.freeze({
  "acl4ssr-mini": "config/ACL4SSR_Online_Mini.ini",
  "acl4ssr-full": "config/ACL4SSR_Online_Full.ini",
});
const store = createStore(__storageDir__);
let masterKey = null;
function currentMasterKey() {
  try {
    const configured = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
    if (configured) {
      if (!masterKey) masterKey = secrets.getMasterKey(__storageDir__);
      return masterKey;
    }
    const keyPath = path.join(__storageDir__, "kns", "master.key");
    if (fs.existsSync(keyPath)) {
      const key = fs.readFileSync(keyPath);
      if (key.length === 32) { masterKey = key; return key; }
    }
  } catch (_) {}
  if (!masterKey) masterKey = secrets.getMasterKey(__storageDir__);
  return masterKey;
}

let pollBusy = false;
let syncBusy = false;
let healthBusy = false;
let endpointBusy = false;
let autoProvisionBusy = false;
let maintenanceLock = false;
let pluginUpdateLockToken = "";
let pluginUpdateLockTimer = null;
let lastLiveSync = 0;
let subscriptionRefreshBusy = false;
let subscriptionRefreshPending = false;
let subscriptionRefreshTimer = null;
let subscriptionRefreshStopped = false;
const pendingTokenUsage = new Map();

function now() { return new Date().toISOString(); }
function randomId(prefix) { return prefix + "-" + Date.now().toString(36) + "-" + crypto.randomBytes(5).toString("hex"); }
function deepClone(value) { return JSON.parse(JSON.stringify(value)); }
function masterKeyFingerprint(key) { return crypto.createHash("sha256").update(key).digest("hex").slice(0, 16); }
function fail(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status || 400;
  throw error;
}

function parseSemver(value) {
  const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(String(value || "").trim());
  if (!match) throw new Error("invalid_semver");
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] > b[index]) return 1;
    if (a[index] < b[index]) return -1;
  }
  return 0;
}

function assertExpectedRevision(actual, body) {
  if (body.expectedRevision == null) return;
  const expected = Number(body.expectedRevision);
  if (!Number.isSafeInteger(expected) || expected < 0) fail("invalid_revision", "expectedRevision 必须是非负整数。", 400);
  if (expected !== Number(actual)) {
    const error = new Error("KNS 数据已被其他操作更新。草稿已保留，请查看最新数据后再保存。");
    error.code = "state_revision_conflict"; error.status = 409;
    error.expectedRevision = expected; error.currentRevision = Number(actual);
    throw error;
  }
}

// Drafts protect only the fields their editor can overwrite. Background job,
// probe and token-usage updates must not invalidate an unrelated form.
function editVersion(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function profileEditVersion(profile) {
  if (!profile) return "";
  return editVersion([profile.id, profile.name, profile.formats, profile.instanceIds || null, profile.machineUuids || null,
    profile.excludeMachineUuids || [], profile.protocols || null, profile.includeTags || [], profile.excludeUnhealthy !== false,
    profile.addressMode || "auto", profile.sortBy || "name", profile.expiresAt || "", profile.revokedAt || ""]);
}
function machinePolicyVersion(machine) {
  return machine ? editVersion([machine.uuid, machine.policy || {}, machine.removedFromKomariAt || ""]) : "";
}
function settingsEditVersion(settings, action) {
  if (action === "settings.update") return editVersion([settings.publicBaseUrl || "", settings.converterUrl || "", settings.converterTarget || "", settings.privateSite === true]);
  const node = settings.defaultNode || {};
  return editVersion([node.protocol || "vless", node.listenPort || 443, node.listenAddress || "::", settings.autoProvisionNewProbes === true]);
}
function actionEditVersion(state, body) {
  if (body.action === "profile.update") return profileEditVersion(state.profiles.find((item) => item.id === String(body.profileId || "")));
  if (body.action === "machine.policy.update") return machinePolicyVersion(state.machines.find((item) => item.uuid === String(body.machineUuid || "").toLowerCase()));
  if (["settings.update", "settings.defaults.update"].includes(body.action)) return settingsEditVersion(state.settings, body.action);
  return "";
}

function assertNoActiveJobs(state, operation) {
  const active = state.jobs.filter((job) => ["authorized", "dispatched", "running", "verifying"].includes(job.state));
  if (active.length) fail("active_jobs_block_maintenance", operation + "已停止：还有 " + active.length + " 个远程任务未完成。请先核对任务结果。", 409);
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
  const payload = JSON.stringify({ format: "KNS-ENCRYPTED-EXPORT", schemaVersion: 1, createdAt: now(), masterKey: currentMasterKey().toString("hex"), state: deepClone(state) });
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
    if (String(headers.authorization || "").startsWith("Bearer ")) return;
    fail("csrf_origin", "管理写入请求必须带同源 Origin 或 Bearer API 身份。", 403);
  }
  let parsedOrigin;
  try { parsedOrigin = new URLConstructor(origin); } catch (_) { fail("csrf_origin", "请求来源无效。", 403); }
  if (!["https:", "http:"].includes(parsedOrigin.protocol) || parsedOrigin.username || parsedOrigin.password || parsedOrigin.origin === "null") fail("csrf_origin", "请求来源无效。", 403);
  const originHost = String(parsedOrigin.host || "").toLowerCase();
  const requestHost = String(headers.host || "").toLowerCase();

  // Komari may receive requests through a reverse proxy whose upstream Host is
  // different from the browser-visible authority. Trust only the administrator
  // configured public URL; never accept arbitrary X-Forwarded-Host values.
  let configuredOrigin = "";
  try {
    const publicBaseUrl = String((getState().settings || {}).publicBaseUrl || "");
    if (publicBaseUrl) configuredOrigin = new URLConstructor(publicBaseUrl).origin.toLowerCase();
  } catch (_) {}
  if (configuredOrigin && parsedOrigin.origin.toLowerCase() === configuredOrigin) return;
  // Origin includes scheme as well as host. The Host fallback is for a
  // same-host HTTPS request; it must not treat HTTP and HTTPS as same-origin.
  if (parsedOrigin.protocol === "https:" && requestHost && originHost === requestHost) return;
  // Browsers set Fetch Metadata headers themselves, so a same-origin page can
  // remain usable when a trusted reverse proxy rewrites the upstream Host.
  // Cross-origin pages cannot make the browser send this value.
  if (parsedOrigin.protocol === "https:" && String(headers["sec-fetch-site"] || "").toLowerCase() === "same-origin") return;
  fail("csrf_origin", "跨站管理请求已拒绝。请确认浏览器访问域名与 KNS 公网地址设置一致。", 403);
}

function readBody(req, maxBytes) {
  const type = String((req.headers || {})["content-type"] || "").toLowerCase();
  const body = String(req.body || "");
  const limit = Number(maxBytes) || 1024 * 1024;
  if (Buffer.byteLength(body, "utf8") > limit) fail("body_too_large", "请求正文超过允许大小。", 413);
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

function constrainLegacyFormats(state) {
  if (!state || !Array.isArray(state.profiles)) return { state, changed: false };
  let changed = false;
  for (const profile of state.profiles) {
    if (!profile || profile.legacy !== true) continue;
    const formats = Array.isArray(profile.formats) ? profile.formats.filter((format) => format === "uri") : [];
    if (formats.length === 1 && formats[0] === "uri" && Array.isArray(profile.formats) && profile.formats.length === 1) continue;
    profile.formats = ["uri"];
    changed = true;
  }
  return { state, changed };
}

function stripLegacyCiphertext(state) {
  let changed = false;
  const decrypt = (box) => { try { return secrets.decryptSecret(box, currentMasterKey()); } catch (_) { return null; } };
  for (const instance of state.instances || []) {
    if (!instance.credential && instance.credentialCiphertext) {
      const value = decrypt(instance.credentialCiphertext);
      if (value) { try { instance.credential = JSON.parse(value); } catch (_) {} }
    }
    if (instance.credential && instance.credentialCiphertext) { delete instance.credentialCiphertext; changed = true; }
  }
  for (const profile of state.profiles || []) {
    if (!profile.token && profile.tokenCiphertext) {
      const value = decrypt(profile.tokenCiphertext);
      if (value) profile.token = value;
    }
    if (profile.token && profile.tokenCiphertext) { delete profile.tokenCiphertext; changed = true; }
  }
  for (const node of state.legacyNodes || []) {
    if (!node.uri && node.ciphertext) {
      const value = decrypt(node.ciphertext);
      if (value) node.uri = value;
    }
    if (node.uri && node.ciphertext) { delete node.ciphertext; changed = true; }
  }
  return changed;
}

function getState() {
  let state = store.read();
  if (state) {
    if (stripLegacyCiphertext(state)) state = save(state);
    store.importLegacyAudit(state.audit);
    const previousPluginVersion = String(state.pluginVersion || "");
    try { state = store.preparePluginVersion(state, PLUGIN_VERSION); }
    catch (error) {
      const cause = safeText(error && error.message || error, 160);
      fail("upgrade_backup_failed", "插件升级前备份或版本检查失败，已停止加载；现有状态未修改。原因：" + cause, 500);
    }
    if (state.settings.remoteInstallDefaultApplied !== true) {
      if (previousPluginVersion === PLUGIN_VERSION) {
        try { store.backupStorageBeforeChange("upgrade"); }
        catch (error) { fail("upgrade_backup_failed", "启用机器默认远程安装前无法完成存储备份，已停止修改；现有状态未修改。", 500); }
      }
      state.settings.remoteInstallDefaultApplied = true;
      state.machines = state.machines.map((machine) => {
        machine.policy = Object.assign({ deployAllowed: true, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [], managementTags: [] }, machine.policy || {});
        machine.policy.deployAllowed = true;
        return machine;
      });
      return save(state);
    }
    const constrained = constrainLegacyFormats(state);
    return constrained.changed ? save(constrained.state) : constrained.state;
  }
  state = initialState();
  const legacyPath = path.join(__storageDir__, "onebox-bridge.json");
  if (fs.existsSync(legacyPath)) {
    try { store.backupStorageBeforeChange("migration"); }
    catch (error) { fail("migration_backup_failed", "迁移前无法完整备份插件数据目录，已停止升级；原数据未修改。", 500); }
    let legacy;
    try { legacy = JSON.parse(fs.readFileSync(legacyPath, "utf8")); }
    catch (_) { fail("legacy_state_corrupt", "旧版数据文件损坏，已保留原文件；请从备份恢复后再升级。", 500); }
    try { masterKey = secrets.getMasterKey(__storageDir__); }
    catch (_) { fail("master_key_unavailable", "迁移需要的 KNS 主密钥不可用，原状态已保留。", 500); }
    if (legacy && typeof legacy === "object") migrateLegacy(state, legacy);
  }
  store.importLegacyAudit(state.audit);
  state.pluginVersion = PLUGIN_VERSION;
  return store.write(state);
}

function migrateLegacy(state, legacy) {
  if (legacy.settings && typeof legacy.settings === "object") {
    if (legacy.settings.converterUrl) state.settings.converterUrl = safeText(legacy.settings.converterUrl, 300);
    if (CONVERTER_TARGETS.has(String(legacy.settings.converterTarget || ""))) state.settings.converterTarget = legacy.settings.converterTarget;
  }
  const oldToken = typeof legacy.token === "string" ? legacy.token : "";
  if (oldToken.length >= 32) {
    const token = secrets.tokenRecord(oldToken);
    state.profiles.push({ id: "legacy-default", name: "旧版默认订阅", ...token, tokenRequired: true, token: oldToken, createdAt: now(), formats: ["uri"], instanceIds: [], includeTags: [], excludeUnhealthy: false, legacy: true });
  }
  for (const record of Array.isArray(legacy.records) ? legacy.records : []) {
    const uuid = String(record.clientUuid || "");
    if (UUID_RE.test(uuid) && !state.machines.some((machine) => machine.uuid === uuid)) {
      state.machines.push({ uuid, name: safeText(record.clientName || uuid), online: null, lastSeen: null, ipv4: "", ipv6: "", sourceIp: "", policy: { deployAllowed: true, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [], managementTags: [] }, updatedAt: now() });
    }
    if (typeof record.link === "string" && record.link) {
      state.legacyNodes.push({ id: randomId("legacy"), machineUuid: uuid, name: safeText(record.clientName || uuid), uri: record.link, enabled: record.state === "published", migratedAt: now() });
    }
  }
  state.audit.push({ id: randomId("audit"), at: now(), action: "state.migrated", actor: "system", details: { from: "onebox-bridge", records: state.legacyNodes.length } });
}

const JOB_HISTORY_LIMIT = 200;
const ACTIVE_JOB_STATES = ["authorized", "dispatched", "running", "verifying"];

function pruneJobHistory(state) {
  const jobs = Array.isArray(state.jobs) ? state.jobs : [];
  const active = jobs.filter((job) => ACTIVE_JOB_STATES.includes(job.state));
  const finished = jobs.filter((job) => !ACTIVE_JOB_STATES.includes(job.state));
  const keptFinished = finished.length > JOB_HISTORY_LIMIT ? finished.slice(-JOB_HISTORY_LIMIT) : finished;
  state.jobs = jobs.filter((job) => active.includes(job) || keptFinished.includes(job));
  return state;
}

function save(state) {
  const saved = store.write(pruneJobHistory(state));
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
    instances: (state.instances || []).map((instance) => ({
      id: instance.id, machineUuid: instance.machineUuid, name: instance.name, tag: instance.tag,
      protocol: instance.protocol, enabled: instance.enabled, publish: instance.publish,
      deleted: !!instance.deletedAt, remoteMissing: !!(instance.remoteStatus && instance.remoteStatus.installed === false), mappingConflict: !!(instance.nat && instance.nat.mappingConflict),
      unhealthy: !!(instance.health && instance.health.state === "unhealthy"),
      hostHealth: instance.health && instance.health.hosts || {},
      endpoint: instance.endpoint && { host: instance.endpoint.host, hosts: instance.endpoint.hosts, port: instance.endpoint.port },
      listen: instance.listen && { port: instance.listen.port, transport: instance.listen.transport },
      tls: instance.tls, options: instance.options, tags: instance.tags,
      credential: instance.credential || null,
      credentialCiphertext: instance.credentialCiphertext,
    })),
    legacyNodes: profile.legacy ? (state.legacyNodes || []).map((node) => ({ id: node.id, machineUuid: node.machineUuid, tags: node.tags, uri: node.uri || "", ciphertext: node.ciphertext, enabled: node.enabled })) : [],
  };
  return crypto.createHash("sha256").update(JSON.stringify(projection)).digest("hex");
}

function readSubscriptionSnapshot(profileId, format) {
  const box = store.readSubscriptionSnapshot(subscriptionSnapshotKey(profileId, format));
  if (!box) return null;
  const record = box && box.schemaVersion === 1 ? box : JSON.parse(secrets.decryptSecret(box, currentMasterKey()));
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
    const queue = initial.profiles.filter(activeSubscriptionProfile).map((profile) => profile.id);
    for (const profileId of queue) {
      if (subscriptionRefreshStopped) break;
      const current = getState();
      const profile = current.profiles.find((candidate) => candidate.id === profileId);
      if (!activeSubscriptionProfile(profile)) continue;
      const pending = [];
      for (const format of new Set(Array.isArray(profile.formats) ? profile.formats : [])) {
        if (!FORMATS.has(format)) continue;
        const sourceHash = subscriptionSourceHash(current, profile, format);
        try {
          const existing = readSubscriptionSnapshot(profile.id, format);
          if (existing && existing.sourceHash === sourceHash) continue;
        } catch (_) {}
        pending.push({ format, sourceHash });
      }
      if (!pending.length) continue;
      try {
        const built = subscriptions.buildSubscriptions(current, profile, pending.map((item) => item.format), (box) => secrets.decryptSecret(box, currentMasterKey()));
        for (const { format, sourceHash } of pending) {
          const result = built[format];
          const record = {
            schemaVersion: 1,
            profileId: profile.id,
            format,
            sourceHash,
            rulesVersion: SUBSCRIPTION_RULES_VERSION,
            generatedAt: now(),
            successCount: result.successCount,
            skippedCount: result.skippedCount,
            contentType: result.contentType,
            contentHash: crypto.createHash("sha256").update(result.body).digest("hex"),
            body: result.body,
          };
          store.writeSubscriptionSnapshot(subscriptionSnapshotKey(profile.id, format), record);
        }
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
  const event = { id: randomId("audit"), at: now(), action, actor: safeText(principal.username || principal.name || principal.id || "admin", 80), details: details || {} };
  store.appendAudit(event);
  state.audit.push(event);
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

function replaceProfileToken(profile, token, expiresAt) {
  ensureProfileTokens(profile);
  profile.tokens = [];
  const record = createProfileToken(profile, token, expiresAt);
  profile.token = token;
  delete profile.tokenCiphertext;
  profile.tokenRequired = true;
  return record;
}

function recoverProfileToken(profile) {
  if (!profile) return "";
  if (profile.token) return profile.token;
  if (!profile.tokenCiphertext) return "";
  try { return secrets.decryptSecret(profile.tokenCiphertext, currentMasterKey()); }
  catch (_) { fail("token_unavailable", "无法解密当前订阅令牌；请轮换令牌后再使用。", 409); }
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

function applyPendingTokenUsage(state) {
  if (!pendingTokenUsage.size) return false;
  const updates = Array.from(pendingTokenUsage.values());
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
  return changed;
}

function flushTokenUsage() {
  if (!pendingTokenUsage.size) return;
  const state = getState();
  if (applyPendingTokenUsage(state)) save(state);
  pendingTokenUsage.clear();
}

function nodesFrom(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.data)) return value.data;
  if (value && Array.isArray(value.clients)) return value.clients;
  throw new Error("Komari 机器清单格式无效，已保留现有机器数据。");
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

function onlineStatusMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const statuses = new Map();
  for (const [rawUuid, status] of Object.entries(value)) {
    const uuid = String(rawUuid).toLowerCase();
    if (UUID_RE.test(uuid) && status && typeof status.online === "boolean") statuses.set(uuid, status.online);
  }
  return statuses;
}

async function syncMachines() {
  if (syncBusy) return false;
  syncBusy = true;
  try {
    const records = nodesFrom(await server.call("admin:listClients"));
    const live = records.map((record) => record && typeof record === "object" ? normalizeMachine(record) : null);
    if (live.some((machine) => !machine) || new Set(live.map((machine) => machine.uuid)).size !== live.length) {
      throw new Error("Komari 机器清单包含无效或重复的机器，已保留现有机器数据。");
    }
    if (live.length) {
      try {
        // admin:listClients returns registered-client records, not live
        // connection state. Komari 1.6.1 exposes current presence in this
        // common RPC; ask only for UUIDs and retain no metric payload.
        const statuses = onlineStatusMap(await server.call("common:getNodesLatestStatus", { uuids: live.map((machine) => machine.uuid) }));
        if (statuses) {
          for (const machine of live) machine.online = statuses.get(machine.uuid) === true;
        }
      } catch (_) {
        // Older Komari runtimes may lack this RPC; preserve any status field
        // supplied by admin:listClients and otherwise leave it unknown.
      }
    }
    const state = getState();
    const machineKey = (uuid) => String(uuid || "").toLowerCase();
    const current = new Map(state.machines.map((machine) => [machineKey(machine.uuid), machine]));
    const baseline = new Set(state.settings.autoProvisionBaselineUuids || []);
    const incoming = [];
    for (const node of live) {
      const old = current.get(node.uuid);
      const previous = old || { policy: { deployAllowed: true, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [], managementTags: [] } };
      const merged = Object.assign({}, previous, node);
      if (old && old.removedFromKomariAt) audit(state, null, "machine.returned_to_komari", { machineUuid: node.uuid });
      delete merged.removedFromKomariAt;
      merged.policy = Object.assign({ deployAllowed: true, addressMode: "auto", manualAddress: "", ddnsHostname: "", tags: [], managementTags: [] }, previous.policy || {});
      if (!old && state.settings.setupComplete === true && state.settings.autoProvisionNewProbes === true && !baseline.has(node.uuid)) {
        merged.policy.deployAllowed = true;
        merged.autoProvision = { state: "queued", templateVersion: Number(state.settings.defaultNode && state.settings.defaultNode.version) || 1, template: deepClone(state.settings.defaultNode), createdAt: now(), updatedAt: now(), message: "新探针已加入自动部署队列。" };
        audit(state, null, "auto_provision.queued", { machineUuid: node.uuid, protocol: "vless", listenPort: state.settings.defaultNode.listenPort });
      }
      if (state.settings.setupComplete === true) baseline.add(node.uuid);
      const observed = preferredObservedAddress(merged);
      const prior = previous.observedAddress || "";
      if (observed && observed !== prior) {
        merged.addressCandidate = observed;
        merged.addressCandidateCount = observed === (previous.addressCandidate || "") ? Number(previous.addressCandidateCount || 0) + 1 : 1;
        if (merged.addressCandidateCount >= 2) merged.observedAddress = observed;
      } else if (observed) {
        merged.addressCandidate = observed;
        merged.addressCandidateCount = Number(previous.addressCandidateCount || 1);
      }
      incoming.push(merged);
    }
    const known = new Set(incoming.map((machine) => machine.uuid));
    const removed = state.machines.filter((machine) => !known.has(machineKey(machine.uuid)));
    const removedUuids = new Set(removed.map((machine) => machineKey(machine.uuid)));
    for (const uuid of removedUuids) baseline.add(uuid);
    state.settings.autoProvisionBaselineUuids = Array.from(baseline);
    for (const machine of removed) audit(state, null, "machine.removed_from_komari", { machineUuid: machine.uuid });
    if (removedUuids.size) {
      state.instances = state.instances.filter((instance) => !removedUuids.has(machineKey(instance.machineUuid)));
      state.runtimes = state.runtimes.filter((runtime) => !removedUuids.has(machineKey(runtime.machineUuid)));
      state.legacyNodes = state.legacyNodes.filter((node) => !removedUuids.has(machineKey(node.machineUuid)));
      for (const job of state.jobs) {
        if (!removedUuids.has(machineKey(job.machineUuid))) continue;
        if (["authorized", "dispatched", "running", "verifying"].includes(job.state)) {
          job.state = "cancelled"; job.updatedAt = now();
          job.message = "机器已从 Komari 删除，KNS 已停止跟踪此任务。";
        }
        closeJob(job);
      }
    }
    const machines = incoming;
    const nextState = Object.assign({}, state, { machines });
    lastLiveSync = Date.now();
    const snapshot = (items) => JSON.stringify((items || []).map((machine) => ({
      uuid: machine.uuid, name: machine.name, online: machine.online, lastSeen: machine.lastSeen || "", ipv4: machine.ipv4 || "", ipv6: machine.ipv6 || "", sourceIp: machine.sourceIp || "",
      removedFromKomariAt: machine.removedFromKomariAt || "",
      region: machine.region || "", os: machine.os || "", arch: machine.arch || "",
      observedAddress: machine.observedAddress || "",
      policy: { deployAllowed: !!(machine.policy && machine.policy.deployAllowed), addressMode: (machine.policy && machine.policy.addressMode) || "auto", manualAddress: (machine.policy && machine.policy.manualAddress) || "", ddnsHostname: (machine.policy && machine.policy.ddnsHostname) || "", tags: (machine.policy && machine.policy.tags) || [], managementTags: (machine.policy && machine.policy.managementTags) || [] },
      autoProvision: machine.autoProvision && { state: machine.autoProvision.state, instanceId: machine.autoProvision.instanceId || "", templateVersion: Number(machine.autoProvision.templateVersion) || 0 },
    })));
    if (removedUuids.size || snapshot(state.machines) !== snapshot(machines)) save(nextState);
    if (nextState.machines.some((machine) => !machine.removedFromKomariAt && machine.autoProvision && machine.autoProvision.state === "queued")) setTimeout(dispatchAutoProvisionQueue, 0);
    return true;
  } finally { syncBusy = false; }
}

function normalizeDefaultNode(body, current) {
  const source = body || {};
  const existing = current || { protocol: "vless", listenPort: 443, listenAddress: "::", sniMode: "preferred", version: 1 };
  const protocol = String(source.protocol || existing.protocol || "vless").toLowerCase();
  if (protocol !== "vless") fail("invalid_default_protocol", "自动部署默认协议固定为 VLESS + Reality，SNI 由 OneBox 自动优选。", 400);
  const listenPort = validatePort(source.listenPort == null ? existing.listenPort : source.listenPort);
  const listenAddress = String(source.listenAddress || existing.listenAddress || "::");
  if (!["::", "0.0.0.0"].includes(listenAddress)) fail("invalid_default_address", "默认监听地址只支持双栈 :: 或 IPv4 0.0.0.0。", 400);
  return { protocol, listenPort, listenAddress, sniMode: "preferred", version: Math.max(1, Number(existing.version) || 1), updatedAt: existing.updatedAt || "" };
}

function automaticInstanceName(machineName, port) {
  const prefix = "VLESS-";
  const suffix = "-" + String(port);
  const middle = safeText(machineName || "Komari探针", Math.max(1, 80 - prefix.length - suffix.length));
  return prefix + (middle || "Komari探针") + suffix;
}

async function dispatchAutoProvisionQueue() {
  if (autoProvisionBusy || maintenanceLock) return;
  autoProvisionBusy = true;
  try {
    const state = getState();
    if (state.settings.setupComplete !== true || state.settings.autoProvisionNewProbes !== true) return;
    const batchSize = Math.max(1, Math.min(10, Number(state.settings.maxBatch) || 10));
    const queued = state.machines.filter((machine) => !machine.removedFromKomariAt && machine.autoProvision && machine.autoProvision.state === "queued" && machine.online === true).slice(0, batchSize);
    for (const machine of queued) {
      try { await startAutoProvision(machine.uuid); }
      catch (error) {
        const latest = getState();
        const current = latest.machines.find((item) => item.uuid === machine.uuid);
        if (current && current.autoProvision && current.autoProvision.state === "queued") {
          current.autoProvision = Object.assign({}, current.autoProvision, { state: "failed", updatedAt: now(), message: safeText(error && error.message || "自动部署无法启动。", 240) });
          audit(latest, null, "auto_provision.failed", { machineUuid: current.uuid, reason: "queue_error" });
          save(latest);
        }
      }
    }
  } finally { autoProvisionBusy = false; }
}

async function startAutoProvision(machineUuid) {
  let state = getState();
  let machine = state.machines.find((item) => item.uuid === machineUuid);
  if (!machine || machine.removedFromKomariAt || !machine.autoProvision || machine.autoProvision.state !== "queued") return;
  if (state.settings.setupComplete !== true || state.settings.autoProvisionNewProbes !== true || machine.online !== true) return;
  if (!machine.policy || machine.policy.deployAllowed !== true) {
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "cancelled", updatedAt: now(), message: "已关闭此探针的部署权限。" });
    save(state); return;
  }
  if (!state.settings.publicBaseUrl) {
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "failed", updatedAt: now(), message: "缺少 HTTPS 公网地址，无法接收 OneBox 回调。" });
    save(state); return;
  }

  const template = normalizeDefaultNode({}, machine.autoProvision.template || state.settings.defaultNode);
  const instanceId = "autov1-" + machine.uuid.replace(/-/g, "");
  const existing = state.instances.find((instance) => instance.id === instanceId && instance.machineUuid === machine.uuid && !instance.deletedAt);
  const owner = (state.instances.find((instance) => instance.id === instanceId) || {}).machineUuid || reservedInstanceOwner(state, instanceId);
  if (owner && owner !== machine.uuid) {
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "failed", updatedAt: now(), message: "默认实例 ID 已被另一台探针占用。" });
    audit(state, null, "auto_provision.failed", { machineUuid, reason: "instance_id_conflict", instanceId });
    save(state); return;
  }
  if (existing) {
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "succeeded", instanceId, updatedAt: now(), message: "默认节点已存在。" });
    save(state); return;
  }
  const conflictingJob = state.jobs.find((job) => job.machineUuid === machine.uuid && job.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(job.state));
  if (conflictingJob || unconfirmedDispatch(state, machine.uuid)) return;

  const validated = validateProtocolSettings({ protocol: template.protocol, listenPort: template.listenPort, listenAddress: template.listenAddress, options: { security: "reality" } });
  if (portConflicts(state, machine.uuid, validated.port, validated.transport, instanceId, validated.listenAddress)) {
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "failed", updatedAt: now(), message: "默认端口 " + validated.port + "/TCP 已被该探针上的其他节点占用。" });
    audit(state, null, "auto_provision.failed", { machineUuid, reason: "port_conflict", listenPort: validated.port });
    save(state); return;
  }
  const name = automaticInstanceName(machine.name, validated.port);
  const requestHash = crypto.createHash("sha256").update(JSON.stringify({ action: "install", machineUuid, instanceId: "", protocol: validated.protocol, port: validated.port, transport: validated.transport, options: validated.options, listenAddress: validated.listenAddress, endpointHost: "", endpointPort: 0, externalPort: 0 })).digest("hex");
  const spec = { id: instanceId, protocol: validated.protocol, port: validated.port, listenAddress: validated.listenAddress, transport: validated.transport, options: validated.options, name, tags: [], idempotencyKey: "auto-v" + template.version + "-" + machine.uuid.replace(/-/g, ""), requestHash };
  const { job, params } = createJob(state, { context: { principal: { username: "auto-provision" } } }, "install", machine, spec, null);
  job.autoProvision = true;
  machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "installing", jobId: job.id, instanceId, updatedAt: now(), message: "正在发送自动部署任务；最终结果仍需 Agent、回调和远端状态核验。" });
  audit(state, null, "auto_provision.authorized", { jobId: job.id, machineUuid, instanceId, protocol: validated.protocol, listenPort: validated.port });
  save(state);

  const submitted = await finishDispatch(job, params);
  state = getState();
  machine = state.machines.find((item) => item.uuid === machineUuid);
  if (machine && machine.autoProvision && machine.autoProvision.jobId === submitted.id) {
    machine.autoProvision.state = ["failed", "needs_reconcile", "cancelled"].includes(submitted.state) ? "failed" : "installing";
    machine.autoProvision.updatedAt = now();
    machine.autoProvision.message = submitted.message || "已发送到 Komari Agent，等待部署结果。";
    save(state);
  }
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
    policyVersion: machinePolicyVersion(machine),
    uuid: machine.uuid, name: machine.name, region: machine.region, os: machine.os, arch: machine.arch,
     online: machine.online, lastSeen: machine.lastSeen, ipv4: machine.ipv4, ipv6: machine.ipv6, sourceIp: machine.sourceIp,
    removedFromKomariAt: machine.removedFromKomariAt || "",
     observedAddress: machine.observedAddress || "", addressCandidate: machine.addressCandidate || "", policy: Object.assign({}, machine.policy || {}, { managementTags: Array.isArray(machine.policy && machine.policy.managementTags) ? Array.from(new Set(machine.policy.managementTags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [] }),
    discoveredAt: machine.discoveredAt || "", discoveredNodes: Array.isArray(machine.discoveredNodes) ? machine.discoveredNodes.map((node) => ({
      tag: safeText(node.tag || "", 128), protocol: safeText(node.protocol || "unknown", 32),
      listen: { port: Number(node.listen && node.listen.port) || 0, address: safeText(node.listen && node.listen.address || "", 64), transport: safeText(node.listen && node.listen.transport || "unknown", 16) },
      managed: node.managed === true, importable: node.importable === true, options: { security: safeText(node.options && node.options.security || "", 32), sni: safeText(node.options && node.options.sni || "", 253), method: safeText(node.options && node.options.method || "", 64) },
      reason: safeText(node.reason || "", 64),
    })) : [],
    runtimeStatus: machine.runtimeStatus ? deepClone(machine.runtimeStatus) : null,
    autoProvision: machine.autoProvision ? deepClone(machine.autoProvision) : null,
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
  delete copy.retrySpec;
  delete copy.retryIdempotencyKey;
  if (copy.callback) {
    delete copy.callback.keyFingerprint;
    if (copy.callback.instance) {
      delete copy.callback.instance.credential;
      delete copy.callback.instance.credentialCiphertext;
    }
  }
  return copy;
}

function jobRetryable(state, job) {
  return !!job && job.state === "failed" && !job.taskId && !job.callback && ["-32040", "-32041"].includes(String(job.rpcErrorCode || "")) &&
    ["install", "reconfigure", "reinstall", "enable", "disable"].includes(job.action) && !!job.retrySpec &&
    !job.retryOfJobId &&
    !state.jobs.some((candidate) => candidate.retryOfJobId === job.id);
}

function publicState(state) {
  const auditPage = store.listAudit(200);
  const jobs = state.jobs.slice().reverse().map((job) => Object.assign(safeJob(job), { canRetry: jobRetryable(state, job) }));
  const settings = Object.assign({}, state.settings);
  delete settings.remoteInstallDefaultApplied;
  return {
    schemaVersion: state.schemaVersion,
    pluginVersion: PLUGIN_VERSION,
    sourceUrl: SOURCE_URL,
    revision: state.revision,
    updatedAt: state.updatedAt,
    settings: Object.assign({}, settings, { oneboxScriptUrl: INSTALLER_URL, oneboxScriptSha256: INSTALLER_SHA256, connectionEditVersion: settingsEditVersion(state.settings, "settings.update"), defaultsEditVersion: settingsEditVersion(state.settings, "settings.defaults.update") }),
    machines: state.machines.map(safeMachine),
    runtimes: state.runtimes,
    instances: state.instances.map(safeInstance),
    jobs,
    audit: auditPage.events,
    auditCursor: auditPage.nextCursor,
    auditHasMore: auditPage.hasMore,
    auditRetention: auditPage.retention,
    profiles: state.profiles.map((profile) => ({ editVersion: profileEditVersion(profile), id: profile.id, name: profile.name, createdAt: profile.createdAt, expiresAt: profile.expiresAt || "", revokedAt: profile.revokedAt || "", tokenRequired: profile.tokenRequired !== false, hasRecoverableToken: !!(profile.token || profile.tokenCiphertext) && profileTokenRecords(profile).some((record) => record && !record.revokedAt && (!record.expiresAt || Date.parse(record.expiresAt) > Date.now())), tokens: profileTokenRecords(profile).map(safeProfileToken), formats: profile.formats, instanceIds: profile.instanceIds || null, machineUuids: profile.machineUuids || null, excludeMachineUuids: profile.excludeMachineUuids || [], protocols: profile.protocols || null, includeTags: profile.includeTags || [], excludeUnhealthy: profile.excludeUnhealthy !== false, addressMode: profile.addressMode || "auto", sortBy: profile.sortBy || "name", legacy: !!profile.legacy })),
    backups: store.listBackups(),
    subscriptionFormats: Array.from(FORMATS),
    endpointPrecedence: ["instance endpoint override", "machine manual public address", "DDNS domain", "Komari-reported address"],
  };
}



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
    // Compare numeric address segments so compressed, expanded and dotted
    // spellings enforce the same boundary. A scope ID is not address data.
    let address = host.toLowerCase().split("%")[0];
    if (address.includes(".")) {
      const tail = address.slice(address.lastIndexOf(":") + 1).split(".").map(Number);
      if (tail.length !== 4 || tail.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) fail("invalid_host", "IPv6 地址无效。", 400);
      address = address.slice(0, address.lastIndexOf(":") + 1) + ((tail[0] << 8) | tail[1]).toString(16) + ":" + ((tail[2] << 8) | tail[3]).toString(16);
    }
    const halves = address.split("::");
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    if (halves.length > 2 || (halves.length === 2 ? missing < 1 : missing !== 0) || left.concat(right).some((part) => !/^[0-9a-f]{1,4}$/.test(part))) fail("invalid_host", "IPv6 地址无效。", 400);
    const words = left.concat(Array(halves.length === 2 ? missing : 0).fill("0"), right).map((part) => parseInt(part, 16));
    if (words.every((part) => part === 0) || (words[0] & 0xff00) === 0xff00) fail("invalid_host", "Endpoint 不能使用未指定或组播 IPv6 地址。", 400);
    if (words.slice(0, 5).every((part) => part === 0) && words[5] === 0xffff) {
      normalizeHost([words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join("."), allowPrivate);
    }
    const privateV6 = words.slice(0, 7).every((part) => part === 0) && words[7] === 1 ||
      (words[0] & 0xfe00) === 0xfc00 || (words[0] & 0xffc0) === 0xfe80 || words[0] === 0x2001 && words[1] === 0x0db8;
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
  const family = mode === "ipv4" ? 4 : mode === "ipv6" ? 6 : 0;
  const matchesMode = (address) => !!address && (!family || require("net").isIP(address) === family);
  if (!manual && !(machine.policy && machine.policy.ddnsHostname) && family && !matchesMode(family === 4 ? machine.ipv4 : machine.ipv6)) return null;
  let hosts = [];
  if (!manual && !(machine.policy && machine.policy.ddnsHostname)) {
    if (mode === "dual") hosts = [machine.ipv4, machine.ipv6].filter(Boolean);
    if (!hosts.length && machine.observedAddress) hosts = String(machine.observedAddress).split(",").filter(matchesMode);
    if (!hosts.length) hosts = preferredObservedAddress(machine).split(",").filter(matchesMode);
  }
  let host = manual || (machine.policy && machine.policy.ddnsHostname) || hosts[0];
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
  const allowedOptions = new Set(["security", "sni", "method", "alpn", "allowInsecure", "flow", "fingerprint", "spiderX", "handshakeServer", "handshakePort", "upMbps", "downMbps", "obfs", "obfsPassword", "alterId", "cipher", "congestionControl", "udpRelayMode"]);
  if (Object.keys(options).some((key) => !allowedOptions.has(key))) fail("invalid_options", "存在 OneBox 不支持的选项。", 400);
  const sni = options.sni ? validHostname(options.sni) : "";
  if (options.sni && !sni) fail("invalid_sni", "SNI 必须是域名。", 400);
  if (["trojan", "vmess", "hysteria2", "tuic", "anytls"].includes(protocol) && !sni) fail("sni_required", "该协议需要配置 TLS SNI。", 400);
  if (protocol === "vless" && options.security !== "reality") fail("security_required", "当前 OneBox 适配器要求 VLESS 使用 Reality。", 400);
  if (protocol === "shadowsocks" && options.method && !["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].includes(String(options.method))) fail("invalid_method", "Shadowsocks 加密方法不受当前 OneBox 适配器支持。", 400);
  if (protocol === "shadowsocks" && !options.method) fail("method_required", "Shadowsocks 需要指定加密方法。", 400);
  if (options.alpn != null) {
    if (!Array.isArray(options.alpn) || options.alpn.length > 8 || !options.alpn.every((item) => typeof item === "string" && /^[A-Za-z0-9._/-]{1,32}$/.test(item))) fail("invalid_alpn", "ALPN 必须是 1–8 个合法字符串。", 400);
  }
  if (options.allowInsecure != null && typeof options.allowInsecure !== "boolean") fail("invalid_allow_insecure", "allowInsecure 必须是布尔值。", 400);
  if (options.flow != null && !["", "xtls-rprx-vision"].includes(String(options.flow))) fail("invalid_flow", "VLESS flow 只支持 xtls-rprx-vision 或留空。", 400);
  if (options.fingerprint != null && !["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"].includes(String(options.fingerprint))) fail("invalid_fingerprint", "Reality fingerprint 不受支持。", 400);
  if (options.spiderX != null && (typeof options.spiderX !== "string" || options.spiderX.length > 256)) fail("invalid_spider_x", "spiderX 必须是不超过 256 字符的字符串。", 400);
  if (options.handshakeServer != null && !validHostname(String(options.handshakeServer))) fail("invalid_handshake_server", "Reality 握手地址必须是域名或 IP。", 400);
  if (options.handshakePort != null && (!Number.isInteger(Number(options.handshakePort)) || Number(options.handshakePort) < 1 || Number(options.handshakePort) > 65535)) fail("invalid_handshake_port", "Reality 握手端口必须是 1–65535 的整数。", 400);
  for (const keyName of ["upMbps", "downMbps"]) {
    if (options[keyName] != null && (!Number.isInteger(Number(options[keyName])) || Number(options[keyName]) < 0 || Number(options[keyName]) > 100000)) fail("invalid_" + keyName, keyName + " 必须是 0–100000 的整数。", 400);
  }
  if (options.obfs != null && !["", "salamander"].includes(String(options.obfs))) fail("invalid_obfs", "Hysteria2 obfs 只支持 salamander 或留空。", 400);
  if (options.obfs === "salamander" && !options.obfsPassword) fail("obfs_password_required", "obfs=salamander 需要 obfsPassword。", 400);
  if (options.obfsPassword != null && (typeof options.obfsPassword !== "string" || options.obfsPassword.length > 256)) fail("invalid_obfs_password", "obfsPassword 过长。", 400);
  if (options.alterId != null && (!Number.isInteger(Number(options.alterId)) || Number(options.alterId) < 0 || Number(options.alterId) > 65535)) fail("invalid_alter_id", "VMess alterId 必须是 0–65535 的整数。", 400);
  if (options.cipher != null && !["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"].includes(String(options.cipher))) fail("invalid_cipher", "VMess cipher 不受支持。", 400);
  if (options.congestionControl != null && !["bbr", "cubic", "new_reno"].includes(String(options.congestionControl))) fail("invalid_congestion", "TUIC congestionControl 不受支持。", 400);
  if (options.udpRelayMode != null && !["native", "quic"].includes(String(options.udpRelayMode))) fail("invalid_udp_relay", "TUIC udpRelayMode 不受支持。", 400);
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

function endpointPublicHosts(endpoint) {
  const values = endpoint && Array.isArray(endpoint.resolvedAddresses) && endpoint.resolvedAddresses.length
    ? endpoint.resolvedAddresses
    : endpoint && Array.isArray(endpoint.hosts) && endpoint.hosts.length ? endpoint.hosts : [endpoint && endpoint.host];
  return Array.from(new Set(values.map((host) => String(host || "").trim()).filter(Boolean)));
}

function markNatMappingConflict(state, instance, endpoint) {
  const current = instance.nat.mappingConflict;
  const publicHosts = endpointPublicHosts(endpoint);
  const sameConflict = current && Number(current.externalPort) === Number(instance.nat.externalPort)
    && JSON.stringify((current.publicHosts || []).slice().sort()) === JSON.stringify(publicHosts.slice().sort());
  if (sameConflict) return false;
  instance.nat.mappingConflict = {
    detectedAt: current && current.detectedAt || now(),
    externalPort: Number(instance.nat.externalPort),
    publicHosts,
  };
  instance.updatedAt = now();
  if (!current) audit(state, null, "instance.nat.mapping_conflict.detected", { instanceId: instance.id, externalPort: Number(instance.nat.externalPort), publicHosts });
  return true;
}

function clearNatMappingConflict(state, instance) {
  if (!instance.nat || !instance.nat.mappingConflict) return false;
  const conflict = instance.nat.mappingConflict;
  delete instance.nat.mappingConflict;
  audit(state, null, "instance.nat.mapping_conflict.cleared", { instanceId: instance.id, externalPort: Number(conflict.externalPort) });
  return true;
}

function checkTwoFactor(value) {
  const code = String(value || "").trim();
  if (code && !/^\d{6,8}$/.test(code)) fail("invalid_2fa", "2FA 验证码必须是 6 或 8 位数字。", 400);
  return code;
}

function makeRemoteCommand(state, job, instance) {
  const callbackUrl = state.settings.publicBaseUrl.replace(/\/$/, "") + API + "/report";
  const runtimeUpgrade = ["runtime.script.update", "runtime.kernel.update"].includes(job.action);
  const remoteAction = job.action === "machine.import" ? "claim" : job.action === "runtime.script.update" ? "update-script" : job.action === "runtime.kernel.update" ? "update-kernel" : job.action;
  const request = {
    schema: 1,
    jobId: job.id,
    machineUuid: job.machineUuid,
    action: remoteAction,
    runtime: { engine: "sing-box", id: job.runtimeId || (instance && instance.runtimeId) || "onebox-main" },
    instance: runtimeUpgrade ? null : {
      id: instance.id,
      protocol: instance.protocol,
      listenPort: instance.listen.port,
      listenAddress: instance.listen.address || "::",
      transport: instance.listen.transport,
      options: instance.options || {},
      ...(job.action === "machine.import" ? { legacyTag: job.legacyTag } : {}),
    },
    ...(job.action === "runtime.script.update" ? { upgrade: { scriptSha256: INSTALLER_SHA256 } } : {}),
    ...(job.action === "runtime.kernel.update" ? { upgrade: { version: job.requestedVersion || "latest" } } : {}),
    idempotencyKey: job.idempotencyKey,
    report: { callback: callbackUrl, oneTimeToken: job._callbackToken },
  };
  const payload = Buffer.from(JSON.stringify(request), "utf8").toString("base64");
  const scriptUrl = INSTALLER_URL;
  const digest = INSTALLER_SHA256;
  const installer = quoteShell(scriptUrl);
  const statusId = instance ? quoteShell(instance.id) : "";
  const verifyCommand = runtimeUpgrade
    ? "kns_rc=$?; verify=$(bash \"$installer\" kns runtime-status); verify_rc=$?; if [ \"$verify_rc\" -eq 0 ]; then printf 'KNS_RUNTIME_STATUS=%s\\n' \"$verify\"; fi; [ \"$kns_rc\" -eq 0 ] || exit \"$kns_rc\"; [ \"$verify_rc\" -eq 0 ] || exit \"$verify_rc\""
    : job.action === "machine.import"
      ? "kns_rc=$?; verify=$(bash \"$installer\" kns discover); discover_rc=$?; if [ \"$discover_rc\" -eq 0 ]; then printf 'KNS_DISCOVERY=%s\\n' \"$verify\"; fi; runtime=$(bash \"$installer\" kns runtime-status); runtime_rc=$?; if [ \"$runtime_rc\" -eq 0 ]; then printf 'KNS_RUNTIME_STATUS=%s\\n' \"$runtime\"; fi; [ \"$kns_rc\" -eq 0 ] || exit \"$kns_rc\"; [ \"$discover_rc\" -eq 0 ] || exit \"$discover_rc\"; [ \"$runtime_rc\" -eq 0 ] || exit \"$runtime_rc\""
      : "kns_rc=$?; verify=$(bash \"$installer\" kns status --instance-id " + statusId + "); verify_rc=$?; if [ \"$verify_rc\" -eq 0 ]; then printf 'KNS_STATUS=%s\\n' \"$verify\"; fi; [ \"$kns_rc\" -eq 0 ] || exit \"$kns_rc\"; [ \"$verify_rc\" -eq 0 ] || exit \"$verify_rc\"";
  const bootstrapCommands = job.action === "install" ? [
    "onebox_config=/etc/onebox/config.json; onebox_needs_bootstrap=0; onebox_bootstrap_blocked=''",
    "if [ -L /etc/onebox ] || [ -L \"$onebox_config\" ]; then onebox_bootstrap_blocked=invalid_config; elif [ -e \"$onebox_config\" ]; then if [ ! -f \"$onebox_config\" ]; then onebox_bootstrap_blocked=invalid_config; elif ! command -v jq >/dev/null 2>&1; then onebox_needs_bootstrap=1; elif ! jq -e 'type == \"object\" and (.inbounds | type == \"array\")' \"$onebox_config\" >/dev/null 2>&1; then onebox_bootstrap_blocked=invalid_config; elif [ ! -x /usr/local/bin/onebox ] || [ ! -x /usr/local/lib/onebox/sing-box ]; then onebox_needs_bootstrap=1; fi; else if [ -e /etc/onebox ] && [ ! -d /etc/onebox ]; then onebox_bootstrap_blocked=existing_state; elif [ -d /etc/onebox ]; then if ! command -v find >/dev/null 2>&1; then onebox_bootstrap_blocked=existing_state; else onebox_existing_state=$(find /etc/onebox -mindepth 1 ! \\( -type d \\( -path /etc/onebox/kns -o -path /etc/onebox/kns/instances -o -path /etc/onebox/kns/certs \\) \\) ! \\( -type f -path /etc/onebox/.version_cache \\) -print -quit 2>/dev/null); onebox_find_rc=$?; if [ \"$onebox_find_rc\" -ne 0 ] || [ -n \"$onebox_existing_state\" ]; then onebox_bootstrap_blocked=existing_state; fi; fi; fi; for onebox_unit in /etc/systemd/system/onebox.service /run/systemd/system/onebox.service /usr/lib/systemd/system/onebox.service /lib/systemd/system/onebox.service /usr/local/lib/systemd/system/onebox.service /etc/init.d/onebox; do if [ -e \"$onebox_unit\" ] || [ -L \"$onebox_unit\" ]; then onebox_bootstrap_blocked=existing_state; fi; done; if [ -z \"$onebox_bootstrap_blocked\" ]; then onebox_needs_bootstrap=1; fi; fi",
    "if [ -n \"$onebox_bootstrap_blocked\" ]; then printf 'KNS_BOOTSTRAP_BLOCKED=%s\\n' \"$onebox_bootstrap_blocked\"; exit 1; fi",
    "if [ \"$onebox_needs_bootstrap\" -eq 1 ]; then printf 'KNS_BOOTSTRAP=started\\n'; bash \"$installer\" install --non-interactive; bootstrap_rc=$?; if [ \"$bootstrap_rc\" -ne 0 ]; then printf 'KNS_BOOTSTRAP_FAILED=%s\\n' \"$bootstrap_rc\"; exit \"$bootstrap_rc\"; fi; printf 'KNS_BOOTSTRAP=completed\\n'; fi",
  ] : [];
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
    ...bootstrapCommands,
    "bash \"$installer\" kns " + quoteShell(remoteAction) + " --request-file \"$request_file\"",
    verifyCommand,
  ].join("; ");
}

function makeRemoteDiscoveryCommand() {
  const installer = quoteShell(INSTALLER_URL);
  const digest = quoteShell(INSTALLER_SHA256);
  return [
    "set -u",
    "[ \"$(id -u)\" -eq 0 ] || { printf '%s\\n' KNS_SCAN_ERROR=not_root; exit 77; }",
    "command -v sha256sum >/dev/null 2>&1 || { printf '%s\\n' KNS_SCAN_ERROR=missing_sha256sum; exit 127; }",
    "command -v bash >/dev/null 2>&1 || { printf '%s\\n' KNS_SCAN_ERROR=missing_bash; exit 127; }",
    "if [ ! -e /etc/onebox/config.json ] && [ ! -L /etc/onebox/config.json ]; then printf '%s\\n' KNS_SCAN_ERROR=config_missing; exit 1; fi",
    "command -v jq >/dev/null 2>&1 || { printf '%s\\n' KNS_SCAN_ERROR=missing_jq; exit 127; }",
    "installer=$(mktemp) || { printf '%s\\n' KNS_SCAN_ERROR=temp_file; exit 1; }; trap 'rm -f \"$installer\"' EXIT",
    "if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 180 " + installer + " -o \"$installer\" || { printf '%s\\n' KNS_SCAN_ERROR=download_failed; exit 1; }; elif command -v wget >/dev/null 2>&1; then wget -qO \"$installer\" " + installer + " || { printf '%s\\n' KNS_SCAN_ERROR=download_failed; exit 1; }; else printf '%s\\n' KNS_SCAN_ERROR=missing_downloader; exit 127; fi",
    "printf '%s  %s\\n' " + digest + " \"$installer\" | sha256sum -c - >/dev/null || { printf '%s\\n' KNS_SCAN_ERROR=checksum_failed; exit 65; }",
    "result=$(bash \"$installer\" kns discover); discover_rc=$?; if [ \"$discover_rc\" -ne 0 ]; then case \"$result\" in *low_pid_headroom*) printf '%s\\n' KNS_RESOURCE=low_pid_headroom ;; *low_memory_headroom*) printf '%s\\n' KNS_RESOURCE=low_memory_headroom ;; esac; printf '%s\\n' KNS_SCAN_ERROR=discover_failed; exit \"$discover_rc\"; fi",
    "printf 'KNS_DISCOVERY=%s\\n' \"$result\"",
    "runtime=$(bash \"$installer\" kns runtime-status) || { printf '%s\\n' KNS_SCAN_ERROR=runtime_failed; exit 1; }; printf 'KNS_RUNTIME_STATUS=%s\\n' \"$runtime\"",
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

function extractDiscovery(value) {
  const text = taskText(value);
  const match = text.match(/KNS_DISCOVERY=(\{[^\r\n]*\})/);
  if (!match) return null;
  try { return JSON.parse(match[1]); } catch (_) { return null; }
}

function extractRuntimeStatus(value) {
  const text = taskText(value);
  const match = text.match(/KNS_RUNTIME_STATUS=(\{[^\r\n]*\})/);
  if (!match) return null;
  try { return JSON.parse(match[1]); } catch (_) { return null; }
}

function extractOneboxErrorCode(value, job) {
  for (const line of taskText(value).split(/\r?\n/)) {
    const candidate = line.trim();
    if (!candidate.startsWith("{") || !candidate.endsWith("}")) continue;
    let result;
    try { result = JSON.parse(candidate); } catch (_) { continue; }
    const error = result && result.error;
    const code = error && typeof error.code === "string" ? error.code : "";
    if (result.schema !== 1 || result.status !== "failed" || result.jobId !== job.id || result.machineUuid !== job.machineUuid || !/^[a-z][a-z0-9_]{0,63}$/.test(code)) continue;
    return code;
  }
  return "";
}

function safeOneboxErrorMessage(code) {
  const messages = {
    onebox_not_installed: "OneBox 基础环境未就绪。请检查 OneBox 初始化结果。",
    missing_dependency: "目标机器缺少 OneBox 安装所需依赖。",
    port_in_use: "目标监听端口与现有 OneBox 节点冲突。",
    sni_selection_failed: "OneBox 未能自动选择 VLESS Reality SNI。",
    config_invalid: "OneBox 配置校验失败；系统已尝试恢复原配置。",
    service_reload_failed: "OneBox 配置校验或服务重载失败；系统已尝试恢复原配置。",
  };
  return messages[code] || "OneBox 返回错误（" + code + "）。";
}

function isRuntimeUpgradeAction(action) { return action === "runtime.script.update" || action === "runtime.kernel.update"; }

function validateRuntimeStatus(value) {
  const runtime = value && value.runtime;
  if (!value || value.schema !== 1 || value.adapterVersion !== ONEBOX_ADAPTER_VERSION || !runtime || runtime.engine !== "sing-box" || runtime.id !== "onebox-main") return null;
  const scriptVersion = String(runtime.oneboxScriptVersion || "");
  const scriptSha256 = String(runtime.oneboxScriptSha256 || "");
  const singBoxVersion = String(runtime.singBoxVersion || "");
  const serviceState = String(runtime.serviceState || "");
  if (scriptVersion.length > 32 || (scriptSha256 && !/^[0-9a-f]{64}$/.test(scriptSha256))) return null;
  if (singBoxVersion !== "unknown" && !/^\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?$/.test(singBoxVersion)) return null;
  if (!["active", "inactive", "unknown"].includes(serviceState)) return null;
  return { adapterVersion: ONEBOX_ADAPTER_VERSION, oneboxScriptVersion: scriptVersion || "unknown", oneboxScriptSha256: scriptSha256, singBoxVersion, serviceState };
}

function validateRuntimeCallback(job, body) {
  if (!body || body.schema !== 1 || body.status !== "succeeded" || body.jobId !== job.id || body.machineUuid !== job.machineUuid || !body.runtime || body.runtime.engine !== "sing-box" || body.runtime.id !== "onebox-main" || body.artifactVersion !== ONEBOX_ADAPTER_VERSION || !Array.isArray(body.instances) || body.instances.length !== 0) fail("invalid_callback", "运行时升级回调结构或任务身份无效。", 400);
  const result = body.operationResult;
  if (!result || typeof result !== "object" || Array.isArray(result)) fail("invalid_callback", "运行时升级回调缺少结果。", 400);
  if (job.action === "runtime.script.update") {
    if (result.type !== "script_update" || result.version !== ONEBOX_SCRIPT_VERSION || result.scriptSha256 !== INSTALLER_SHA256 || !/^[0-9a-f]{64}$/.test(String(result.previousSha256 || "")) || typeof result.changed !== "boolean") fail("invalid_callback", "OneBox 管理脚本升级回调与固定产物不匹配。", 400);
    return { type: "script_update", version: ONEBOX_SCRIPT_VERSION, previousSha256: result.previousSha256, scriptSha256: INSTALLER_SHA256, changed: result.changed };
  }
  if (result.type !== "kernel_update" || result.requestedVersion !== "latest" || !/^\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?$/.test(String(result.previousVersion || "")) || !/^\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?$/.test(String(result.singBoxVersion || "")) || !["active", "inactive"].includes(result.serviceState)) fail("invalid_callback", "sing-box 内核升级回调字段无效。", 400);
  return { type: "kernel_update", requestedVersion: "latest", previousVersion: result.previousVersion, singBoxVersion: result.singBoxVersion, serviceState: result.serviceState };
}

function runtimeUpgradeMatches(job, status, operationResult) {
  if (!status || !operationResult) return false;
  if (job.action === "runtime.script.update") return status.oneboxScriptVersion === ONEBOX_SCRIPT_VERSION && status.oneboxScriptSha256 === INSTALLER_SHA256 && operationResult.scriptSha256 === status.oneboxScriptSha256;
  return status.singBoxVersion === operationResult.singBoxVersion && status.serviceState === operationResult.serviceState && ["active", "inactive"].includes(status.serviceState);
}

function runtimeUpgradeWasApplied(job, status) {
  if (!status) return false;
  if (job.action === "runtime.script.update") {
    if (status.oneboxScriptSha256 !== INSTALLER_SHA256) return false;
    const previousSha256 = job.previousRuntimeStatus && job.previousRuntimeStatus.oneboxScriptSha256;
    return !previousSha256 || previousSha256 !== INSTALLER_SHA256;
  }
  const previous = job.previousRuntimeStatus || {};
  return typeof previous.singBoxVersion === "string" && previous.singBoxVersion !== "unknown" && status.singBoxVersion !== "unknown" && status.singBoxVersion !== previous.singBoxVersion;
}

function validateDiscovery(job, result) {
  if (!result || result.schema !== 1 || result.adapterVersion !== ONEBOX_ADAPTER_VERSION || !result.runtime || result.runtime.engine !== "sing-box" || result.runtime.id !== "onebox-main" || !Array.isArray(result.instances) || result.instances.length > 500) return null;
  const allowedTransports = new Set(["tcp", "udp", "tcp+udp", "ws"]);
  return result.instances.slice(0, 200).filter((node) => node && typeof node.tag === "string" && node.tag.length > 0 && node.tag.length <= 128 && node.listen && Number.isInteger(Number(node.listen.port)) && Number(node.listen.port) >= 0 && Number(node.listen.port) <= 65535 && typeof node.protocol === "string").map((node) => ({
    tag: safeText(node.tag, 128), protocol: safeText(node.protocol, 32),
    listen: { port: Number(node.listen.port), address: safeText(node.listen.address || "", 64), transport: allowedTransports.has(node.listen.transport) ? node.listen.transport : "unknown" },
    managed: node.managed === true, importable: node.importable === true,
    options: { security: safeText(node.options && node.options.security || "", 32), sni: safeText(node.options && node.options.sni || "", 253), method: safeText(node.options && node.options.method || "", 64) },
    reason: safeText(node.reason || "", 64),
  }));
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
    if (tls.allowInsecure != null && typeof tls.allowInsecure !== "boolean") fail("invalid_callback", "回调 allowInsecure 必须是布尔值。", 400);
  }
  if (job.action === "machine.import") {
    const expectedTag = "kns-" + job.instanceId;
    if (node.legacyTag !== job.legacyTag || node.tag !== expectedTag || !Array.isArray(node.resources) || node.resources.length !== 1 || node.resources[0].type !== "oneboxInbound" || node.resources[0].id !== expectedTag || node.resources[0].owned !== true || node.resources[0].shared !== false) fail("invalid_callback", "旧节点接管回调的 tag 或资源归属无效。", 400);
  } else if (!Array.isArray(node.resources) || !node.resources.length || !node.resources.every((resource) => resource && resource.owned === true && resource.shared === false)) fail("invalid_callback", "回调资源所有权声明无效。", 400);
  if (!ID_RE.test(node.id) || !PROTOCOLS[node.protocol]) fail("invalid_callback", "回调实例标识或协议无效。", 400);
  return node;
}

function findTask(job) {
  return server.call("admin:getSpecificTaskResult", { task_id: job.taskId, uuid: job.machineUuid });
}

function reservedInstanceOwner(state, instanceId, excludeJobId) {
  const job = (state.jobs || []).find((item) => item.instanceId === instanceId && item.id !== excludeJobId && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
  return job ? job.machineUuid : "";
}

function ensureInstance(state, job, callbackInstance) {
  const existing = state.instances.find((item) => item.id === job.instanceId);
  if (existing && existing.machineUuid !== job.machineUuid) fail("instance_id_conflict", "该实例 ID 已属于另一台探针。", 409);
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
      existing.credential = callbackInstance.credential;
      delete existing.credentialCiphertext;
    }
    existing.enabled = job.action === "enable";
    existing.updatedAt = now();
    if (job.action === "disable") existing.health = Object.assign({}, existing.health, { state: "unverified", reason: "disabled" });
    return;
  }
  const machine = state.machines.find((item) => item.uuid === job.machineUuid);
  if (!machine) fail("machine_missing", "目标探针在 Komari 列表中不存在。", 409);
  if (!callbackInstance) fail("callback_instance_missing", "远端回调实例信息缺失。", 409);
  if (job.action === "machine.import") {
    if (job.callback && job.callback.keyFingerprint && job.callback.keyFingerprint !== masterKeyFingerprint(currentMasterKey())) {
      fail("callback_key_changed", "KNS 主密钥在回调接收后发生变化，无法安全登记回调凭据。", 409);
    }
    if (!callbackInstance.credential || typeof callbackInstance.credential !== "object") fail("callback_credential_missing", "远端回调中的凭据缺失。", 409);
  }
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
  const credential = callbackInstance.credential || null;
  const record = Object.assign(existing || {}, {
    id: callbackInstance.id,
    machineUuid: job.machineUuid,
    name: job.name || (existing && existing.name) || job.legacyTag || callbackInstance.id,
    tags: Array.isArray(job.tags) ? job.tags : existing && existing.tags || [],
    protocol: callbackInstance.protocol,
    runtimeId: job.runtimeId || "onebox-main",
    runtimeEngine: "sing-box",
    listen: { port: callbackInstance.listen.port, transport: callbackInstance.listen.transport, address: job.listenAddress || "::" },
    options: job.options || {},
    tls: callbackInstance.tls || {},
    credential,
    resources: callbackInstance.resources,
    endpoint,
    endpointOverride: job.endpointOverride || existing && existing.endpointOverride || null,
    nat: job.nat || existing && existing.nat || null,
    enabled: true,
    publish: existing ? existing.publish : true,
    health: existing && existing.health || { state: callbackInstance.listen.transport === "udp" ? "unverified" : "unknown", level: "L0", consecutiveFailures: 0, consecutiveSuccesses: 0, lastCheckedAt: "", reason: "awaiting_probe" },
    createdAt: existing && existing.createdAt || now(),
    updatedAt: now(),
    artifactVersion: safeText(job.artifactVersion || "", 80),
  });
  delete record.credentialCiphertext;
  if (job.action === "machine.import") {
    record.managedBy = "onebox";
    record.ownership = "owned";
    record.legacyTag = job.legacyTag;
    record.oneboxTag = callbackInstance.tag || "kns-" + job.instanceId;
    delete record.readOnly;
  }
  if (existing) {
    Object.assign(existing, record);
    delete existing.deletedAt;
    if (existing.remoteStatus && existing.remoteStatus.installed === false) delete existing.remoteStatus;
  } else state.instances.push(record);
  state.runtimes = state.runtimes.filter((runtime) => !(runtime.machineUuid === job.machineUuid && runtime.id === record.runtimeId));
  state.runtimes.push({ machineUuid: job.machineUuid, id: record.runtimeId, engine: "sing-box", state: "shared", updatedAt: now(), references: state.instances.filter((item) => item.machineUuid === job.machineUuid && !item.deletedAt).length });
}

async function pollPendingJobs() {
  if (pollBusy) return;
  pollBusy = true;
  try {
    const stateBeforePoll = getState();
    let recoveredOrphans = false;
    const orphanCutoff = Date.now() - 30 * 60 * 1000;
    for (const job of stateBeforePoll.jobs) {
      if (!job.taskId && ["authorized", "dispatched", "running", "verifying"].includes(job.state) && Date.parse(job.createdAt) < orphanCutoff) {
        job.state = "needs_reconcile";
        job.dispatchUncertain = true;
        job.updatedAt = now();
        job.message = "任务派发结果未知且没有 Komari task ID；请核对探针状态后再操作。系统未自动重发远程命令。";
        closeJob(job);
        recoveredOrphans = true;
      }
    }
    if (recoveredOrphans) save(stateBeforePoll);
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
      if (isRuntimeUpgradeAction(job.action)) {
        const runtimeStatus = validateRuntimeStatus(extractRuntimeStatus(result));
        const machine = state.machines.find((item) => item.uuid === job.machineUuid);
        if (machine && runtimeStatus) { machine.runtimeStatus = runtimeStatus; job.runtimeStatus = runtimeStatus; changed = true; }
        if (code !== 0) {
          const applied = runtimeUpgradeMatches(job, runtimeStatus, job.callback && job.callback.operationResult) || runtimeUpgradeWasApplied(job, runtimeStatus);
          job.state = applied ? "needs_reconcile" : "failed";
          job.updatedAt = now();
          job.message = applied
            ? "目标版本已在机器上出现，但任务/回调未完整确认；请核查 OneBox 状态后再操作。"
            : "OneBox 更新未完成目标版本核验；请查看机器当前版本和服务状态。未将任务标记为成功。";
          closeJob(job); changed = true; continue;
        }
        if (!machine || !runtimeStatus || !job.callback || job.callback.status !== "succeeded" || !runtimeUpgradeMatches(job, runtimeStatus, job.callback.operationResult)) {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "OneBox 更新已执行，但 Agent、一次性回调与版本/服务状态没有全部匹配；请核查任务详情。";
          closeJob(job); changed = true; continue;
        }
        job.state = "succeeded"; job.updatedAt = now();
        job.message = job.action === "runtime.script.update"
          ? "OneBox 管理脚本已固定校验并更新；现有节点配置未修改。"
          : "sing-box 内核已更新并核验；共享服务状态保持原样。";
        closeJob(job); changed = true;
        audit(state, null, "runtime.upgrade.succeeded", { jobId: job.id, action: job.action, machineUuid: job.machineUuid, previousVersion: job.callback.operationResult.previousVersion || "", version: job.callback.operationResult.version || job.callback.operationResult.singBoxVersion || "" });
        continue;
      }
      if (code !== 0) {
        const outputText = taskText(result);
        const resourceLimit = outputText.match(/(?:KNS_RESOURCE=|"code"\s*:\s*")(low_pid_headroom|low_memory_headroom)/);
        const scanFailure = job.action === "machine.discover" && outputText.match(/(?:^|\n)KNS_SCAN_ERROR=(not_root|missing_sha256sum|missing_bash|missing_jq|config_missing|temp_file|download_failed|missing_downloader|checksum_failed|discover_failed|runtime_failed)(?:\r?\n|$)/);
        const scanMessages = { not_root: "Komari Agent 未以 root 运行。", missing_sha256sum: "机器缺少 sha256sum，无法校验 OneBox 脚本。", missing_bash: "机器缺少 bash，无法运行 OneBox 扫描。", missing_jq: "机器缺少 jq，无法读取 OneBox 配置。", config_missing: "未找到 /etc/onebox/config.json；这台机器可能尚未安装 OneBox。", temp_file: "无法创建临时文件，请检查临时目录与磁盘空间。", download_failed: "无法下载 OneBox 扫描脚本，请检查机器访问 GitHub 的网络和 DNS。", missing_downloader: "机器缺少 curl 或 wget，无法下载 OneBox 扫描脚本。", checksum_failed: "下载的 OneBox 脚本校验失败，请检查网络或代理。", discover_failed: "OneBox 读取节点配置失败，请检查机器上的 OneBox 配置及依赖。", runtime_failed: "OneBox 运行状态读取失败，请检查机器上的 OneBox 环境及依赖。" };
        const bootstrapBlocked = outputText.match(/(?:^|\n)KNS_BOOTSTRAP_BLOCKED=(existing_state|invalid_config)(?:\r?\n|$)/);
        const bootstrapFailure = outputText.match(/(?:^|\n)KNS_BOOTSTRAP_FAILED=(\d{1,3})(?:\r?\n|$)/);
        const bootstrapCompleted = /^KNS_BOOTSTRAP=completed$/m.test(outputText);
        const oneboxErrorCode = extractOneboxErrorCode(result, job);
        job.state = "failed"; job.updatedAt = now(); job.message = resourceLimit
          ? (resourceLimit[1] === "low_pid_headroom" ? "探针剩余进程额度不足；OneBox 已跳过操作，请释放或提高 pids 限额后重试。" : "探针可用内存不足；OneBox 已跳过操作，请释放或提高内存限额后重试。")
          : /remote control is disabled\.?/i.test(outputText)
            ? "Komari Agent 的远程控制未启用；请检查该机器的 Agent 配置。"
          : scanFailure
            ? scanMessages[scanFailure[1]]
          : bootstrapBlocked
            ? (bootstrapBlocked[1] === "existing_state" ? "检测到 OneBox 主配置缺失，但仍有旧数据或服务文件；为保护现场，自动初始化已停止。请先恢复 OneBox 配置。" : "OneBox 主配置路径异常或格式无效；自动初始化已停止，未覆盖现有配置。请检查配置路径和文件结构后重试。")
            : bootstrapFailure
            ? "OneBox 基础环境初始化失败（退出码 " + bootstrapFailure[1] + "），节点安装未继续。请检查目标机系统、依赖和网络。原始输出未保存在 KNS。"
            : oneboxErrorCode
              ? (bootstrapCompleted ? "OneBox 基础环境已就绪，但节点安装失败：" : "节点安装失败：") + safeOneboxErrorMessage(oneboxErrorCode) + "原始输出未保存在 KNS。"
              : code === -1 ? "Komari Agent 返回退出码 -1；请检查远程控制是否启用及 Agent 日志。敏感输出未保存在 KNS。" : "远程任务退出码 " + code + "。敏感输出未保存在 KNS。";
        closeJob(job); changed = true; continue;
      }
      const status = extractStatus(result);
      if (job.action === "machine.discover") {
        const discovered = validateDiscovery(job, extractDiscovery(result));
        const runtimeStatus = validateRuntimeStatus(extractRuntimeStatus(result));
        const machine = state.machines.find((item) => item.uuid === job.machineUuid);
        if (!discovered || !runtimeStatus || !machine) {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "远端发现结果格式无效，未保存节点信息。"; changed = true; continue;
        }
        machine.discoveredNodes = discovered;
        machine.discoveredAt = now();
        machine.runtimeStatus = runtimeStatus;
        job.state = "succeeded"; job.updatedAt = now(); job.message = "只读扫描完成，发现 " + discovered.length + " 个 OneBox 入站；可导入的节点需要管理员逐个确认。"; closeJob(job); changed = true;
        audit(state, null, "machine.legacy_discovery.completed", { jobId: job.id, machineUuid: job.machineUuid, discoveredCount: discovered.length, importableCount: discovered.filter((node) => node.importable).length });
        continue;
      }
      if (job.action === "machine.import") {
        const discovered = validateDiscovery(job, extractDiscovery(result));
        const runtimeStatus = validateRuntimeStatus(extractRuntimeStatus(result));
        const expectedTag = "kns-" + job.instanceId;
        const candidate = discovered && discovered.find((node) => node.tag === expectedTag && node.managed && node.protocol === job.protocol && node.listen.port === job.listenPort && node.listen.transport === job.listenTransport);
        const oldTagRemains = discovered && discovered.some((node) => node.tag === job.legacyTag);
        const machine = state.machines.find((item) => item.uuid === job.machineUuid);
        if (!candidate || oldTagRemains || !runtimeStatus || !machine || !job.callback || job.callback.status !== "succeeded") {
          job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "旧节点接管未完成双重核验；请检查 OneBox 配置和节点 tag。"; closeJob(job); changed = true; continue;
        }
        try {
          const callbackInstance = job.action === "machine.import" && callbackCiphertextMatchesCurrentKey(job)
            ? job.callback.instance
            : resolveCallbackNode(job);
          ensureInstance(state, job, callbackInstance);
        }
        catch (error) {
          job.updatedAt = now();
          const errorType = error && typeof error.name === "string" ? safeText(error.name, 24).toLowerCase().replace(/[^a-z0-9_-]/g, "") : "";
          job.pollErrorCode = error && error.code ? safeText(error.code, 32) : (errorType ? "verification_" + errorType : "verification_error");
          job.state = error && error.code === "endpoint_missing" ? "verifying" : "needs_reconcile";
          job.message = error && error.code === "endpoint_missing" ? "旧节点凭据已安全接收；请先设置可用 Endpoint 后重试核验。" : "旧节点回调已收到，但本地登记核对失败；需要管理员复核。";
          if (job.state !== "verifying") closeJob(job);
          changed = true; continue;
        }
        machine.runtimeStatus = runtimeStatus;
        job.state = "succeeded"; job.updatedAt = now(); job.message = "旧节点已接管；现可在 KNS 中重配置、启停、重装或卸载。"; closeJob(job); changed = true;
        audit(state, null, "instance.legacy_claim.completed", { jobId: job.id, machineUuid: job.machineUuid, instanceId: job.instanceId, legacyTag: job.legacyTag });
        continue;
      }
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
            const checkedAt = now();
            const uninstallPreview = { complete: preview.complete === true, serviceImpact: safeText(preview.serviceImpact || "unknown", 40) };
            uninstallPreview.version = crypto.createHash("sha256").update(JSON.stringify({ machineUuid: job.machineUuid, instanceId: instance.id, checkedAt, resources, uninstallPreview })).digest("hex");
            instance.remoteStatus = { installed: status.instance.installed === true, enabled: status.instance.enabled === true, serviceState: status.instance.serviceState || "unknown", healthLevel: status.instance.healthLevel || "L0", checkedAt, installState: status.instance.installState || "unknown", resources, uninstallPreview };
            if (status.instance.installed === true) instance.enabled = status.instance.enabled !== false;
          } else {
            const absent = Array.isArray(status.instances) && status.instances.find((item) => item.id === job.instanceId && item.installed === false);
            if (!absent) { job.state = "needs_reconcile"; job.updatedAt = now(); job.message = "OneBox 未返回该实例的可识别状态。"; changed = true; continue; }
            instance.remoteStatus = { installed: false, enabled: false, serviceState: "unknown", healthLevel: "L0", checkedAt: now(), installState: "not_installed" };
            instance.updatedAt = now();
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
        const bootstrapped = job.action === "install" && /^KNS_BOOTSTRAP=completed$/m.test(taskText(result));
        job.state = "succeeded"; job.updatedAt = now(); job.message = job.action === "uninstall" ? "已验证实例已卸载。" : bootstrapped ? "OneBox 基础环境已初始化；节点安装和远端核查均完成。" : "回调和远程实例状态均已验证。"; closeJob(job); changed = true;
        audit(state, null, "job.succeeded", { jobId: job.id, action: job.action, machineUuid: job.machineUuid, instanceId: job.instanceId });
    }
    for (const job of state.jobs.filter((item) => item.autoProvision === true)) {
      const machine = state.machines.find((item) => item.uuid === job.machineUuid);
      if (!machine || !machine.autoProvision || machine.autoProvision.jobId !== job.id) continue;
      const nextState = job.state === "succeeded" ? "succeeded" : ["failed", "timed_out", "needs_reconcile", "cancelled"].includes(job.state) ? "failed" : "installing";
      if (machine.autoProvision.state !== nextState || machine.autoProvision.message !== job.message) {
        machine.autoProvision.state = nextState;
        machine.autoProvision.updatedAt = job.updatedAt || now();
        machine.autoProvision.message = job.message || (nextState === "succeeded" ? "默认节点已部署并登记。" : "自动部署需要检查任务结果。");
        changed = true;
      }
    }
    if (changed) save(state);
    if (state.machines.some((machine) => !machine.removedFromKomariAt && machine.autoProvision && machine.autoProvision.state === "queued")) setTimeout(dispatchAutoProvisionQueue, 0);
  } finally { pollBusy = false; }
}

function createJob(state, req, action, machine, spec, existingInstance) {
  if (action === "install" && !existingInstance) {
    const instanceId = String(spec.id || "");
    const owner = (state.instances || []).find((item) => item.id === instanceId) || null;
    const reservedOwner = reservedInstanceOwner(state, instanceId);
    if (owner && owner.machineUuid !== machine.uuid || reservedOwner && reservedOwner !== machine.uuid) fail("instance_id_conflict", "该实例 ID 已属于或保留给另一台探针。", 409);
  }
  const twoFactor = checkTwoFactor(spec.twoFactorCode);
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
    runtimeId: instance.runtimeId || "onebox-main", options: instance.options || {}, name: instance.name, tags: instance.tags || [], legacyTag: spec.legacyTag || "",
    endpointOverride: spec.endpointOverride || instance.endpointOverride || null, nat: spec.nat || instance.nat || null,
    idempotencyKey, callbackTokenSalt: tokenRecord.salt, callbackTokenHash: tokenRecord.hash, _callbackToken: token,
    callback: null, taskId: "", createdAt: now(), updatedAt: now(), actor: safeText(((req.context || {}).principal || {}).username || "admin", 80),
    message: "任务已授权，正在发送到探针。",
  };
  job.retrySpec = {
    machineUuid: machine.uuid, instanceId: instance.id, protocol: instance.protocol,
    listenPort: instance.listen.port, listenAddress: instance.listen.address, listenTransport: instance.listen.transport,
    options: instance.options || {}, name: instance.name, tags: instance.tags || [], action, legacyTag: spec.legacyTag || "",
    endpointOverride: spec.endpointOverride || instance.endpointOverride || null, nat: spec.nat || instance.nat || null,
  };
  job.requestHash = String(spec.requestHash || "");
  state.jobs.push(job);
  const command = makeRemoteCommand(state, job, instance);
  const params = { command, clients: [machine.uuid] };
  if (twoFactor) params["2fa_code"] = twoFactor;
  delete job._callbackToken;
  return { job, instance, params };
}

function createRuntimeUpgradeJob(state, req, action, machine, spec) {
  const twoFactor = checkTwoFactor(spec.twoFactorCode);
  const token = secrets.createToken();
  const tokenRecord = secrets.tokenRecord(token);
  const job = {
    id: randomId("job"), action, state: "authorized", machineUuid: machine.uuid, machineName: machine.name,
    instanceId: "", protocol: "runtime", runtimeId: "onebox-main", idempotencyKey: safeText(spec.idempotencyKey, 256),
    requestedVersion: action === "runtime.kernel.update" ? "latest" : "", expectedScriptSha256: action === "runtime.script.update" ? INSTALLER_SHA256 : "",
    expectedScriptVersion: action === "runtime.script.update" ? ONEBOX_SCRIPT_VERSION : "", previousRuntimeStatus: machine.runtimeStatus || null,
    callbackTokenSalt: tokenRecord.salt, callbackTokenHash: tokenRecord.hash, _callbackToken: token,
    callback: null, taskId: "", createdAt: now(), updatedAt: now(), actor: safeText(((req.context || {}).principal || {}).username || "admin", 80),
    message: "运行时升级已授权，正在发送到 Komari Agent。", requestHash: spec.requestHash,
  };
  state.jobs.push(job);
  const params = { command: makeRemoteCommand(state, job, null), clients: [machine.uuid] };
  if (twoFactor) params["2fa_code"] = twoFactor;
  delete job._callbackToken;
  return { job, params };
}

async function dispatchJob(state, job, params) {
  try {
    const result = await server.call("admin:exec", params);
    job.taskId = String(result && (result.task_id || result.taskId) || "");
    if (!job.taskId) { job.state = "needs_reconcile"; job.dispatchUncertain = true; job.message = "Komari 未返回任务编号，无法确认命令是否送达。请先核查机器状态，确认处理后再执行其他变更。"; }
    else { job.state = "dispatched"; job.message = "已发送到 Komari Agent，等待执行与回调验证。"; }
  } catch (error) {
    const code = error && error.code != null ? safeText(error.code, 32) : "rpc_error";
    job.rpcErrorCode = code;
    const rejected = ["-32040", "-32041"].includes(code);
    job.state = rejected ? "failed" : "needs_reconcile";
    if (!rejected) job.dispatchUncertain = true;
    job.message = code === "-32040" ? "Komari 拒绝远程命令：需要管理员重新认证。" : code === "-32041" ? "Komari 拒绝远程命令：权限不足或远程控制未启用。" : "Komari 未确认远程命令是否送达（" + code + "）。请先核查机器状态，确认处理后再执行其他变更。";
  }
  job.updatedAt = now();
}

async function finishDispatch(job, params) {
  let latest = getState();
  let current = latest.jobs.find((item) => item.id === job.id);
  if (!current) fail("job_lost", "任务记录在远程提交期间消失，请检查状态备份。", 500);
  if (current.state === "cancelled") return current;
  let presence;
  try { presence = onlineStatusMap(await server.call("common:getNodesLatestStatus", { uuids: [job.machineUuid] })); }
  catch (_) { presence = null; }
  latest = getState();
  current = latest.jobs.find((item) => item.id === job.id);
  if (!current) fail("job_lost", "任务记录在远程提交期间消失，请检查状态备份。", 500);
  if (current.state === "cancelled") return current;
  const machine = latest.machines.find((item) => item.uuid === job.machineUuid && !item.removedFromKomariAt);
  if (!machine || !presence || presence.get(job.machineUuid) !== true) {
    current.state = machine ? "failed" : "cancelled";
    current.updatedAt = now();
    current.message = !machine ? "机器已从 Komari 删除，未发送远程命令。" : presence && presence.get(job.machineUuid) === false ? "机器当前离线，未发送远程命令。" : "无法确认机器在线状态，未发送远程命令。";
    closeJob(current); save(latest); return current;
  }
  await dispatchJob(null, job, params);
  latest = getState();
  current = latest.jobs.find((item) => item.id === job.id);
  if (!current) fail("job_lost", "任务记录在远程提交期间消失，请检查状态备份。", 500);
  if (current.state === "cancelled") return current;
  if (current.callback) {
    current.taskId = job.taskId || current.taskId;
    if (job.dispatchUncertain && !current.taskId) {
      current.dispatchUncertain = true;
      current.state = "needs_reconcile";
      current.updatedAt = job.updatedAt;
      current.message = "已收到回调，但 Komari 未返回任务编号，无法完成双重核验。请核查机器状态并确认处理。";
    }
  } else for (const field of ["taskId", "state", "updatedAt", "message", "rpcErrorCode", "dispatchUncertain"]) current[field] = job[field];
  save(latest);
  return current;
}

function unconfirmedDispatch(state, machineUuid) {
  return state.jobs.find((job) => job.machineUuid === machineUuid && job.dispatchUncertain && !["machine.discover", "instance.status"].includes(job.action) && !["succeeded", "cancelled"].includes(job.state) && !(job.attentionAcknowledgedAt && job.attentionAcknowledgedState === job.state));
}

function requireConfirmedDispatch(state, machineUuid) {
  if (unconfirmedDispatch(state, machineUuid)) fail("dispatch_unconfirmed", "之前的远程命令可能已经送达。请先只读核查机器，在工作台确认处理后再执行变更。", 409);
}

function machineByUuid(state, uuid) {
  const machine = state.machines.find((item) => item.uuid === uuid);
  if (!machine) fail("machine_not_found", "Komari 中不存在这台探针。", 404);
  if (machine.removedFromKomariAt) fail("machine_removed", "这台机器已从 Komari 删除，远程操作已停用；重新接入 Komari 后可恢复管理。", 409);
  return machine;
}

function requirePolicy(machine) {
  if (!machine.policy || machine.policy.deployAllowed !== true) fail("deployment_not_allowed", "此探针已关闭远程安装。请先在机器卡片中重新启用。", 403);
}

function installAction(body) { return ["install", "reconfigure", "reinstall", "uninstall", "enable", "disable"].includes(String(body.action || "")); }

async function handleAction(req, res) {
  checkOrigin(req);
  const body = readBody(req, 16 * 1024 * 1024);
  const action = String(body.action || "");
  if (action !== "backup.inspect" && Buffer.byteLength(String(req.body || ""), "utf8") > 1024 * 1024) fail("body_too_large", "请求正文超过允许大小。", 413);
  const state = getState();
  if (maintenanceLock && !(action === "plugin.update.unlock" && pluginUpdateLockToken)) fail("maintenance_in_progress", "KNS 正在执行互斥设置或数据维护；请稍后重试。", 409);
  // Remote jobs validate current targets and resources; their request is not an edit of the whole state.
  const currentStateActions = ["install", "install.batch", "uninstall", "enable", "disable", "instance.status", "machine.discover", "runtime.script.update", "runtime.kernel.update", "job.retry", "autoProvision.retry", "machine.sync", "profile.create", "profile.preview", "profile.token.show", "attention.acknowledge", "plugin.update.check", "plugin.update.prepare", "plugin.update.unlock"];
  if (body.expectedEditVersion != null) {
    const currentVersion = actionEditVersion(state, body);
    if (!currentVersion || typeof body.expectedEditVersion !== "string" || body.expectedEditVersion !== currentVersion) fail("state_revision_conflict", "当前编辑的设置已被其他操作修改。草稿已保留，请核对后再保存。", 409);
  } else if (!currentStateActions.includes(action)) assertExpectedRevision(state.revision, body);
  if (state.settings.setupComplete !== true && !["setup.complete", "backup.export", "backup.inspect", "backup.restore.preview", "profile.preview", "plugin.update.check", "plugin.update.prepare", "plugin.update.unlock"].includes(action)) {
    fail("setup_required", "请先完成连接设置；未初始化期间管理页面为只读。", 409);
  }
  if (action === "attention.acknowledge") {
    if (body.kind === "job") {
      const job = state.jobs.find((item) => item.id === String(body.jobId || ""));
      if (!job || !["failed", "needs_reconcile", "timed_out"].includes(job.state) || job.state !== body.expectedState) fail("attention_changed", "任务状态已变化，请刷新后重新查看。", 409);
      if (!job.attentionAcknowledgedAt || job.attentionAcknowledgedState !== job.state) {
        job.attentionAcknowledgedAt = now();
        job.attentionAcknowledgedState = job.state;
        audit(state, req, "attention.job.acknowledged", { jobId: job.id, machineUuid: job.machineUuid, state: job.state });
        save(state);
      }
      return json(res, 200, { ok: true, acknowledgedAt: job.attentionAcknowledgedAt });
    }
    if (body.kind === "health") {
      const instance = state.instances.find((item) => item.id === String(body.instanceId || "") && !item.deletedAt);
      const health = instance && instance.health;
      const incident = health && (health.attentionIncidentId || "legacy");
      if (!health || health.state !== "unhealthy" || body.incidentId !== incident) fail("attention_changed", "节点检测状态已变化，请刷新后重新查看。", 409);
      if (health.attentionAcknowledgedIncidentId !== incident) {
        health.attentionIncidentId = incident;
        health.attentionAcknowledgedIncidentId = incident;
        health.attentionAcknowledgedAt = now();
        audit(state, req, "attention.health.acknowledged", { instanceId: instance.id, machineUuid: instance.machineUuid, incidentId: incident });
        save(state);
      }
      return json(res, 200, { ok: true, acknowledgedAt: health.attentionAcknowledgedAt });
    }
    fail("invalid_attention_kind", "待处理事项类型无效。", 400);
  }
  if (action === "plugin.update.prepare") {
    assertNoActiveJobs(state, "更新插件");
    if (autoProvisionBusy) fail("active_jobs_block_maintenance", "自动部署队列正在处理，请稍后再更新。", 409);
    maintenanceLock = true;
    pluginUpdateLockToken = randomId("update");
    const token = pluginUpdateLockToken;
    pluginUpdateLockTimer = setTimeout(() => {
      if (pluginUpdateLockToken !== token) return;
      pluginUpdateLockToken = ""; pluginUpdateLockTimer = null; maintenanceLock = false;
      setTimeout(dispatchAutoProvisionQueue, 0);
    }, 5 * 60 * 1000);
    return json(res, 200, { ok: true, token });
  }
  if (action === "plugin.update.unlock") {
    if (!pluginUpdateLockToken || body.token !== pluginUpdateLockToken) fail("invalid_update_lock", "更新锁无效或已过期。", 409);
    if (pluginUpdateLockTimer) clearTimeout(pluginUpdateLockTimer);
    pluginUpdateLockTimer = null; pluginUpdateLockToken = ""; maintenanceLock = false;
    setTimeout(dispatchAutoProvisionQueue, 0);
    return json(res, 200, { ok: true });
  }
  if (action === "plugin.update.check") {
    const current = String(PLUGIN_VERSION || "");
    let latest = "";
    let latestUrl = "";
    let publishedAt = "";
    try {
      const controller = typeof AbortController === "function" ? new AbortController() : null;
      const timer = controller ? setTimeout(() => controller.abort(), 8000) : null;
      const response = await fetch("https://api.github.com/repos/liuarui/komari-plugin-kns/releases/latest", {
        headers: { accept: "application/vnd.github+json", "user-agent": "komari-plugin-kns/" + current },
        signal: controller && controller.signal,
      });
      if (timer) clearTimeout(timer);
      if (!response || !response.ok) fail("update_check_failed", "无法检查更新：GitHub 返回 HTTP " + (response && response.status || "未知") + "。", 502);
      const payload = await response.json();
      latest = String(payload.tag_name || payload.name || "").replace(/^v/i, "");
      latestUrl = String(payload.html_url || "https://github.com/liuarui/komari-plugin-kns/releases");
      publishedAt = String(payload.published_at || "");
      if (!latest) fail("update_check_failed", "无法检查更新：GitHub 未返回有效版本号。", 502);
    } catch (error) {
      if (error && error.status) throw error;
      fail("update_check_failed", "无法检查更新：" + safeText(error && error.message || error, 160), 502);
    }
    let updateAvailable;
    try { updateAvailable = compareSemver(latest, current) > 0; }
    catch (_) { fail("update_check_failed", "无法检查更新：GitHub 返回的版本号无法按 SemVer 比较。", 502); }
    return json(res, 200, { ok: true, currentVersion: current, latestVersion: latest, updateAvailable, sourceUrl: SOURCE_URL, latestUrl, publishedAt, checkedAt: now() });
  }
  if (action === "setup.complete") {
    if (state.settings.setupComplete === true) return json(res, 200, { ok: true, alreadyComplete: true });
    const base = String(body.publicBaseUrl || "").trim().replace(/\/$/, "");
    let parsed;
    try { parsed = new URLConstructor(base); } catch (_) { fail("invalid_public_url", "Komari 公网地址必须是 HTTPS URL。", 400); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) fail("invalid_public_url", "KNS 回调需要不含账号、查询和片段的 HTTPS 地址。", 400);
    const defaultNode = normalizeDefaultNode(body.defaultNode, state.settings.defaultNode);
    if (body.autoProvisionNewProbes === true && body.confirmAutoProvision !== true) fail("auto_provision_confirmation_required", "开启新探针自动部署需要明确确认 root 安装影响。", 400);
    maintenanceLock = true;
    try {
      let synced;
      try { synced = await syncMachines(); }
      catch (_) { fail("probe_sync_required", "暂时无法同步 Komari 探针。请稍后重试，避免把已有探针误判为新探针。", 503); }
      if (!synced) fail("probe_sync_busy", "探针同步正在进行；请稍后重试完成初始化。", 409);
      const fresh = getState();
      if (fresh.settings.setupComplete === true) return json(res, 200, { ok: true, alreadyComplete: true });
      fresh.settings.publicBaseUrl = parsed.origin + parsed.pathname.replace(/\/$/, "");
      fresh.settings.defaultNode = Object.assign({}, defaultNode, { updatedAt: now() });
      fresh.settings.autoProvisionNewProbes = body.autoProvisionNewProbes === true;
      fresh.settings.autoProvisionBaselineUuids = Array.from(new Set(fresh.machines.map((machine) => machine.uuid)));
      fresh.settings.setupComplete = true;
      let profile = fresh.profiles.find((item) => item.autoManagedDefault === true && !item.revokedAt);
      if (!profile) {
        profile = {
          id: randomId("profile"), name: "KNS 默认订阅", createdAt: now(), expiresAt: "", revokedAt: "",
          formats: ["uri", "mihomo-full"], instanceIds: null, machineUuids: null, excludeMachineUuids: [],
          protocols: null, includeTags: [], excludeUnhealthy: true, addressMode: "auto", sortBy: "name", autoManagedDefault: true, tokenRequired: true, tokens: [],
        };
        fresh.profiles.push(profile);
      }
      const token = secrets.createToken();
      const tokenRecord = replaceProfileToken(profile, token, profile.expiresAt || "");
      audit(fresh, req, "setup.completed", { profileId: profile.id, tokenId: tokenRecord.id, defaultNode, autoProvisionNewProbes: fresh.settings.autoProvisionNewProbes, baselineMachineCount: fresh.settings.autoProvisionBaselineUuids.length });
      save(fresh);
      return json(res, 200, Object.assign({ ok: true, baselineMachineCount: fresh.settings.autoProvisionBaselineUuids.length, profile: { id: profile.id, name: profile.name }, tokenId: tokenRecord.id }, buildProfileTokenLinks(fresh, profile, token)));
    } finally { maintenanceLock = false; }
  }
  if (action === "machine.sync") {
    const synced = await syncMachines();
    if (!synced) fail("probe_sync_busy", "探针同步正在进行；请稍后重试。", 409);
    return json(res, 200, { ok: true, revision: getState().revision });
  }
  if (action === "settings.defaults.update") {
    if (body.autoProvisionNewProbes === true && !state.settings.autoProvisionNewProbes && body.confirmAutoProvision !== true) fail("auto_provision_confirmation_required", "开启新探针自动部署需要明确确认 root 安装影响。", 400);
    const previous = normalizeDefaultNode({}, state.settings.defaultNode);
    const next = normalizeDefaultNode(body.defaultNode, previous);
    if (next.protocol !== previous.protocol || next.listenPort !== previous.listenPort || next.listenAddress !== previous.listenAddress) next.version = previous.version + 1;
    next.updatedAt = now();
    state.settings.defaultNode = next;
    if (typeof body.autoProvisionNewProbes === "boolean") {
      state.settings.autoProvisionNewProbes = body.autoProvisionNewProbes;
      if (!body.autoProvisionNewProbes) for (const machine of state.machines) {
        if (machine.autoProvision && machine.autoProvision.state === "queued") {
          machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "cancelled", updatedAt: now(), message: "已停止新自动部署队列；已派发任务继续执行。" });
        }
      }
    }
    audit(state, req, "settings.default_node.updated", { defaultNode: next, autoProvisionNewProbes: state.settings.autoProvisionNewProbes });
    save(state); return json(res, 200, { ok: true, settings: publicState(state).settings });
  }
  if (action === "autoProvision.retry") {
    if (body.confirm !== true) fail("confirmation_required", "重新尝试自动部署需要显式确认。", 400);
    if (!state.settings.autoProvisionNewProbes) fail("auto_provision_disabled", "当前已关闭新探针自动部署。", 409);
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    if (!machine.autoProvision || machine.autoProvision.state !== "failed") fail("auto_provision_not_retryable", "当前自动部署状态不能直接重试。", 409);
    const reservedId = "autov1-" + machine.uuid.replace(/-/g, "");
    if (state.instances.some((instance) => instance.id === reservedId && instance.machineUuid === machine.uuid && !instance.deletedAt)) fail("auto_provision_instance_exists", "默认节点已登记，请从节点页执行状态核查。", 409);
    if (machine.online !== true) fail("machine_offline", "探针当前不在线，无法重新提交自动部署。", 409);
    requireConfirmedDispatch(state, machine.uuid);
    if (state.jobs.some((job) => job.machineUuid === machine.uuid && ["authorized", "dispatched", "running", "verifying"].includes(job.state))) fail("runtime_busy", "该探针仍有远程任务进行中。", 409);
    machine.policy = Object.assign({}, machine.policy || {}, { deployAllowed: true });
    machine.autoProvision = Object.assign({}, machine.autoProvision, { state: "queued", updatedAt: now(), message: "管理员请求重新尝试默认部署。" });
    audit(state, req, "auto_provision.retry", { machineUuid: machine.uuid, templateVersion: state.settings.defaultNode.version || 1 });
    save(state); setTimeout(dispatchAutoProvisionQueue, 0);
    return json(res, 200, { ok: true, machine: safeMachine(machine) });
  }
  if (action === "job.retry") {
    if (body.confirm !== true) fail("confirmation_required", "重试远程任务需要明确确认。", 400);
    const failed = state.jobs.find((job) => job.id === String(body.jobId || ""));
    if (!failed) fail("job_not_found", "找不到要重试的任务。", 404);
    const retryKey = safeText(body.idempotencyKey || "", 256);
    if (!retryKey) fail("idempotency_key_required", "重试请求需要唯一幂等键。", 400);
    const retry = state.jobs.find((job) => job.retryOfJobId === failed.id);
    if (retry) {
      if (retry.retryIdempotencyKey !== retryKey) fail("idempotency_conflict", "此失败任务已使用其他幂等键重试；请检查已创建的重试任务。", 409);
      return json(res, 200, { ok: !["failed", "cancelled"].includes(retry.state), reused: true, job: Object.assign(safeJob(retry), { canRetry: jobRetryable(state, retry) }) });
    }
    if (!jobRetryable(state, failed)) fail("job_not_retryable", "该任务可能已到达探针，不能安全自动重试；请先核对机器状态。", 409);
    const machine = machineByUuid(state, failed.machineUuid);
    requireConfirmedDispatch(state, machine.uuid);
    if (machine.online !== true) fail("machine_offline", "探针当前不在线，无法重试。", 409);
    requirePolicy(machine);
    if (state.jobs.some((job) => job.machineUuid === machine.uuid && job.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(job.state))) fail("runtime_busy", "该探针的共享 OneBox Runtime 仍有未完成任务。", 409);
    const priorSpec = failed.retrySpec;
    const existingInstance = state.instances.find((instance) => instance.id === failed.instanceId && instance.machineUuid === machine.uuid && !instance.deletedAt);
    if (failed.action !== "install" && !existingInstance) fail("instance_not_found", "目标实例已不存在，不能重试原任务。", 409);
    if (failed.action === "install" && existingInstance) fail("instance_exists", "该节点已登记，请先核查远端状态，不会重复安装。", 409);
    const validated = validateProtocolSettings({ protocol: priorSpec.protocol, listenPort: priorSpec.listenPort, listenAddress: priorSpec.listenAddress, options: priorSpec.options });
    if (portConflicts(state, machine.uuid, validated.port, validated.transport, failed.instanceId, validated.listenAddress)) fail("port_conflict", "原任务端口现已被其他节点占用；请核对机器状态后重新配置。", 409);
    let retryNat = priorSpec.nat ? deepClone(priorSpec.nat) : null;
    if (retryNat) {
      retryNat.externalPort = validatePort(retryNat.externalPort);
      const endpoint = candidateAddress(machine, state, {
        listen: { port: validated.port, address: validated.listenAddress, transport: validated.transport },
        endpointOverride: priorSpec.endpointOverride || null,
        nat: retryNat,
      });
      if (!endpoint) fail("nat_endpoint_missing", "NAT 地址已不可用；请重新配置公网 Endpoint 后再尝试。", 409);
      if (natMappingConflicts(state, retryNat.externalPort, validated.transport, endpointPublicHosts(endpoint), failed.instanceId)) fail("nat_mapping_conflict", "原 NAT 映射现已与其他节点冲突；请核对公网地址后重新配置。", 409);
      retryNat.publicHost = endpoint.host;
      retryNat.publicHosts = endpointPublicHosts(endpoint);
    }
    const spec = {
      id: failed.instanceId, protocol: validated.protocol, port: validated.port, listenAddress: validated.listenAddress,
      transport: validated.transport, options: validated.options, name: priorSpec.name, tags: priorSpec.tags, legacyTag: priorSpec.legacyTag || failed.legacyTag || "",
      endpointOverride: priorSpec.endpointOverride, nat: retryNat, idempotencyKey: retryKey,
      requestHash: failed.requestHash, twoFactorCode: body.twoFactorCode,
    };
    const retryInstance = existingInstance ? Object.assign({}, existingInstance, {
      protocol: validated.protocol,
      listen: { port: validated.port, address: validated.listenAddress, transport: validated.transport },
      options: validated.options, name: priorSpec.name, tags: priorSpec.tags || [],
      endpointOverride: priorSpec.endpointOverride || null, nat: retryNat,
    }) : null;
    const { job, params } = createJob(state, req, failed.action, machine, spec, retryInstance);
    job.retryOfJobId = failed.id;
    job.retryCount = Number(failed.retryCount || 0) + 1;
    job.retryIdempotencyKey = retryKey;
    audit(state, req, "job.retry.authorized", { jobId: job.id, retryOfJobId: failed.id, machineUuid: machine.uuid, action: job.action });
    save(state);
    const submitted = await finishDispatch(job, params);
    return json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: Object.assign(safeJob(submitted), { canRetry: jobRetryable(getState(), submitted) }) });
  }
  if (action === "install.batch") {
    if (body.confirm !== true) fail("confirmation_required", "批量部署需要明确确认。", 400);
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先完成 Komari HTTPS 公网地址设置。", 409);
    const uuids = Array.from(new Set((Array.isArray(body.machineUuids) ? body.machineUuids : []).map((uuid) => String(uuid || "").toLowerCase()).filter(Boolean)));
    const maxBatch = Math.max(1, Math.min(10, Number(state.settings.maxBatch) || 10));
    if (!uuids.length || uuids.length > maxBatch) fail("invalid_batch_size", "批量部署机器数量必须在 1 至 " + maxBatch + " 台之间。", 400);
    const batchId = safeText(body.batchId || "", 128);
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(batchId)) fail("invalid_batch_id", "批量部署请求标识无效。", 400);
    if (typeof body.twoFactorCode === "string" && body.twoFactorCode.length > 32) fail("invalid_two_factor", "2FA 验证码格式无效。", 400);
    const validated = validateProtocolSettings(body);
    const tags = Array.isArray(body.tags) ? Array.from(new Set(body.tags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [];
    const endpointOverride = makeEndpointOverride(body.endpointHost, body.endpointPort, !!state.settings.privateSite);
    const externalPort = body.externalPort ? validatePort(body.externalPort) : 0;
    const requestSpecs = [];
    const results = [];
    for (const machineUuid of uuids) {
      const key = batchId + ":" + machineUuid;
      const machine = state.machines.find((item) => item.uuid === machineUuid);
      try {
        if (!machine) fail("machine_not_found", "Komari 中不存在这台探针。", 404);
        if (machine.removedFromKomariAt) fail("machine_removed", "这台机器已从 Komari 删除，不能再提交远程安装。", 409);
        if (machine.online !== true) fail("machine_offline", "探针当前离线或状态未知。", 409);
        requirePolicy(machine);
        const requestHash = crypto.createHash("sha256").update(JSON.stringify({ action: "install", machineUuid, instanceId: "", protocol: validated.protocol, port: validated.port, transport: validated.transport, options: validated.options, listenAddress: validated.listenAddress, endpointHost: body.endpointHost || "", endpointPort: body.endpointPort || 0, externalPort })).digest("hex");
        const prior = state.jobs.find((job) => job.action === "install" && job.machineUuid === machineUuid && job.idempotencyKey === key);
        if (prior) {
          if (prior.requestHash !== requestHash) fail("idempotency_conflict", "同一批量请求标识已用于不同的部署参数。", 409);
          results.push({ machineUuid, reused: true, accepted: !["failed", "cancelled"].includes(prior.state), job: safeJob(prior) });
          continue;
        }
        requireConfirmedDispatch(state, machineUuid);
        if (state.jobs.some((job) => job.machineUuid === machineUuid && job.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(job.state))) fail("runtime_busy", "该探针的共享 OneBox Runtime 仍有未完成任务。", 409);
        const instanceId = randomId("kns");
        if (portConflicts(state, machineUuid, validated.port, validated.transport, instanceId, validated.listenAddress)) fail("port_conflict", "该机器已有节点占用相同监听地址、端口和传输类型。", 409);
        const nat = externalPort ? { externalPort } : null;
        const instance = { id: instanceId, machineUuid, runtimeId: "onebox-main", name: safeText(body.name || machine.name + " " + validated.protocol, 80), tags, protocol: validated.protocol, listen: { port: validated.port, transport: validated.transport, address: validated.listenAddress }, options: validated.options, endpointOverride, nat };
        if (nat) {
          const publicEndpoint = candidateAddress(machine, state, instance);
          if (!publicEndpoint) fail("nat_endpoint_missing", "配置 NAT 外部端口时，必须提供公网 Endpoint 地址或先同步机器地址。", 409);
          nat.publicHost = publicEndpoint.host; nat.publicHosts = endpointPublicHosts(publicEndpoint);
          if (natMappingConflicts(state, nat.externalPort, validated.transport, endpointPublicHosts(publicEndpoint), instanceId)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 组合已被另一个 KNS 实例占用。", 409);
        }
        const spec = { id: instanceId, protocol: validated.protocol, port: validated.port, listenAddress: validated.listenAddress, transport: validated.transport, options: validated.options, name: instance.name, tags, endpointOverride, nat, idempotencyKey: key, requestHash, twoFactorCode: body.twoFactorCode };
        const created = createJob(state, req, "install", machine, spec, instance);
        created.job.batchId = batchId;
        audit(state, req, "job.authorized", { jobId: created.job.id, action: "install", machineUuid, instanceId, batchId });
        requestSpecs.push({ machineUuid, job: created.job, params: created.params });
      } catch (error) {
        results.push({ machineUuid, accepted: false, error: { code: error.code || "request_failed", message: safeText(error.message || error, 240) } });
      }
    }
    if (!requestSpecs.length && !results.some((item) => item.reused)) return json(res, 200, { ok: false, batchId, results });
    if (requestSpecs.length) save(state);
    for (const item of requestSpecs) {
      try {
        const submitted = await finishDispatch(item.job, item.params);
        results.push({ machineUuid: item.machineUuid, accepted: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
      } catch (error) {
        results.push({ machineUuid: item.machineUuid, accepted: false, error: { code: error.code || "dispatch_failed", message: safeText(error.message || error, 240) } });
      }
    }
    const acceptedCount = results.filter((item) => item.accepted).length;
    return json(res, 202, { ok: acceptedCount > 0, batchId, acceptedCount, results });
  }
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
    if (policy.managementTags != null) next.managementTags = Array.isArray(policy.managementTags) ? Array.from(new Set(policy.managementTags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [];
    if (!Array.isArray(next.managementTags)) next.managementTags = [];
    machine.policy = next; machine.updatedAt = now();
    audit(state, req, "machine.policy.updated", { machineUuid: machine.uuid, deployAllowed: next.deployAllowed, addressMode: next.addressMode });
    save(state); return json(res, 200, { ok: true, machine: safeMachine(machine) });
  }
  if (action === "settings.update") {
    const base = String(body.publicBaseUrl || "").trim().replace(/\/$/, "");
    let parsed;
    try { parsed = new URLConstructor(base); } catch (_) { fail("invalid_public_url", "Komari 公网地址必须是 HTTPS URL。", 400); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) fail("invalid_public_url", "KNS 回调需要不含账号、查询和片段的 HTTPS 地址。", 400);
    state.settings.publicBaseUrl = parsed.origin + parsed.pathname.replace(/\/$/, "");
    state.settings.privateSite = body.privateSite === true;
    if (body.converterUrl != null) {
      const configuredUrl = String(body.converterUrl).trim();
      const converter = configuredUrl ? parseConverterUrl(configuredUrl) : null;
      if (configuredUrl && !converter) fail("invalid_converter_url", "SubConverter 地址必须是以 /sub 结尾且不含账号或片段的 HTTPS URL；留空可关闭外部转换。", 400);
      state.settings.converterUrl = converter ? converter.toString() : "";
    }
    if (body.converterTarget != null) {
      if (!CONVERTER_TARGETS.has(String(body.converterTarget))) fail("invalid_converter_target", "SubConverter target 不在支持列表中。", 400);
      state.settings.converterTarget = String(body.converterTarget);
    }
    audit(state, req, "settings.updated", { privateSite: state.settings.privateSite });
    save(state); return json(res, 200, { ok: true, settings: publicState(state).settings });
  }
  if (action === "machine.discover") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    if (machine.online !== true) fail("machine_offline", "探针当前不在线，无法扫描 OneBox 配置。", 409);
    const key = safeText(body.idempotencyKey || "", 256);
    if (!key) fail("idempotency_key_required", "只读扫描需要 idempotencyKey。", 400);
    const requestHash = crypto.createHash("sha256").update(machine.uuid + ":discover-legacy-onebox").digest("hex");
    const prior = state.jobs.find((item) => item.action === action && item.machineUuid === machine.uuid && item.idempotencyKey === key);
    if (prior) {
      if (prior.requestHash !== requestHash) fail("idempotency_conflict", "相同 idempotencyKey 已用于其他扫描请求。", 409);
      return json(res, 200, { ok: !["failed", "cancelled"].includes(prior.state), reused: true, job: safeJob(prior) });
    }
    const conflict = state.jobs.find((item) => item.machineUuid === machine.uuid && item.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
    if (conflict) fail("runtime_busy", "该探针已有 OneBox 任务进行中，请等待完成后再扫描。", 409);
    const code = checkTwoFactor(body.twoFactorCode);
    const job = { id: randomId("job"), action, state: "authorized", machineUuid: machine.uuid, machineName: machine.name, runtimeId: "onebox-main", idempotencyKey: key, requestHash, taskId: "", callback: null, createdAt: now(), updatedAt: now(), actor: safeText(((req.context || {}).principal || {}).username || "admin", 80), message: "正在远程只读扫描 OneBox 入站。" };
    state.jobs.push(job); audit(state, req, "machine.legacy_discovery.requested", { jobId: job.id, machineUuid: machine.uuid }); save(state);
    const params = { command: makeRemoteDiscoveryCommand(), clients: [machine.uuid] };
    if (code) params["2fa_code"] = code;
    const submitted = await finishDispatch(job, params); return json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
  }
  if (action === "machine.import") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    if (machine.online !== true) fail("machine_offline", "探针当前不在线，无法导入 OneBox 凭据。", 409);
    if (body.confirm !== true) fail("confirmation_required", "接管会把旧 OneBox 入站迁移到 KNS 管理，并重载共享 sing-box 服务；需要明确确认。", 400);
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址，以接收一次性加密回调。", 409);
    const legacyTag = String(body.legacyTag || "");
    if (!legacyTag || legacyTag.length > 128) fail("invalid_legacy_tag", "旧版 OneBox tag 无效。", 400);
    const scannedAt = Date.parse(machine.discoveredAt || "");
    if (!Number.isFinite(scannedAt) || scannedAt > Date.now() || Date.now() - scannedAt > 30 * 60 * 1000) fail("discovery_stale", "请先重新扫描；旧节点发现结果无效或超过 30 分钟。", 409);
    const candidate = (machine.discoveredNodes || []).find((node) => node.tag === legacyTag);
    if (!candidate || candidate.managed || !candidate.importable || !PROTOCOLS[candidate.protocol] || !["tcp", "udp", "tcp+udp"].includes(candidate.listen.transport) || !Number.isInteger(candidate.listen.port) || candidate.listen.port < 1 || candidate.listen.port > 65535) fail("legacy_node_not_importable", "此历史节点不受安全导入支持，请查看扫描结果中的原因。", 409);
    const legacyExisting = (state.instances || []).find((instance) => instance.machineUuid === machine.uuid && instance.managedBy === "legacy_import" && instance.legacyTag === legacyTag && !instance.deletedAt) || null;
    if ((state.instances || []).some((instance) => instance.machineUuid === machine.uuid && instance.legacyTag === legacyTag && instance.managedBy !== "legacy_import" && !instance.deletedAt)) fail("legacy_node_already_managed", "该旧 tag 已被 KNS 节点记录占用，请重新扫描并核对配置。", 409);
    const idempotencyKey = safeText(body.idempotencyKey || "", 256);
    if (!idempotencyKey) fail("idempotency_key_required", "节点导入需要 idempotencyKey。", 400);
    const prior = state.jobs.find((item) => item.machineUuid === machine.uuid && item.action === action && item.idempotencyKey === idempotencyKey);
    const instanceId = prior ? prior.instanceId : legacyExisting ? legacyExisting.id : randomId("legacy");
    const endpointOverrideProvided = Object.prototype.hasOwnProperty.call(body, "endpointHost") || Object.prototype.hasOwnProperty.call(body, "endpointPort");
    const endpointOverride = endpointOverrideProvided ? makeEndpointOverride(body.endpointHost, body.endpointPort, !!state.settings.privateSite) : legacyExisting && legacyExisting.endpointOverride || null;
    const externalPortProvided = Object.prototype.hasOwnProperty.call(body, "externalPort");
    const nat = externalPortProvided ? (body.externalPort ? { externalPort: validatePort(body.externalPort) } : null) : legacyExisting && legacyExisting.nat ? deepClone(legacyExisting.nat) : null;
    const importEndpoint = candidateAddress(machine, state, { listen: { port: candidate.listen.port }, endpointOverride, nat });
    if (!importEndpoint) fail("endpoint_missing", "请先设置可用公网地址或 DDNS，再导入订阅节点。", 409);
    if (nat) {
      nat.publicHost = importEndpoint.host;
      nat.publicHosts = endpointPublicHosts(importEndpoint);
      if (natMappingConflicts(state, nat.externalPort, candidate.listen.transport, nat.publicHosts, instanceId)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 组合已被另一个 KNS 实例占用。", 409);
    }
    const requestHash = crypto.createHash("sha256").update(JSON.stringify({ action, machineUuid: machine.uuid, instanceId, legacyTag, protocol: candidate.protocol, port: candidate.listen.port, transport: candidate.listen.transport, endpointOverride, externalPort: nat && nat.externalPort || 0 })).digest("hex");
    if (prior) {
      if (prior.requestHash !== requestHash) fail("idempotency_conflict", "相同 idempotencyKey 已用于其他导入请求。", 409);
      return json(res, 200, { ok: !["failed", "cancelled"].includes(prior.state), reused: true, job: safeJob(prior) });
    }
    requireConfirmedDispatch(state, machine.uuid);
    const conflict = state.jobs.find((item) => item.machineUuid === machine.uuid && item.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
    if (conflict) fail("runtime_busy", "该探针已有 OneBox 任务进行中，请等待完成后再导入。", 409);
    const address = ["::", "0.0.0.0", "127.0.0.1", "::1"].includes(candidate.listen.address) ? candidate.listen.address : "::";
    const spec = {
      id: instanceId, legacyTag, name: safeText(body.name || subscriptions.subscriptionNodeName(candidate.protocol, machine.name, importEndpoint.port || candidate.listen.port), 80), tags: Array.isArray(body.tags) ? body.tags.map((tag) => safeText(tag, 32)).filter(Boolean) : legacyExisting && legacyExisting.tags || [],
      protocol: candidate.protocol, port: candidate.listen.port, listenAddress: address, transport: candidate.listen.transport,
      options: candidate.options || {}, endpointOverride, nat, idempotencyKey, twoFactorCode: body.twoFactorCode, requestHash,
    };
    const claimInstance = legacyExisting ? Object.assign({}, legacyExisting, { protocol: candidate.protocol, listen: { port: candidate.listen.port, address, transport: candidate.listen.transport }, options: candidate.options || {}, endpointOverride, nat, name: spec.name, tags: spec.tags }) : null;
    const { job, params } = createJob(state, req, action, machine, spec, claimInstance);
    job.legacyTag = legacyTag; job.requestHash = requestHash;
    audit(state, req, "instance.legacy_import.authorized", { jobId: job.id, machineUuid: machine.uuid, instanceId: job.instanceId, legacyTag });
    save(state);
    const submitted = await finishDispatch(job, params); return json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
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
  if (action === "diagnostics.key.check") {
    const instance = (state.instances || []).find((item) => item.credentialCiphertext && !item.deletedAt);
    if (!instance) return json(res, 200, { ok: true, instanceId: "", candidates: [] });
    const candidates = [];
    const tryKey = (source, key) => {
      if (!key || key.length !== 32) { candidates.push({ source, works: false, reason: "invalid_length" }); return; }
      try { secrets.decryptSecret(instance.credentialCiphertext, key); candidates.push({ source, works: true }); }
      catch (_) { candidates.push({ source, works: false }); }
    };
    tryKey("current", currentMasterKey());
    try {
      for (const name of fs.readdirSync(store.backupDir).filter((n) => /^master-\d{4}-\d{2}-\d{2}\.key$/.test(n)).sort().reverse()) {
        tryKey("backup:" + name, fs.readFileSync(path.join(store.backupDir, name)));
      }
      for (const name of fs.readdirSync(store.backupDir).filter((n) => /^pre-(upgrade|migration)-/.test(n))) {
        const keyPath = path.join(store.backupDir, name, "kns", "master.key");
        if (fs.existsSync(keyPath)) tryKey("snapshot:" + name, fs.readFileSync(keyPath));
      }
    } catch (error) { candidates.push({ source: "scan", works: false, reason: safeText(error && error.message || error, 160) }); }
    return json(res, 200, { ok: true, instanceId: instance.id, candidates });
  }
  if (action === "backup.restore.preview") {
    assertNoActiveJobs(state, "恢复备份");
    let preview;
    try { preview = store.inspectBackup(String(body.name || "")); }
    catch (error) { fail("backup_preview_failed", safeText(error && error.message || error, 240), 400); }
    if (preview.requiresMasterKey && !preview.keyAvailable) fail("backup_key_missing", "该备份缺少可用的配对主密钥；恢复已阻止。", 409);
    return json(res, 200, { ok: true, currentRevision: state.revision, backup: preview });
  }
  if (action === "backup.inspect") {
    const imported = decryptBackupEnvelope(body.envelope, body.passphrase);
    const configured = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
    const keyCompatible = !configured || (/^[a-f0-9]{64}$/i.test(configured) && crypto.timingSafeEqual(Buffer.from(configured, "hex"), imported.key));
    if (!keyCompatible) fail("master_key_conflict", "导入备份的密钥与当前 KNS_MASTER_KEY 不匹配；尚未修改数据。", 409);
    const backup = imported.state;
    return json(res, 200, { ok: true, currentRevision: state.revision, keyCompatible: true, backup: { schemaVersion: backup.schemaVersion, pluginVersion: backup.pluginVersion || "", createdAt: backup.updatedAt || backup.createdAt || "", counts: { machines: backup.machines.length, instances: backup.instances.filter((item) => !item.deletedAt).length, profiles: backup.profiles.length, jobs: backup.jobs.length } } });
  }
  if (action === "profile.token.show") {
    const profile = state.profiles.find((item) => item.id === String(body.profileId || ""));
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    if (profile.revokedAt || (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now())) fail("profile_unavailable", "订阅档案已停用或过期。", 409);
    if (profile.tokenRequired === false) {
      return json(res, 200, Object.assign({ ok: true, profileId: profile.id, token: "", tokenId: "", tokenRequired: false }, buildProfileTokenLinks(state, profile, "", body.format)));
    }
    const token = recoverProfileToken(profile);
    const record = profileTokenRecords(profile).find((item) => item && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()) && secrets.verifyToken(token, item));
    if (!token || !record) fail("token_reissue_required", "旧版令牌无法恢复；请轮换一次以生成可重复查看的新令牌。", 409);
    res.setHeader("Cache-Control", "no-store");
    return json(res, 200, Object.assign({ ok: true, profileId: profile.id, token, tokenId: record.id || "legacy-token", tokenRequired: profile.tokenRequired !== false }, buildProfileTokenLinks(state, profile, token, body.format)));
  }
  if (action === "profile.token.configure") {
    const profile = state.profiles.find((item) => item.id === String(body.profileId || ""));
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    if (typeof body.enabled !== "boolean") fail("invalid_token_mode", "enabled 必须是布尔值。", 400);
    if (profile.revokedAt) fail("profile_revoked", "订阅档案已撤销，请先轮换令牌恢复。", 409);
    if (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now()) fail("profile_expired", "订阅档案已过期，请先更新档案有效期。", 409);
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址。", 409);
    if (!body.enabled) {
      profile.tokenRequired = false;
      audit(state, req, "profile.token.disabled", { profileId: profile.id });
      save(state);
      return json(res, 200, Object.assign({ ok: true, profileId: profile.id, tokenRequired: false }, buildProfileTokenLinks(state, profile, "", body.format)));
    }
    applyPendingTokenUsage(state);
    let token = (profile.token || profile.tokenCiphertext) ? recoverProfileToken(profile) : "";
    const currentRecord = token && profileTokenRecords(profile).find((item) => item && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()) && secrets.verifyToken(token, item));
    let record = currentRecord || null;
    if (!record) {
      token = secrets.createToken();
      record = replaceProfileToken(profile, token, profile.expiresAt || "");
      profile.rotatedAt = now();
    } else {
      profile.tokens = [record];
      profile.tokenRequired = true;
    }
    profile.revokedAt = "";
    audit(state, req, record === currentRecord ? "profile.token.enabled" : "profile.token.enabled_and_rotated", { profileId: profile.id, tokenId: record.id });
    save(state);
    pendingTokenUsage.clear();
    res.setHeader("Cache-Control", "no-store");
    return json(res, 200, Object.assign({ ok: true, profileId: profile.id, token, tokenId: record.id, tokenRequired: true }, buildProfileTokenLinks(state, profile, token, body.format)));
  }
  if (action === "profile.create" || action === "profile.rotate" || action === "profile.token.create") {
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址。", 409);
    if (action === "profile.create") {
      const profileId = randomId("profile");
      const name = safeText(body.name || "订阅档案", 80);
      const defaults = { instanceIds: null, machineUuids: null, excludeMachineUuids: [], protocols: null, includeTags: [], formats: ["mihomo-full", "uri"], excludeUnhealthy: true, addressMode: "auto", sortBy: "name", expiresAt: "" };
      const filters = profileFilterFields(body, defaults);
      const tokenRequired = body.tokenRequired !== false;
      const profile = { id: profileId, name, createdAt: now(), tokens: [], tokenRequired, ...filters, legacy: false };
      let token = ""; let tokenRecord = null;
      if (tokenRequired) { token = secrets.createToken(); tokenRecord = replaceProfileToken(profile, token, profile.expiresAt || ""); }
      state.profiles.push(profile);
      audit(state, req, "profile.created", { profileId, formats: filters.formats, tokenRequired });
      save(state);
      res.setHeader("Cache-Control", "no-store");
      return json(res, 201, Object.assign({ ok: true, profile: { id: profile.id, name: profile.name, tokenRequired }, tokenId: tokenRecord && tokenRecord.id || "" }, buildProfileTokenLinks(state, profile, token, body.format)));
    }

    const profileId = String(body.profileId || "");
    const profile = state.profiles.find((item) => item.id === profileId);
    if (!profile) fail("profile_not_found", "订阅档案不存在。", 404);
    if (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now()) fail("profile_expired", "订阅档案已过期，请先更新档案有效期。", 409);
    if (action === "profile.rotate" && body.graceSeconds != null && Number(body.graceSeconds) !== 0) fail("token_grace_unsupported", "每个订阅只保留一个令牌；轮换后旧令牌立即失效。", 400);
    if (action === "profile.token.create" && profile.revokedAt) fail("profile_revoked", "订阅档案已撤销，请先轮换令牌恢复。", 409);
    const active = profileTokenRecords(profile).filter((record) => record && !record.revokedAt && (!record.expiresAt || Date.parse(record.expiresAt) > Date.now()));
    if (action === "profile.token.create" && active.length) fail("token_already_exists", "每个订阅只保留一个令牌；请使用轮换令牌。", 409);
    applyPendingTokenUsage(state);
    const token = secrets.createToken();
    let tokenExpiresAt = body.expiresAt ? validateFutureDate(body.expiresAt) : (profile.expiresAt || "");
    if (profile.expiresAt && (!tokenExpiresAt || Date.parse(profile.expiresAt) < Date.parse(tokenExpiresAt))) tokenExpiresAt = profile.expiresAt;
    const tokenRecord = replaceProfileToken(profile, token, tokenExpiresAt);
    profile.revokedAt = "";
    if (action === "profile.rotate") profile.rotatedAt = now();
    const auditAction = action === "profile.rotate" ? "profile.rotated" : "profile.token.created";
    audit(state, req, auditAction, { profileId, tokenId: tokenRecord.id, replacedTokenCount: active.length });
    save(state);
    pendingTokenUsage.clear();
    res.setHeader("Cache-Control", "no-store");
    return json(res, action === "profile.token.create" ? 201 : 200, Object.assign({ ok: true, profileId, tokenId: tokenRecord.id, tokenRequired: true }, buildProfileTokenLinks(state, profile, token, body.format)));
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
    const keepSecret = keep.credential ? JSON.stringify(keep.credential) : (keep.credentialCiphertext ? secrets.decryptSecret(keep.credentialCiphertext, currentMasterKey()) : "");
    const duplicates = state.instances.filter((item) => item.id !== keep.id && item.machineUuid === keep.machineUuid && !item.deletedAt && item.protocol === keep.protocol && item.listen.port === keep.listen.port && item.listen.transport === keep.listen.transport && item.endpoint && keep.endpoint && item.endpoint.host === keep.endpoint.host && keepSecret && ((item.credential && JSON.stringify(item.credential) === keepSecret) || (item.credentialCiphertext && secrets.decryptSecret(item.credentialCiphertext, currentMasterKey()) === keepSecret)));
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
    if (nextNat && natMappingConflicts(state, nextNat.externalPort, instance.listen.transport, endpointPublicHosts(nextEndpoint), instance.id)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 传输组合已被另一个 KNS 实例占用。", 409);
    if (body.name != null) instance.name = safeText(body.name, 80);
    if (body.tags != null) instance.tags = Array.isArray(body.tags) ? Array.from(new Set(body.tags.map((tag) => safeText(tag, 32)).filter(Boolean))).slice(0, 30) : [];
    if (body.endpointHost != null) instance.endpointOverride = nextOverride;
    if (body.externalPort != null) instance.nat = nextNat;
    if (instance.nat && nextEndpoint) {
      instance.nat.publicHost = nextEndpoint.host;
      instance.nat.publicHosts = endpointPublicHosts(nextEndpoint);
    }
    instance.endpoint = nextEndpoint;
    instance.updatedAt = now(); audit(state, req, "instance.metadata.updated", { instanceId: instance.id }); save(state); return json(res, 200, { ok: true });
  }
  if (action === "backup.restore") {
    if (body.confirmPhrase !== "恢复") fail("confirmation_required", "请输入“恢复”以确认替换 KNS 数据。", 400);
    assertNoActiveJobs(state, "恢复备份");
    maintenanceLock = true;
    try {
      const restored = store.restoreBackup(String(body.name || ""), { expectedRevision: state.revision });
      masterKey = secrets.getMasterKey(__storageDir__);
      pendingTokenUsage.clear();
      store.pruneSubscriptionSnapshots([]);
      audit(restored, req, "backup.restored", { name: safeText(body.name, 80) });
      save(restored);
      return json(res, 200, { ok: true, revision: restored.revision });
    } finally { maintenanceLock = false; }
  }
  if (action === "instance.status") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    const instance = state.instances.find((item) => item.id === String(body.instanceId || "") && item.machineUuid === machine.uuid && !item.deletedAt);
    if (!instance) fail("instance_not_found", "实例不存在或不属于此探针。", 404);
    const key = safeText(body.idempotencyKey || "", 256);
    if (!key) fail("idempotency_key_required", "状态核查需要 idempotencyKey。", 400);
    const prior = state.jobs.find((item) => item.action === action && item.machineUuid === machine.uuid && item.instanceId === instance.id && item.idempotencyKey === key);
    if (prior) return json(res, 200, { ok: true, reused: true, job: safeJob(prior) });
    const conflict = state.jobs.find((item) => item.machineUuid === machine.uuid && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
    if (conflict) fail("runtime_busy", "该探针已有 OneBox 任务进行中，请等待完成后再核查状态。", 409);
    const code = checkTwoFactor(body.twoFactorCode);
    const params = { command: makeRemoteStatusCommand(instance), clients: [machine.uuid] };
    if (code) params["2fa_code"] = code;
    const job = { id: randomId("job"), action, state: "authorized", machineUuid: machine.uuid, machineName: machine.name, instanceId: instance.id, protocol: instance.protocol, runtimeId: instance.runtimeId || "onebox-main", idempotencyKey: key, requestHash: crypto.createHash("sha256").update(machine.uuid + ":" + instance.id + ":status").digest("hex"), taskId: "", callback: null, createdAt: now(), updatedAt: now(), message: "正在提交只读状态核查。" };
    state.jobs.push(job); audit(state, req, "instance.status.requested", { jobId: job.id, instanceId: instance.id, machineUuid: machine.uuid }); save(state);
    const submitted = await finishDispatch(job, params); return json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
  }
  if (action === "runtime.script.update" || action === "runtime.kernel.update") {
    const machine = machineByUuid(state, String(body.machineUuid || "").toLowerCase());
    if (machine.online !== true) fail("machine_offline", "探针当前不在线，无法升级 OneBox。", 409);
    requirePolicy(machine);
    if (body.confirm !== true) fail("confirmation_required", "OneBox 运行时升级需要显式确认。", 400);
    if (!state.settings.publicBaseUrl) fail("public_url_required", "请先设置 Komari HTTPS 公网地址，以接收 OneBox 升级结果。", 409);
    const scanAt = Date.parse(machine.discoveredAt || "");
    const hasOneBox = Array.isArray(machine.discoveredNodes) && machine.discoveredNodes.length > 0 || state.instances.some((item) => item.machineUuid === machine.uuid && !item.deletedAt);
    if (!hasOneBox || !Number.isFinite(scanAt) || Date.now() - scanAt > 30 * 60 * 1000) fail("runtime_scan_stale", "请先在 30 分钟内完成该探针的 OneBox 只读扫描，再发起升级。", 409);
    const version = String(body.version || "latest");
    if (action === "runtime.kernel.update" && version !== "latest") fail("invalid_upgrade_version", "KNS 仅支持升级到最新稳定版 sing-box。", 400);
    const idempotencyKey = safeText(body.idempotencyKey || "", 256);
    if (!idempotencyKey) fail("idempotency_key_required", "每次 OneBox 运行时升级都必须提供 idempotencyKey。", 400);
    const requestHash = crypto.createHash("sha256").update(JSON.stringify({ action, machineUuid: machine.uuid, target: action === "runtime.kernel.update" ? version : INSTALLER_SHA256 })).digest("hex");
    const prior = state.jobs.find((item) => item.machineUuid === machine.uuid && item.action === action && item.idempotencyKey === idempotencyKey);
    if (prior) {
      if (prior.requestHash !== requestHash) fail("idempotency_conflict", "相同 idempotencyKey 已用于不同的 OneBox 升级目标。", 409);
      return json(res, 200, { ok: !["failed", "cancelled"].includes(prior.state), reused: true, job: safeJob(prior) });
    }
    requireConfirmedDispatch(state, machine.uuid);
    const conflict = state.jobs.find((item) => item.machineUuid === machine.uuid && item.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
    if (conflict) fail("runtime_busy", "该探针的共享 OneBox Runtime 仍有未完成任务。", 409);
    const spec = { idempotencyKey, requestHash, version, twoFactorCode: body.twoFactorCode };
    const { job, params } = createRuntimeUpgradeJob(state, req, action, machine, spec);
    audit(state, req, "runtime.upgrade.authorized", { jobId: job.id, action, machineUuid: machine.uuid, target: action === "runtime.kernel.update" ? "latest-stable" : INSTALLER_SHA256 });
    save(state);
    const submitted = await finishDispatch(job, params);
    return json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
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
    const owner = (state.instances.find((item) => item.id === proposedId) || {}).machineUuid || reservedInstanceOwner(state, proposedId);
    if (actionName === "install" && owner && owner !== machineUuid) fail("instance_id_conflict", "该实例 ID 已属于另一台探针。", 409);
    if (actionName === "install" && instance && !instance.deletedAt) fail("instance_exists", "该实例已经登记，请选择重配置、重装或新建实例。", 409);
    if (actionName !== "install" && (!instance || instance.deletedAt)) fail("instance_not_found", "重配置或重装需要选择已登记实例。", 404);
    if (instance && instance.managedBy === "legacy_import") fail("legacy_instance_readonly", "导入的旧版节点仅支持订阅发布设置；如需修改节点配置，请在 OneBox 中操作。", 409);
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
        instance.nat.publicHosts = endpointPublicHosts(publicEndpoint);
        if (natMappingConflicts(state, instance.nat.externalPort, validated.transport, endpointPublicHosts(publicEndpoint), proposedId)) fail("nat_mapping_conflict", "公网 IP、外部端口和 TCP/UDP 传输组合已被另一个 KNS 实例占用。", 409);
      }
    } else if (actionName === "reconfigure") {
      instance = Object.assign({}, instance, { protocol: validated.protocol, listen: { port: validated.port, transport: validated.transport, address: validated.listenAddress }, options: validated.options });
    }
    spec.id = proposedId; spec.port = actionName === "reinstall" ? instance.listen.port : validated.port; spec.listenAddress = actionName === "reinstall" ? instance.listen.address : validated.listenAddress; spec.transport = actionName === "reinstall" ? instance.listen.transport : validated.transport; spec.protocol = instance.protocol; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  } else {
    instance = state.instances.find((item) => item.id === String(body.instanceId || "") && item.machineUuid === machineUuid && !item.deletedAt);
    if (!instance) fail("instance_not_found", "目标实例不存在或不属于该探针。", 404);
    if (instance.managedBy === "legacy_import") fail("legacy_instance_readonly", "导入的旧版节点仅支持订阅发布设置；如需修改节点配置，请在 OneBox 中操作。", 409);
    if (actionName === "uninstall") {
      const remote = instance.remoteStatus || {};
      const preview = remote.uninstallPreview || {};
      const checkedAt = Date.parse(remote.checkedAt || "");
      const validResources = Array.isArray(remote.resources) && remote.resources.length > 0 && remote.resources.every((resource) => resource && resource.type && resource.id && resource.action && typeof resource.owned === "boolean" && typeof resource.shared === "boolean" && typeof resource.present === "boolean");
      if (remote.installed !== true || preview.complete !== true || !validResources || !/^[a-f0-9]{64}$/i.test(String(preview.version || ""))) fail("uninstall_preview_incomplete", "卸载未提交：请先取得完整的远端资源影响预览。", 409);
      if (!Number.isFinite(checkedAt) || checkedAt > Date.now() || Date.now() - checkedAt > 5 * 60 * 1000) fail("uninstall_preview_stale", "卸载预览已过期；请重新检查机器上的实际配置。", 409);
      if (String(body.previewVersion || "") !== preview.version) fail("uninstall_preview_changed", "卸载预览版本已变化；请重新检查并确认最新资源影响。", 409);
    }
    spec.id = instance.id; spec.protocol = instance.protocol; spec.port = instance.listen.port; spec.listenAddress = instance.listen.address; spec.transport = instance.listen.transport; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  }
  if (["enable", "disable"].includes(actionName)) {
    // These operations are translated into the OneBox adapter contract below.
    spec.protocol = instance.protocol; spec.id = instance.id; spec.port = instance.listen.port; spec.listenAddress = instance.listen.address; spec.transport = instance.listen.transport; spec.options = instance.options; spec.name = instance.name; spec.tags = instance.tags;
  }
  const requestHashData = {
    action: actionName, machineUuid, instanceId: body.instanceId || "", protocol: spec.protocol || "", port: spec.port || 0,
    transport: spec.transport || "", options: spec.options || {}, listenAddress: spec.listenAddress || "", endpointHost: body.endpointHost || "", endpointPort: body.endpointPort || 0, externalPort: body.externalPort || 0,
  };
  if (actionName === "uninstall") requestHashData.previewVersion = String(body.previewVersion || "");
  const requestHash = crypto.createHash("sha256").update(JSON.stringify(requestHashData)).digest("hex");
  const prior = state.jobs.find((item) => item.machineUuid === machineUuid && item.action === actionName && item.idempotencyKey === suppliedIdempotencyKey);
  if (prior) {
    if (prior.requestHash !== requestHash) fail("idempotency_conflict", "相同 idempotencyKey 已用于不同的远程动作。", 409);
    return json(res, 200, { ok: !["failed", "cancelled"].includes(prior.state), reused: true, job: safeJob(prior) });
  }
  requireConfirmedDispatch(state, machineUuid);
  spec.idempotencyKey = suppliedIdempotencyKey;
  spec.requestHash = requestHash;
  const conflictingJob = state.jobs.find((item) => item.machineUuid === machineUuid && item.runtimeId === "onebox-main" && ["authorized", "dispatched", "running", "verifying"].includes(item.state));
  if (conflictingJob) fail("runtime_busy", "该机器的共享 OneBox Runtime 仍有未完成配置任务。", 409);
  const { job, instance: jobInstance, params } = createJob(state, req, actionName, machine, spec, instance);
  audit(state, req, "job.authorized", { jobId: job.id, action: actionName, machineUuid, instanceId: job.instanceId, uninstallPreviewVersion: actionName === "uninstall" ? String(body.previewVersion || "") : undefined });
  // Persist the authorization record before dispatch so callbacks cannot precede it.
  save(state);
  const submitted = await finishDispatch(job, params);
  json(res, 202, { ok: !["failed", "cancelled"].includes(submitted.state), job: safeJob(submitted) });
}

function validateFutureDate(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) fail("invalid_expiry", "订阅过期时间必须是未来时间。", 400);
  return date.toISOString();
}

function profileUrl(state, profileId, token, format) {
  const base = state.settings.publicBaseUrl.replace(/\/$/, "") + API + "/sub?profile=" + encodeURIComponent(profileId) + "&format=" + encodeURIComponent(format || "mihomo-full");
  return token ? base + "&token=" + encodeURIComponent(token) : base;
}

function parseConverterUrl(value) {
  try {
    const converter = new URLConstructor(value);
    if (converter.protocol !== "https:" || converter.username || converter.password || converter.hash || !converter.pathname.endsWith("/sub")) return null;
    return converter;
  } catch (_) { return null; }
}

function buildConverterUrl(state, sourceUrl, target, rulePreset) {
  try {
    // Revalidate persisted/imported settings as well as newly saved settings.
    const converter = parseConverterUrl(state.settings.converterUrl);
    if (!converter || new URLConstructor(sourceUrl).protocol !== "https:") return "";
    const selectedTarget = String(target || state.settings.converterTarget || "clash");
    if (!CONVERTER_TARGETS.has(selectedTarget)) return "";
    converter.searchParams.set("target", selectedTarget);
    converter.searchParams.set("url", sourceUrl);
    converter.searchParams.delete("config");
    if (rulePreset) {
      if (selectedTarget !== "clash" || !Object.prototype.hasOwnProperty.call(CONVERTER_RULE_PRESETS, rulePreset)) return "";
      converter.searchParams.set("config", CONVERTER_RULE_PRESETS[rulePreset]);
    }
    return converter.toString();
  } catch (_) { return ""; }
}

function buildConverterUrls(state, sourceUrl) {
  const urls = {};
  for (const target of CONVERTER_TARGETS) {
    const url = buildConverterUrl(state, sourceUrl, target);
    if (url) urls[target] = url;
  }
  for (const preset of Object.keys(CONVERTER_RULE_PRESETS)) {
    const url = buildConverterUrl(state, sourceUrl, "clash", preset);
    if (url) urls["clash-" + preset] = url;
  }
  return urls;
}

function buildProfileTokenLinks(state, profile, token, extraFormat) {
  const subscriptionUrls = {};
  const availableSubscriptionUrls = {};
  const effectiveToken = profile.tokenRequired === false ? "" : String(token || "");
  const formats = new Set(Array.isArray(profile.formats) ? profile.formats : []);
  if (extraFormat && FORMATS.has(String(extraFormat))) formats.add(String(extraFormat));
  for (const format of formats) {
    if (FORMATS.has(format)) subscriptionUrls[format] = profileUrl(state, profile.id, effectiveToken, format);
  }
  for (const format of FORMATS) availableSubscriptionUrls[format] = profileUrl(state, profile.id, effectiveToken, format);
  const tokenUrl = subscriptionUrls.uri || "";
  const nativeFormat = ["mihomo-full", "mihomo-provider", "singbox-full", "singbox-outbounds"].find((format) => subscriptionUrls[format]) || "";
  return {
    token: effectiveToken,
    tokenRequired: profile.tokenRequired !== false,
    subscriptionUrls,
    availableSubscriptionUrls,
    tokenUrl,
    nativeUrl: nativeFormat ? subscriptionUrls[nativeFormat] : "",
    nativeFormat,
    converterTarget: state.settings.converterTarget || "clash",
    converterUrl: tokenUrl ? buildConverterUrl(state, tokenUrl) : "",
    converterUrls: tokenUrl ? buildConverterUrls(state, tokenUrl) : {},
  };
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
  res.setHeader("Link", "<" + SOURCE_URL + ">; rel=\"source\"");
  res.setHeader("X-KNS-License", "AGPL-3.0-only");
  const state = getState();
  const query = req.query || {};
  const profileId = legacy ? "legacy-default" : String(query.profile || "");
  const profile = state.profiles.find((item) => item.id === profileId);
  const token = String(query.token || "");
  if (!profile) { res.statusCode = 404; res.setHeader("Cache-Control", "no-store"); res.end("Not found\n"); return; }
  if (profile.revokedAt || (profile.expiresAt && Date.parse(profile.expiresAt) <= Date.now())) { res.statusCode = 403; res.setHeader("Cache-Control", "no-store"); res.end("Subscription expired or revoked\n"); return; }
  let tokenRecord = null;
  if (profile.tokenRequired !== false) {
    tokenRecord = profileValid(profile, token);
    if (!tokenRecord) { res.statusCode = 404; res.setHeader("Cache-Control", "no-store"); res.end("Not found\n"); return; }
    recordTokenUsage(profile.id, tokenRecord.id || "legacy-token");
  }
  const format = legacy ? "uri" : String(query.format || "mihomo-full");
  if (!FORMATS.has(format)) { res.statusCode = 400; res.setHeader("Cache-Control", "no-store"); res.end("Unsupported subscription format\n"); return; }
  let snapshot;
  try { snapshot = readSubscriptionSnapshot(profile.id, format); }
  catch (error) { console.warn("[KNS] subscription snapshot read failed:", profile.id, format, String(error && error.message || error).slice(0, 160)); snapshot = null; }
  const snapshotExpected = !Array.isArray(profile.formats) || profile.formats.includes(format);
  if (!snapshot && snapshotExpected) console.warn("[KNS] subscription snapshot missing:", profile.id, format);
  const currentSourceHash = subscriptionSourceHash(state, profile, format);
  if (snapshot && snapshot.sourceHash !== currentSourceHash && snapshotExpected) console.warn("[KNS] subscription snapshot stale:", profile.id, format, String(snapshot.sourceHash).slice(0, 12), currentSourceHash.slice(0, 12));
  if (!snapshot || snapshot.sourceHash !== currentSourceHash) {
    if (snapshotExpected) scheduleSubscriptionRefresh();
    // Snapshot cache miss or unreadable cache: build from state for this request
    // instead of returning an endless 503. The background refresh still repairs
    // the cache for later requests.
    try {
      const built = subscriptions.buildSubscription(state, profile, format, (box) => secrets.decryptSecret(box, currentMasterKey()));
      const liveHash = crypto.createHash("sha256").update(built.body).digest("hex");
      const liveEtag = '"' + liveHash + '"';
      res.setHeader("Content-Type", built.contentType);
      res.setHeader("Cache-Control", "private, no-store, max-age=0");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("ETag", liveEtag);
      res.setHeader("X-KNS-Snapshot-Generated-At", now());
      res.setHeader("X-KNS-Snapshot-Success", String(built.successCount));
      res.setHeader("X-KNS-Snapshot-Skipped", String(built.skippedCount));
      res.setHeader("Vary", "Authorization, Cookie");
      if (String((req.headers || {})["if-none-match"] || "") === liveEtag) { res.statusCode = 304; res.end(); return; }
      res.statusCode = 200;
      res.end(built.body);
      return;
    } catch (error) {
      console.warn("[KNS] subscription direct build failed:", profile.id, format, String(error && error.message || error).slice(0, 160));
    }
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
    const runtimeUpgrade = isRuntimeUpgradeAction(job.action);
    const node = runtimeUpgrade ? null : validateCallbackInstance(job, body);
    const operationResult = runtimeUpgrade ? validateRuntimeCallback(job, body) : null;
    job.artifactVersion = body.artifactVersion;
    job.callback = { status: body.status, receivedAt: now(), payloadHash: bodyDigest, keyFingerprint: masterKeyFingerprint(currentMasterKey()), instance: node ? Object.assign({}, node, { credential: node.credential }) : null, operationResult };
    delete job.callbackTokenHash;
    delete job.callbackTokenSalt;
    job.state = job.dispatchUncertain && !job.taskId ? "needs_reconcile" : "verifying"; job.updatedAt = now(); job.message = job.dispatchUncertain && !job.taskId ? "已收到回调，但没有 Komari 任务编号，无法完成双重核验。请核查机器状态并确认处理。" : runtimeUpgrade ? "回调已验签，正在核对 Agent 退出码与 OneBox 版本/服务状态。" : "回调已验签，正在核对 Agent 退出码与远程实例状态。";
    save(state);
    res.statusCode = 204; res.end();
  } catch (error) {
    res.statusCode = error.status || 400; res.end("Invalid callback\n");
  }
}

function safeNodeFromCallback(job, state) {
  const callback = job.callback && job.callback.instance;
  if (!callback) return null;
  const node = { ...callback };
  if (!node.credential && node.credentialCiphertext) node.credential = JSON.parse(secrets.decryptSecret(node.credentialCiphertext, currentMasterKey()));
  delete node.credentialCiphertext;
  return node;
}

function resolveCallbackNode(job, state) {
  const node = job.callback && job.callback.instance;
  if (!node) return null;
  if (job.callback.keyFingerprint && job.callback.keyFingerprint !== masterKeyFingerprint(currentMasterKey())) {
    const error = new Error("KNS 主密钥在回调接收后发生变化，无法解密回调凭据。");
    error.code = "callback_key_changed";
    throw error;
  }
  const result = Object.assign({}, node);
  if (node.credential) { result.credential = node.credential; return result; }
  try { result.credential = JSON.parse(secrets.decryptSecret(node.credentialCiphertext, currentMasterKey())); }
  catch (_) {
    const error = new Error("回调凭据密文无法使用当前 KNS 主密钥解密。");
    error.code = "callback_decrypt_failed";
    throw error;
  }
  return result;
}

function closeJob(job) {
  if (job.callback && job.callback.instance) { delete job.callback.instance.credential; delete job.callback.instance.credentialCiphertext; }
  delete job.callbackTokenHash; delete job.callbackTokenSalt; delete job._callbackToken;
}

function callbackCiphertextMatchesCurrentKey(job) {
  const fingerprint = job && job.callback && job.callback.keyFingerprint;
  return !!fingerprint && fingerprint === masterKeyFingerprint(currentMasterKey());
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
        const hosts = Array.from(new Set((Array.isArray(endpoint.hosts) && endpoint.hosts.length ? endpoint.hosts : [endpoint.host]).filter(Boolean)));
        const checks = [];
        for (const host of hosts) {
          const check = endpoint.port ? await endpointReachable(host, endpoint.port, standardTls ? sni || host : "") : { ok: false, level: "L1-TCP", reason: "endpoint_missing" };
          checks.push({ host, check });
        }
        if (!checks.length) checks.push({ host: endpoint.host || "", check: { ok: false, level: "L1-TCP", reason: "endpoint_missing" } });
        return { id: instance.id, endpoint: instance.endpoint, checks };
      })));
    }
    const state = getState();
    let changed = false;
    for (const result of results) {
      const instance = state.instances.find((item) => item.id === result.id && !item.deletedAt && item.enabled);
      if (!instance) continue;
      if (JSON.stringify(instance.endpoint || {}) !== JSON.stringify(result.endpoint || {})) continue;
      if (result.udp) {
        const current = instance.health || {};
        if (current.state === "unverified" && current.reason === "agent_listener_only") continue;
        instance.health = Object.assign({}, current, { state: "unverified", level: "L1-UDP", reason: "agent_listener_only", lastCheckedAt: now(), hosts: {} });
        changed = true; continue;
      }
      const previousHosts = (instance.health && instance.health.hosts) || {};
      const hostHealth = {};
      for (const { host, check } of result.checks || []) {
        const prior = Object.assign({ consecutiveFailures: 0, consecutiveSuccesses: 0 }, previousHosts[host] || {});
        if (check.ok) {
          prior.consecutiveSuccesses = Math.min((Number(prior.consecutiveSuccesses) || 0) + 1, 2);
          prior.consecutiveFailures = 0;
          prior.state = prior.consecutiveSuccesses >= 2 ? "healthy" : (prior.state === "healthy" ? "healthy" : "suspect");
        } else {
          prior.consecutiveFailures = Math.min((Number(prior.consecutiveFailures) || 0) + 1, 3);
          prior.consecutiveSuccesses = 0;
          prior.state = prior.consecutiveFailures >= 3 ? "unhealthy" : "suspect";
        }
        prior.level = check.level; prior.reason = check.reason;
        hostHealth[host] = prior;
      }
      const states = Object.values(hostHealth);
      const allUnhealthy = states.length && states.every((item) => item.state === "unhealthy");
      const anyHealthy = states.some((item) => item.state === "healthy");
      const health = Object.assign({ consecutiveFailures: 0, consecutiveSuccesses: 0 }, instance.health || {}, { hosts: hostHealth });
      health.state = allUnhealthy ? "unhealthy" : anyHealthy ? "healthy" : "suspect";
      health.level = allUnhealthy ? (states[0] && states[0].level || "L1-TCP") : (states.find((item) => item.state !== "unhealthy") || states[0] || {}).level || "L1-TCP";
      health.reason = allUnhealthy ? "all_addresses_failed" : anyHealthy ? "reachable" : "partial_or_unconfirmed";
      health.consecutiveFailures = allUnhealthy ? Math.max(...states.map((item) => item.consecutiveFailures || 0), 0) : 0;
      health.consecutiveSuccesses = anyHealthy ? Math.max(...states.map((item) => item.consecutiveSuccesses || 0), 0) : 0;
      const previous = instance.health || {};
      if (health.state === "unhealthy" && (previous.state === "healthy" || previous.state === "unverified" || !previous.attentionIncidentId && previous.state !== "unhealthy")) {
        health.attentionIncidentId = randomId("health");
        delete health.attentionAcknowledgedIncidentId; delete health.attentionAcknowledgedAt;
      } else if (health.state === "healthy") {
        delete health.attentionIncidentId; delete health.attentionAcknowledgedIncidentId; delete health.attentionAcknowledgedAt;
      }
      const hostSummary = (hosts) => Object.fromEntries(Object.entries(hosts || {}).sort().map(([host, item]) => [host, {
        state: item && item.state || "", consecutiveFailures: Number(item && item.consecutiveFailures) || 0,
        consecutiveSuccesses: Number(item && item.consecutiveSuccesses) || 0, level: item && item.level || "", reason: item && item.reason || "",
      }]));
      if ((previous.state || "") === health.state && (previous.level || health.level) === health.level && (previous.reason || health.reason) === health.reason && JSON.stringify(hostSummary(previous.hosts)) === JSON.stringify(hostSummary(hostHealth))) continue;
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
      const count = same ? Number(current.count || 0) + 1 : 1;
      // Keep counting through the first two matching observations, then stop
      // rewriting state just to bump count/observedAt on an unchanged answer.
      if (!(same && Number(current.count || 0) >= 2)) {
        machine.ddnsObservation = { addresses: result.addresses, count, observedAt: now() };
        changed = true;
      }
      if (result.addresses.length && (machine.ddnsObservation && machine.ddnsObservation.count >= 2 || same && Number(current.count || 0) >= 2)) {
        resolvedByMachine.set(machine.uuid, result.addresses);
      }
    }
    if (changed) save(state);
    changed = false;

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
        if (instance.nat && natMappingConflicts(state, instance.nat.externalPort, (instance.listen || {}).transport, endpointPublicHosts(endpoint), instance.id)) {
          if (markNatMappingConflict(state, instance, endpoint)) changed = true;
          continue;
        }
        const current = instance.endpoint || {};
        const sameHost = current.host === endpoint.host && JSON.stringify(current.hosts || [current.host]) === JSON.stringify(endpoint.hosts || [endpoint.host]);
        const sameResolved = JSON.stringify((current.resolvedAddresses || []).slice().sort()) === JSON.stringify((endpoint.resolvedAddresses || []).slice().sort());
        if ((instance.nat && instance.nat.mappingConflict) || !sameHost || !sameResolved) candidates.push({ id: instance.id, machineUuid: machine.uuid, endpoint, fingerprint: endpointConfigFingerprint(machine, instance, endpoint), listen: instance.listen, tls: instance.tls });
      }
    }
    if (changed) save(state);
    const verified = [];
    for (let offset = 0; offset < candidates.length; offset += 5) {
      verified.push(...await Promise.all(candidates.slice(offset, offset + 5).map(async (candidate) => {
        const isUdp = candidate.listen && candidate.listen.transport === "udp";
        const hosts = Array.from(new Set((candidate.endpoint.hosts || [candidate.endpoint.host]).filter(Boolean)));
        if (isUdp) return { ...candidate, reachableHosts: hosts };
        const reachableHosts = [];
        for (const host of hosts) {
          const sni = candidate.tls && (candidate.tls.sni || candidate.tls.server_name) || "";
          const check = await endpointReachable(host, candidate.endpoint.port, candidate.tls && candidate.tls.security === "tls" ? sni || host : "");
          if (check.ok) reachableHosts.push(host);
        }
        return { ...candidate, reachableHosts };
      })));
    }
    state = getState();
    changed = false;
    for (const result of verified) {
      if (!result.reachableHosts || !result.reachableHosts.length) continue;
      const machine = state.machines.find((item) => item.uuid === result.machineUuid);
      const instance = state.instances.find((item) => item.id === result.id && item.machineUuid === result.machineUuid && !item.deletedAt && item.enabled);
      if (!machine || !instance) continue;
      let currentCandidate;
      try { currentCandidate = candidateAddress(machine, state, instance); } catch (_) { continue; }
      const reachable = new Set(result.reachableHosts);
      currentCandidate.hosts = (currentCandidate.hosts || [currentCandidate.host]).filter((host) => reachable.has(host));
      if (!currentCandidate.hosts.length) continue;
      if (currentCandidate.resolvedAddresses && currentCandidate.resolvedAddresses.length) {
        currentCandidate.resolvedAddresses = currentCandidate.resolvedAddresses.filter((host) => reachable.has(host));
      }
      currentCandidate.host = currentCandidate.hosts.includes(currentCandidate.host) ? currentCandidate.host : currentCandidate.hosts[0];
      currentCandidate.family = currentCandidate.hosts.length > 1 ? "dual" : (String(currentCandidate.host).includes(":") ? "ipv6" : "ipv4_or_domain");
      if (result.endpoint.source === "ddns") {
        const observation = machine.ddnsObservation;
        const addresses = observation && Array.isArray(observation.addresses) ? observation.addresses : [];
        if (!observation || observation.count < 2) continue;
        currentCandidate.resolvedAddresses = addresses.filter((host) => reachable.has(host));
        if (!currentCandidate.resolvedAddresses.length) continue;
      }
      result.endpoint = Object.assign({}, result.endpoint, {
        host: currentCandidate.host,
        hosts: currentCandidate.hosts.slice(),
        family: currentCandidate.family,
        resolvedAddresses: currentCandidate.resolvedAddresses || [],
      });
      result.fingerprint = endpointConfigFingerprint(machine, instance, currentCandidate);
      if (endpointConfigFingerprint(machine, instance, currentCandidate) !== result.fingerprint) continue;
      if (instance.nat && natMappingConflicts(state, instance.nat.externalPort, (instance.listen || {}).transport, endpointPublicHosts(currentCandidate), instance.id)) {
        if (markNatMappingConflict(state, instance, currentCandidate)) changed = true;
        continue;
      }
      instance.endpoint = result.endpoint;
      if (instance.nat) {
        instance.nat.publicHost = result.endpoint.host;
        instance.nat.publicHosts = endpointPublicHosts(result.endpoint);
        if (clearNatMappingConflict(state, instance)) changed = true;
      }
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
    catch (error) {
      const detail = { code: error.code || "request_failed", message: safeText(error.message || error, 300) };
      if (error.expectedRevision != null) detail.expectedRevision = error.expectedRevision;
      if (error.currentRevision != null) detail.currentRevision = error.currentRevision;
      json(res, error.status || 400, { error: detail });
    }
  });
}

async function downloadPluginUpdate(req, res) {
  const version = String((req.query || {}).version || "");
  try {
    if (!/^\d+\.\d+\.\d+$/.test(version) || compareSemver(version, PLUGIN_VERSION) <= 0) throw new Error("invalid_version");
  } catch (_) { fail("invalid_update_version", "只能安装比当前版本新的正式版本。", 400); }
  if (maintenanceLock) fail("maintenance_in_progress", "KNS 正在执行数据维护，请稍后再更新。", 409);
  assertNoActiveJobs(getState(), "更新插件");
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), 30000) : null;
  const options = { headers: { accept: "application/vnd.github+json", "user-agent": "komari-plugin-kns/" + PLUGIN_VERSION }, signal: controller && controller.signal };
  try {
    const latest = await fetch("https://api.github.com/repos/liuarui/komari-plugin-kns/releases/latest", options);
    if (!latest || !latest.ok) fail("update_download_failed", "无法获取 GitHub 最新发布信息。", 502);
    const release = await latest.json();
    if (String(release.tag_name || "") !== "v" + version || release.draft || release.prerelease) fail("update_version_changed", "最新发布版本已变化，请重新检查更新。", 409);
    const assets = Array.isArray(release.assets) ? release.assets : [];
    const archive = assets.find((item) => item && item.name === "onebox-bridge.zip" && item.state === "uploaded");
    const checksumAsset = assets.find((item) => item && item.name === "onebox-bridge.zip.sha256" && item.state === "uploaded");
    if (!archive || !Number.isSafeInteger(archive.size) || archive.size < 4 || archive.size > 8 * 1024 * 1024 || !checksumAsset || !Number.isSafeInteger(checksumAsset.size) || checksumAsset.size < 1 || checksumAsset.size > 512) fail("update_package_invalid", "发布页的更新包或校验文件缺失，或大小无效。", 502);
    const base = "https://github.com/liuarui/komari-plugin-kns/releases/download/v" + version + "/";
    const checksumResponse = await fetch(base + "onebox-bridge.zip.sha256", options);
    if (!checksumResponse || !checksumResponse.ok) fail("update_download_failed", "无法下载更新校验文件。", 502);
    const checksumText = await checksumResponse.text();
    const checksum = checksumText.length <= 512 && /^([a-f0-9]{64})\s+\*?onebox-bridge\.zip\s*$/i.exec(checksumText);
    if (!checksum) fail("update_checksum_invalid", "更新校验文件格式无效。", 502);
    const packageResponse = await fetch(base + "onebox-bridge.zip", options);
    if (!packageResponse || !packageResponse.ok) fail("update_download_failed", "无法下载插件更新包。", 502);
    const declaredSize = Number(packageResponse.headers && packageResponse.headers.get("content-length") || 0);
    if (declaredSize > 8 * 1024 * 1024) fail("update_package_too_large", "插件更新包超过允许大小。", 502);
    const data = Buffer.from(await packageResponse.arrayBuffer());
    if (data.length !== archive.size || data[0] !== 0x50 || data[1] !== 0x4b) fail("update_package_invalid", "插件更新包格式或大小无效。", 502);
    const digest = crypto.createHash("sha256").update(data).digest("hex");
    if (digest !== checksum[1].toLowerCase()) fail("update_checksum_mismatch", "插件更新包校验失败，已停止安装。", 502);
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.write(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
    res.end();
  } catch (error) {
    if (error && error.status) throw error;
    fail("update_download_failed", "下载插件更新失败，请检查 GitHub 网络连接后重试。", 502);
  } finally { if (timer) clearTimeout(timer); }
}

function registerRoutes() {
  registerAdmin("GET", "/admin/state", (_req, res) => json(res, 200, publicState(getState())));
  registerAdmin("GET", "/admin/update-package", downloadPluginUpdate);
  registerAdmin("POST", "/admin/action", handleAction);
  registerAdmin("GET", "/admin/logs", (req, res) => {
    const state = getState();
    const limit = Math.max(1, Math.min(500, Number((req.query || {}).limit) || 100));
    const logs = store.listAudit(limit, safeText((req.query || {}).before || "", 120));
    json(res, 200, { audit: logs.events.reverse(), nextCursor: logs.nextCursor, hasMore: logs.hasMore, auditRetention: logs.retention, jobs: state.jobs.slice(-limit).reverse().map(safeJob) });
  });
  registerAdmin("GET", "/admin/export", (_req, res) => json(res, 405, { error: { code: "encrypted_export_required", message: "请在管理页输入独立口令，创建加密备份。" } }));
  registerAdmin("POST", "/admin/import", (req, res) => {
    checkOrigin(req);
    const body = readBody(req, 16 * 1024 * 1024);
    if (maintenanceLock) fail("maintenance_in_progress", "KNS 正在执行数据维护；请稍后重试。", 409);
    if (body.confirmPhrase !== "恢复") fail("confirmation_required", "请输入“恢复”以确认替换 KNS 数据。", 400);
    const current = getState();
    assertExpectedRevision(current.revision, body);
    assertNoActiveJobs(current, "导入备份");
    maintenanceLock = true;
    try {
      const imported = decryptBackupEnvelope(body.envelope, body.passphrase);
      const configured = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
      if (configured && (!/^[a-f0-9]{64}$/i.test(configured) || !crypto.timingSafeEqual(Buffer.from(configured, "hex"), imported.key))) fail("master_key_conflict", "导入备份的密钥与当前 KNS_MASTER_KEY 不匹配；请先协调宿主密钥配置。", 409);
      const restored = store.importBackup(imported.state, imported.key, { expectedRevision: current.revision });
      masterKey = imported.key;
      pendingTokenUsage.clear();
      store.pruneSubscriptionSnapshots([]);
      audit(restored, req, "backup.imported", { format: "KNS-ENCRYPTED-EXPORT", schemaVersion: 1 });
      save(restored);
      json(res, 200, { ok: true, revision: restored.revision });
    } finally { maintenanceLock = false; }
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
  store.ensureDirectories();
  store.recoverInterruptedRestore();
  if (!masterKey) masterKey = secrets.getMasterKey(__storageDir__);
  getState();
  registerRoutes();
  server.cron("@every 15s", () => { cronTick(); });
  server.cron("@every 15s", () => { syncMachines().catch((error) => console.error("[KNS] machine sync failed:", safeText(error.message || error, 200))); });
  server.cron("@every 1m", () => { refreshEndpoints().catch((error) => console.error("[KNS] endpoint refresh failed:", safeText(error.message || error, 200))); });
  server.cron("@every 1m", () => { try { flushTokenUsage(); } catch (error) { console.error("[KNS] token usage save failed:", safeText(error.message || error, 200)); } });
  server.cron("@every 5m", () => { refreshHealth().catch((error) => console.error("[KNS] health check failed:", safeText(error.message || error, 200))); });
  server.cron("@every 5m", () => { scheduleSubscriptionRefresh(); });
  server.cron("0 3 * * *", () => { try { const state = getState(); store.write(state); } catch (error) { console.error("[KNS] daily backup failed:", safeText(error && error.message || error, 200)); } });
  scheduleSubscriptionRefresh();
  syncMachines().catch((error) => console.error("[KNS] initial machine sync failed:", safeText(error.message || error, 200)));
}

function unload() {
  try { flushTokenUsage(); } catch (_) {}
  if (pluginUpdateLockTimer) clearTimeout(pluginUpdateLockTimer);
  pluginUpdateLockTimer = null; pluginUpdateLockToken = ""; maintenanceLock = false;
  pollBusy = false; syncBusy = false; healthBusy = false;
  subscriptionRefreshStopped = true;
  subscriptionRefreshPending = false;
  if (subscriptionRefreshTimer) clearTimeout(subscriptionRefreshTimer);
  subscriptionRefreshTimer = null;
}

module.exports = { load, unload };
