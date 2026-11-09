"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function hex(value) { return Buffer.from(value).toString("hex"); }

function readMasterKey(fsModule, keyPath) {
  if (!fsModule.existsSync(keyPath)) return null;
  const key = fsModule.readFileSync(keyPath);
  if (key.length !== 32) throw new Error("KNS master key file has an invalid length.");
  try { fsModule.chmodSync(keyPath, 0o600); } catch (_) {}
  return key;
}

function getMasterKey(storageDir, fsModule) {
  fsModule = fsModule || fs;
  const configured = typeof process !== "undefined" && process.env ? process.env.KNS_MASTER_KEY : "";
  if (configured) {
    if (!/^[a-f0-9]{64}$/i.test(configured)) throw new Error("KNS_MASTER_KEY must be 64 hexadecimal characters.");
    return Buffer.from(configured, "hex");
  }
  const dir = path.join(storageDir, "kns");
  const keyPath = path.join(dir, "master.key");
  fsModule.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const existing = readMasterKey(fsModule, keyPath);
  if (existing) return existing;

  const key = crypto.randomBytes(32);
  let fd;
  let created = false;
  try {
    // Komari's fs shim implements exclusive open flags, while readFileSync on a
    // missing path may surface the shim's lstat error without Node's ENOENT code.
    fd = fsModule.openSync(keyPath, "wx", 0o600);
    created = true;
    const written = fsModule.writeSync(fd, key, 0, key.length, null);
    if (written !== key.length) throw new Error("KNS master key write was incomplete.");
    fsModule.fsyncSync(fd);
    fsModule.closeSync(fd);
    fd = undefined;
    try { fsModule.chmodSync(keyPath, 0o600); } catch (_) {}
    return key;
  } catch (error) {
    if (fd !== undefined) try { fsModule.closeSync(fd); } catch (_) {}
    let concurrentKey;
    try { concurrentKey = readMasterKey(fsModule, keyPath); }
    catch (readError) {
      if (created) try { fsModule.unlinkSync(keyPath); } catch (_) {}
      throw readError;
    }
    if (concurrentKey) return concurrentKey;
    if (created) try { fsModule.unlinkSync(keyPath); } catch (_) {}
    throw error;
  }
}

function encryptSecret(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return { alg: "A256GCM", iv: hex(iv), tag: hex(cipher.getAuthTag()), data: hex(encrypted) };
}

function decryptSecret(box, key) {
  if (!box || box.alg !== "A256GCM" || !box.iv || !box.tag || typeof box.data !== "string") {
    throw new Error("Encrypted secret has an invalid format.");
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "hex"));
  decipher.setAuthTag(Buffer.from(box.tag, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(box.data, "hex")), decipher.final()]).toString("utf8");
}

function createToken() { return crypto.randomBytes(32).toString("base64url"); }

function hashToken(token, salt) {
  return crypto.createHash("sha256").update(String(salt)).update(":").update(String(token)).digest("hex");
}

function tokenRecord(token) {
  const salt = hex(crypto.randomBytes(16));
  return { salt, hash: hashToken(token, salt) };
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) diff |= (a[i % (a.length || 1)] || 0) ^ (b[i % (b.length || 1)] || 0);
  return diff === 0;
}

function verifyToken(token, record) {
  return !!record && constantTimeEqual(hashToken(token, record.salt), record.hash);
}

module.exports = { createToken, decryptSecret, encryptSecret, getMasterKey, hashToken, tokenRecord, verifyToken };
