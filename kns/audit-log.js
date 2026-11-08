"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_RETENTION_DAYS = 365;
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_SEGMENT_BYTES = 256 * 1024;
const MAX_RECORD_BYTES = 64 * 1024;
const SEGMENT_RE = /^audit-(\d{4}-\d{2}-\d{2})-(\d{6})\.jsonl$/;

function createAuditLog(storageDir, options) {
  const settings = Object.assign({ retentionDays: DEFAULT_RETENTION_DAYS, maxBytes: DEFAULT_MAX_BYTES, segmentBytes: DEFAULT_SEGMENT_BYTES }, options || {});
  const root = path.join(path.resolve(storageDir), "kns", "audit");
  const metadataPath = path.join(root, "retention.json");

  function syncFile(filename) {
    const fd = fs.openSync(filename, "r");
    try { fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  }

  function syncDirectory(directory) {
    let fd;
    try { fd = fs.openSync(directory, "r"); fs.fsyncSync(fd); }
    catch (_) {}
    finally { if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {} }
  }

  function ensureDirectory() {
    fs.mkdirSync(path.dirname(root), { recursive: true, mode: 0o700 });
    try { fs.chmodSync(path.dirname(root), 0o700); } catch (_) {}
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("KNS audit log refuses a non-directory storage path.");
    try { fs.chmodSync(root, 0o700); } catch (_) {}
  }

  function initialMetadata() {
    return {
      format: "KNS-AUDIT-RETENTION-v1",
      retentionDays: settings.retentionDays,
      maxBytes: settings.maxBytes,
      segmentBytes: settings.segmentBytes,
      prunedSegments: 0,
      prunedRecords: 0,
      prunedBytes: 0,
      prunedFrom: "",
      prunedThrough: "",
      lastPrunedAt: "",
      pending: null,
      legacyImported: false,
    };
  }

  function readMetadata() {
    if (!fs.existsSync(metadataPath)) return initialMetadata();
    const stat = fs.lstatSync(metadataPath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("KNS audit retention metadata is not a regular file; audit records were left untouched.");
    const value = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    if (!value || value.format !== "KNS-AUDIT-RETENTION-v1" || !Number.isInteger(value.prunedSegments) || !Number.isInteger(value.prunedRecords) || !Number.isInteger(value.prunedBytes)) {
      throw new Error("KNS audit retention metadata is invalid; audit records were left untouched.");
    }
    return Object.assign(initialMetadata(), value);
  }

  function writeMetadata(value) {
    const temporary = metadataPath + "." + crypto.randomBytes(8).toString("hex") + ".tmp";
    try {
      fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { mode: 0o600, flag: "wx" });
      try { fs.chmodSync(temporary, 0o600); } catch (_) {}
      syncFile(temporary);
      fs.renameSync(temporary, metadataPath);
      try { fs.chmodSync(metadataPath, 0o600); } catch (_) {}
      syncDirectory(root);
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch (_) {}
      throw error;
    }
  }

  function segmentFiles() {
    return fs.readdirSync(root).filter((name) => {
      if (!SEGMENT_RE.test(name)) return false;
      const stat = fs.lstatSync(path.join(root, name));
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("KNS audit segment is not a regular file; records were left untouched: " + name);
      return true;
    }).sort();
  }

  function readSegment(name) {
    const content = fs.readFileSync(path.join(root, name), "utf8");
    const result = [];
    for (const line of content.split("\n")) {
      if (!line) continue;
      let event;
      try { event = JSON.parse(line); }
      catch (_) { throw new Error("KNS audit segment is corrupt and was left untouched: " + name); }
      if (!event || typeof event.id !== "string" || typeof event.at !== "string" || typeof event.action !== "string") {
        throw new Error("KNS audit segment contains an invalid record and was left untouched: " + name);
      }
      result.push(event);
    }
    return result;
  }

  function completePending(metadata) {
    const pending = metadata.pending;
    if (!pending) return;
    if (!SEGMENT_RE.test(String(pending.file || "")) || !Number.isInteger(pending.records) || !Number.isInteger(pending.bytes)) {
      throw new Error("KNS audit retention checkpoint is invalid; audit records were left untouched.");
    }
    const filename = path.join(root, pending.file);
    if (fs.existsSync(filename)) fs.unlinkSync(filename);
    metadata.prunedSegments += 1;
    metadata.prunedRecords += pending.records;
    metadata.prunedBytes += pending.bytes;
    if (pending.firstAt && (!metadata.prunedFrom || pending.firstAt < metadata.prunedFrom)) metadata.prunedFrom = pending.firstAt;
    if (pending.lastAt && (!metadata.prunedThrough || pending.lastAt > metadata.prunedThrough)) metadata.prunedThrough = pending.lastAt;
    metadata.lastPrunedAt = new Date().toISOString();
    metadata.pending = null;
    writeMetadata(metadata);
  }

  function prune() {
    ensureDirectory();
    const metadata = readMetadata();
    completePending(metadata);
    const files = segmentFiles();
    let totalBytes = files.reduce((sum, name) => sum + fs.statSync(path.join(root, name)).size, 0);
    const cutoff = Date.now() - settings.retentionDays * 24 * 60 * 60 * 1000;
    for (const name of files) {
      const match = SEGMENT_RE.exec(name);
      const expired = Date.parse(match[1] + "T00:00:00Z") < cutoff;
      if (!expired && totalBytes <= settings.maxBytes) break;
      const fullPath = path.join(root, name);
      const events = readSegment(name);
      const bytes = fs.statSync(fullPath).size;
      const timestamps = events.map((event) => event.at).sort();
      metadata.pending = {
        file: name,
        records: events.length,
        bytes,
        firstAt: events.length ? timestamps[0] : "",
        lastAt: events.length ? timestamps[timestamps.length - 1] : "",
        reason: expired ? "age" : "size",
      };
      writeMetadata(metadata);
      completePending(metadata);
      totalBytes -= bytes;
    }
    return metadata;
  }

  function validateEvent(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.id !== "string" || !value.id || typeof value.at !== "string" || typeof value.action !== "string" || !value.action) {
      throw new Error("KNS audit event is invalid.");
    }
    const line = JSON.stringify({ id: value.id, at: value.at, action: value.action, actor: String(value.actor || "system"), details: value.details && typeof value.details === "object" ? value.details : {} }) + "\n";
    if (Buffer.byteLength(line, "utf8") > MAX_RECORD_BYTES) throw new Error("KNS audit event exceeds the 64 KiB record limit.");
    return line;
  }

  function appendWithoutPrune(event) {
    const line = validateEvent(event);
    const dateValue = new Date(event.at);
    const day = Number.isNaN(dateValue.getTime()) ? new Date().toISOString().slice(0, 10) : dateValue.toISOString().slice(0, 10);
    const matches = segmentFiles().filter((name) => name.startsWith("audit-" + day + "-"));
    let sequence = matches.length ? Number(SEGMENT_RE.exec(matches[matches.length - 1])[2]) : 0;
    let filename = "audit-" + day + "-" + ("000000" + sequence).slice(-6) + ".jsonl";
    if (matches.length && fs.statSync(path.join(root, filename)).size + Buffer.byteLength(line, "utf8") > settings.segmentBytes) {
      sequence += 1;
      filename = "audit-" + day + "-" + ("000000" + sequence).slice(-6) + ".jsonl";
    }
    const destination = path.join(root, filename);
    if (fs.existsSync(destination)) {
      const stat = fs.lstatSync(destination);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("KNS audit segment is not a regular file; records were left untouched: " + filename);
    }
    const fd = fs.openSync(destination, "a", 0o600);
    try {
      const bytes = Buffer.from(line, "utf8");
      let offset = 0;
      while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    try { fs.chmodSync(destination, 0o600); } catch (_) {}
  }

  function append(event) {
    ensureDirectory();
    const metadata = readMetadata();
    completePending(metadata);
    appendWithoutPrune(event);
    prune();
    return event;
  }

  function importEvents(events, markLegacy) {
    ensureDirectory();
    const metadata = readMetadata();
    completePending(metadata);
    if (markLegacy && metadata.legacyImported) return 0;
    const knownIds = new Set();
    for (const name of segmentFiles()) for (const event of readSegment(name)) knownIds.add(event.id);
    let added = 0;
    for (const event of Array.isArray(events) ? events : []) {
      if (!event || typeof event.id !== "string" || knownIds.has(event.id)) continue;
      appendWithoutPrune(event);
      knownIds.add(event.id);
      added += 1;
    }
    if (markLegacy) metadata.legacyImported = true;
    writeMetadata(metadata);
    prune();
    return added;
  }

  function list(limit, before) {
    ensureDirectory();
    const metadata = prune();
    const count = Math.max(1, Math.min(5000, Number(limit) || 100));
    const cursor = String(before || "");
    let cursorFound = !cursor;
    const newestFirst = [];
    for (const name of segmentFiles().reverse()) {
      const segment = readSegment(name);
      for (let index = segment.length - 1; index >= 0; index -= 1) {
        const event = segment[index];
        if (!cursorFound) {
          if (event.id === cursor) cursorFound = true;
          continue;
        }
        newestFirst.push(event);
        if (newestFirst.length > count) break;
      }
      if (newestFirst.length > count) break;
    }
    if (!cursorFound) throw new Error("KNS audit cursor was not found; it may be outside the retention period.");
    const hasMore = newestFirst.length > count;
    const events = newestFirst.slice(0, count).reverse();
    return { events, hasMore, nextCursor: hasMore && events.length ? events[0].id : "", retention: publicRetention(metadata) };
  }

  function publicRetention(metadata) {
    return {
      retentionDays: settings.retentionDays,
      maxBytes: settings.maxBytes,
      segmentBytes: settings.segmentBytes,
      prunedSegments: metadata.prunedSegments,
      prunedRecords: metadata.prunedRecords,
      prunedBytes: metadata.prunedBytes,
      prunedFrom: metadata.prunedFrom,
      prunedThrough: metadata.prunedThrough,
      lastPrunedAt: metadata.lastPrunedAt,
      pending: !!metadata.pending,
    };
  }

  function retention() {
    ensureDirectory();
    const metadata = readMetadata();
    completePending(metadata);
    return publicRetention(metadata);
  }

  function importLegacy(events) { return importEvents(events, true); }
  function importHistory(events) { return importEvents(events, false); }

  return { append, importHistory, importLegacy, list, retention, root };
}

module.exports = { createAuditLog };
