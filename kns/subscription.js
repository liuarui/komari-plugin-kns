"use strict";

const { URLSearchParams: URLSearchParamsConstructor } = require("./url");

function quoteYaml(value) { return JSON.stringify(String(value == null ? "" : value)); }

function cleanLabel(value) {
  return String(value || "node").replace(/[\r\n\u0000-\u001f]/g, " ").trim().slice(0, 80) || "node";
}

function hostPort(host, port) {
  const value = String(host || "");
  return (value.includes(":") && value[0] !== "[" ? "[" + value + "]" : value) + ":" + Number(port);
}

function query(values) {
  const out = new URLSearchParamsConstructor();
  Object.keys(values).sort().forEach((key) => {
    const value = values[key];
    if (value !== undefined && value !== null && String(value) !== "") out.set(key, String(value));
  });
  return out.toString();
}

function credValue(credential, names) {
  for (const name of names) if (credential && credential[name] != null) return String(credential[name]);
  return "";
}

function tlsValue(tls, camel, snake) {
  return tls && (tls[camel] != null ? tls[camel] : tls[snake]);
}

function endpointOf(instance) {
  const endpoint = instance.endpoint || {};
  const listen = instance.listen || {};
  return { host: String(endpoint.host || ""), port: Number(endpoint.port || listen.port || 0), source: endpoint.source || "unknown" };
}

function commonProxy(instance) {
  const credential = instance.credential || {};
  const tls = instance.tls || {};
  const endpoint = endpointOf(instance);
  const protocol = String(instance.protocol || "").toLowerCase();
  const name = cleanLabel(instance.name || instance.tag || (protocol + "-" + String(instance.id || "node").slice(0, 8)));
  const sni = String(tlsValue(tls, "sni", "server_name") || "");
  const security = String(tls.security || (tls.enabled ? "tls" : ""));
  const proxy = { name, type: protocol, server: endpoint.host, port: endpoint.port };
  if (tls.allowInsecure === true || tls.allow_insecure === true) proxy["skip-cert-verify"] = true;
  switch (protocol) {
    case "vless":
      proxy.uuid = credValue(credential, ["uuid", "id", "value"]);
      proxy.flow = credValue(credential, ["flow"]);
      proxy.network = String((instance.listen || {}).transport || "tcp").split("+")[0];
      proxy.udp = true;
      if (security) {
        proxy.tls = true;
        proxy.servername = sni;
        if (security === "reality") {
          proxy["client-fingerprint"] = "chrome";
          proxy["reality-opts"] = {
            "public-key": String(tlsValue(tls, "publicKey", "public_key") || ""),
            "short-id": String(tlsValue(tls, "shortId", "short_id") || ""),
          };
        }
      }
      break;
    case "trojan":
    case "anytls":
      proxy.type = protocol === "anytls" ? "anytls" : "trojan";
      proxy.password = credValue(credential, ["password", "value"]);
      proxy.sni = sni;
      proxy.udp = true;
      if (Array.isArray(tls.alpn) && tls.alpn.length) proxy.alpn = tls.alpn;
      if (security) proxy.tls = true;
      break;
    case "vmess":
      proxy.uuid = credValue(credential, ["uuid", "id", "value"]);
      proxy.alterId = Number(credential.alter_id || credential.alterId || 0);
      proxy.cipher = String(credential.security || credential.cipher || "auto");
      proxy.network = String((instance.listen || {}).transport || "tcp").split("+")[0];
      if (security) { proxy.tls = true; proxy.servername = sni; }
      if (Array.isArray(tls.alpn) && tls.alpn.length) proxy.alpn = tls.alpn;
      break;
    case "shadowsocks":
      proxy.type = "ss";
      proxy.cipher = credValue(credential, ["method", "cipher"]);
      proxy.password = credValue(credential, ["password", "value"]);
      proxy.udp = true;
      break;
    case "hysteria2":
      proxy.password = credValue(credential, ["password", "auth", "value"]);
      proxy.sni = sni;
      proxy.alpn = Array.isArray(tls.alpn) ? tls.alpn : ["h3"];
      if (instance.options && instance.options.upMbps) proxy.up = String(instance.options.upMbps) + " Mbps";
      if (instance.options && instance.options.downMbps) proxy.down = String(instance.options.downMbps) + " Mbps";
      break;
    case "tuic":
      proxy.uuid = credValue(credential, ["uuid", "id"]);
      proxy.password = credValue(credential, ["password", "value"]);
      proxy.sni = sni;
      proxy["congestion-controller"] = String((instance.options || {}).congestionController || "bbr");
      proxy["udp-relay-mode"] = String((instance.options || {}).udpRelayMode || "native");
      proxy.alpn = Array.isArray(tls.alpn) ? tls.alpn : ["h3"];
      break;
    default: return null;
  }
  return proxy;
}

function encodeUri(proxy, instance) {
  const endpoint = endpointOf(instance);
  const server = hostPort(endpoint.host, endpoint.port);
  const label = encodeURIComponent(cleanLabel(proxy.name));
  const security = String((instance.tls || {}).security || "");
  const sni = String(tlsValue(instance.tls || {}, "sni", "server_name") || "");
  switch (proxy.type) {
    case "vless": {
      const values = { encryption: "none", type: (instance.listen || {}).transport || "tcp", security };
      if (sni) values.sni = sni;
      if (proxy.flow) values.flow = proxy.flow;
      if (security === "reality") {
        values.pbk = tlsValue(instance.tls, "publicKey", "public_key") || "";
        values.sid = tlsValue(instance.tls, "shortId", "short_id") || "";
        values.fp = "chrome";
      }
      return "vless://" + encodeURIComponent(proxy.uuid) + "@" + server + "?" + query(values) + "#" + label;
    }
    case "trojan":
    case "anytls": {
      const protocol = proxy.type;
      const values = { security: security || "tls", sni, type: (instance.listen || {}).transport || "tcp", alpn: proxy.alpn && proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? 1 : "" };
      return protocol + "://" + encodeURIComponent(proxy.password) + "@" + server + "?" + query(values) + "#" + label;
    }
    case "vmess": {
      const payload = { v: "2", ps: cleanLabel(proxy.name), add: endpoint.host, port: String(endpoint.port), id: proxy.uuid, aid: String(proxy.alterId), scy: proxy.cipher, net: proxy.network, type: "none", host: sni, tls: security ? "tls" : "", alpn: proxy.alpn && proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? "1" : "" };
      return "vmess://" + Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
    }
    case "ss": {
      const user = Buffer.from(proxy.cipher + ":" + proxy.password, "utf8").toString("base64").replace(/=+$/, "");
      return "ss://" + user + "@" + server + "#" + label;
    }
    case "hysteria2":
      return "hysteria2://" + encodeURIComponent(proxy.password) + "@" + server + "?" + query({ sni, alpn: proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? 1 : 0 }) + "#" + label;
    case "tuic":
      return "tuic://" + encodeURIComponent(proxy.uuid) + ":" + encodeURIComponent(proxy.password) + "@" + server + "?" + query({ sni, alpn: proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? 1 : "" }) + "#" + label;
    default: return "";
  }
}

function profileSelection(profile) {
  return {
    ids: Array.isArray(profile.instanceIds) && profile.instanceIds.length ? new Set(profile.instanceIds) : null,
    allowedMachines: Array.isArray(profile.machineUuids) && profile.machineUuids.length ? new Set(profile.machineUuids) : null,
    deniedMachines: new Set(Array.isArray(profile.excludeMachineUuids) ? profile.excludeMachineUuids : []),
  };
}

function matchesProfileSelection(record, selection) {
  if (selection.ids && !selection.ids.has(record.id)) return false;
  if (selection.allowedMachines || selection.deniedMachines.size) {
    if (!record.machineUuid) return false;
    if (selection.allowedMachines && !selection.allowedMachines.has(record.machineUuid)) return false;
    if (selection.deniedMachines.has(record.machineUuid)) return false;
  }
  return true;
}

function filterInstances(state, profile) {
  const selection = profileSelection(profile);
  const protocols = Array.isArray(profile.protocols) && profile.protocols.length ? new Set(profile.protocols) : null;
  const tags = Array.isArray(profile.includeTags) && profile.includeTags.length ? new Set(profile.includeTags) : null;
  return state.instances.filter((instance) => {
    if (!instance.enabled || instance.publish === false || instance.deletedAt || instance.remoteStatus && instance.remoteStatus.installed === false) return false;
    if (instance.nat && instance.nat.mappingConflict) return false;
    const hostHealth = instance.health && instance.health.hosts || {};
    const hosts = Array.isArray(instance.endpoint && instance.endpoint.hosts) && instance.endpoint.hosts.length ? instance.endpoint.hosts : [instance.endpoint && instance.endpoint.host];
    const allHostsUnhealthy = hosts.filter(Boolean).length && hosts.filter(Boolean).every((host) => hostHealth[host] && hostHealth[host].state === "unhealthy");
    if (profile.excludeUnhealthy !== false && (allHostsUnhealthy || (!Object.keys(hostHealth).length && instance.health && instance.health.state === "unhealthy"))) return false;
    if (!matchesProfileSelection(instance, selection)) return false;
    if (protocols && !protocols.has(instance.protocol)) return false;
    if (tags && tags.size && !(instance.tags || []).some((tag) => tags.has(tag))) return false;
    const endpoint = endpointOf(instance);
    return !!endpoint.host && !!endpoint.port;
  });
}

function yamlProxy(proxy) {
  const lines = [];
  Object.keys(proxy).forEach((key) => {
    const value = proxy[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      lines.push("  " + key + ":");
      Object.keys(value).forEach((child) => lines.push("    " + quoteYaml(child) + ": " + quoteYaml(value[child])));
    } else if (Array.isArray(value)) lines.push("  " + key + ": [" + value.map(quoteYaml).join(", ") + "]");
    else if (typeof value === "boolean" || typeof value === "number") lines.push("  " + key + ": " + String(value));
    else lines.push("  " + key + ": " + quoteYaml(value));
  });
  return lines.join("\n");
}

function mihomo(proxies, providerOnly) {
  const output = ["proxies:"];
  proxies.forEach((proxy) => output.push("-\n" + yamlProxy(proxy)));
  if (!providerOnly) {
    output.push("proxy-groups:");
    output.push("  - name: KNS");
    output.push("    type: select");
    output.push("    proxies: [" + proxies.map((proxy) => quoteYaml(proxy.name)).join(", ") + (proxies.length ? ", " : "") + '"DIRECT"]');
    output.push("rules:");
    output.push("  - MATCH,KNS");
  }
  return output.join("\n") + "\n";
}

function singbox(proxies, full) {
  const outbounds = proxies.map((proxy) => {
    const item = { type: proxy.type === "ss" ? "shadowsocks" : proxy.type, tag: proxy.name, server: proxy.server, server_port: proxy.port };
    if (proxy.uuid) item.uuid = proxy.uuid;
    if (proxy.password) item.password = proxy.password;
    if (proxy.flow) item.flow = proxy.flow;
    if (proxy.cipher) {
      if (proxy.type === "vmess") item.security = proxy.cipher;
      else item.method = proxy.cipher;
    }
    if (proxy.alterId != null) item.alter_id = proxy.alterId;
    if (proxy["congestion-controller"]) item.congestion_control = proxy["congestion-controller"];
    if (proxy["udp-relay-mode"]) item.udp_relay_mode = proxy["udp-relay-mode"];
    if (proxy.type === "vless" || proxy.type === "vmess" || proxy.type === "trojan" || proxy.type === "anytls") {
      item.tls = { enabled: !!proxy.tls, server_name: proxy.servername || proxy.sni || "" };
      if (proxy.alpn) item.tls.alpn = proxy.alpn;
      if (proxy["skip-cert-verify"] === true) item.tls.insecure = true;
      if (proxy["reality-opts"]) {
        item.tls.reality = { enabled: true, public_key: proxy["reality-opts"]["public-key"], short_id: proxy["reality-opts"]["short-id"] };
        item.tls.utls = { enabled: true, fingerprint: proxy["client-fingerprint"] || "chrome" };
      }
    } else if (proxy.type === "hysteria2" || proxy.type === "tuic") {
      item.tls = { enabled: true, server_name: proxy.sni || "", alpn: proxy.alpn };
      if (proxy["skip-cert-verify"] === true) item.tls.insecure = true;
    }
    if (proxy.network && proxy.network !== "tcp") item.transport = { type: proxy.network };
    return item;
  });
  if (!full) return { outbounds };
  const tags = proxies.map((proxy) => proxy.name);
  outbounds.push({ type: "direct", tag: "direct" }, { type: "block", tag: "block" });
  return {
    log: { level: "info", timestamp: true },
    dns: { servers: [{ type: "local", tag: "local" }], final: "local" },
    inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 2080 }],
    outbounds,
    route: { auto_detect_interface: true, final: tags[0] || "direct" },
  };
}

function assignNativeNames(proxies, identities) {
  const reserved = new Set(["direct", "block", "DIRECT", "REJECT", "KNS"]);
  const counts = new Map();
  for (const proxy of proxies) counts.set(proxy.name, (counts.get(proxy.name) || 0) + 1);
  // Reserve user labels too, so a generated suffix cannot steal another node's name.
  const used = new Set([...reserved, ...counts.keys()]);
  const named = proxies.map((proxy) => Object.assign({}, proxy));
  const order = proxies.map((_, index) => index).sort((a, b) => identities[a].key < identities[b].key ? -1 : identities[a].key > identities[b].key ? 1 : 0);
  for (const index of order) {
    const proxy = named[index];
    if (counts.get(proxy.name) === 1 && !reserved.has(proxy.name)) continue;
    const suffix = identities[index].suffix;
    const base = proxy.name.slice(0, Math.max(1, 79 - suffix.length)) + "-" + suffix;
    let name = base;
    let sequence = 2;
    while (used.has(name)) {
      const tail = "-" + sequence++;
      name = base.slice(0, 80 - tail.length) + tail;
    }
    proxy.name = name;
    used.add(name);
  }
  return named;
}

function prepareSubscription(state, profile, decrypt) {
  const selected = filterInstances(state, profile);
  const sortBy = profile.sortBy || "name";
  const machineNames = new Map((state.machines || []).map((machine) => [machine.uuid, machine.name || machine.uuid]));
  const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
  selected.sort((a, b) => {
    const left = sortBy === "protocol" ? a.protocol : sortBy === "endpoint" ? (a.endpoint && a.endpoint.host || "") : sortBy === "machine" ? (machineNames.get(a.machineUuid) || a.machineUuid || "") : a.name || a.id;
    const right = sortBy === "protocol" ? b.protocol : sortBy === "endpoint" ? (b.endpoint && b.endpoint.host || "") : sortBy === "machine" ? (machineNames.get(b.machineUuid) || b.machineUuid || "") : b.name || b.id;
    return compare(String(left).toLowerCase(), String(right).toLowerCase()) || compare(String(a.id), String(b.id));
  });
  const proxies = [];
  const identities = [];
  const uris = [];
  const representedInstanceIds = new Set();
  const candidateCount = (state.instances || []).filter((instance) => instance.enabled && instance.publish !== false && !instance.deletedAt).length;
  const connectionFingerprints = new Set();
  for (const instance of selected) {
    const restored = Object.assign({}, instance);
    if (instance.credentialCiphertext) {
      try {
        restored.credential = JSON.parse(decrypt(instance.credentialCiphertext));
      } catch (_) {
        // One unreadable credential must not block the whole snapshot.
        console.warn("[KNS] subscription skipped instance with unreadable credential:", String(instance.id || "node").slice(0, 80));
        continue;
      }
    }
    const endpoint = restored.endpoint || {};
    let hosts = Array.isArray(endpoint.hosts) && endpoint.hosts.length ? endpoint.hosts : [endpoint.host];
    if (["ipv4", "ipv6"].includes(profile.addressMode)) {
      const net = require("net");
      const expectedFamily = profile.addressMode === "ipv4" ? 4 : 6;
      hosts = hosts.filter((host) => { const family = net.isIP(String(host)); return !family || family === expectedFamily; });
    }
    const hostHealth = restored.health && restored.health.hosts || {};
    if (profile.excludeUnhealthy !== false) hosts = hosts.filter((host) => !(hostHealth[host] && hostHealth[host].state === "unhealthy"));
    for (let index = 0; index < hosts.length; index += 1) {
      if (!hosts[index]) continue;
      const copy = Object.assign({}, restored, { endpoint: Object.assign({}, endpoint, { host: hosts[index] }) });
      if (hosts.length > 1) copy.name = cleanLabel(restored.name || restored.tag || restored.id) + (String(hosts[index]).includes(":") ? "-IPv6" : "-IPv4");
      const proxy = commonProxy(copy);
      if (!proxy) continue;
      const fingerprintData = Object.assign({}, proxy);
      delete fingerprintData.name;
      const fingerprint = JSON.stringify(fingerprintData);
      if (connectionFingerprints.has(fingerprint)) continue;
      connectionFingerprints.add(fingerprint);
      proxies.push(proxy);
      const family = require("net").isIP(proxy.server);
      identities.push({
        key: JSON.stringify([String(instance.id || "node"), proxy.server, proxy.port, proxy.type]),
        suffix: cleanLabel(instance.id || "node").slice(0, 40) + "-" + (family ? "IPv" + family : "host") + "-" + proxy.port,
      });
      representedInstanceIds.add(instance.id);
      const uri = encodeUri(proxy, copy);
      if (uri) uris.push(uri);
    }
  }
  const selection = profileSelection(profile);
  for (const legacy of profile.legacy ? (state.legacyNodes || []) : []) {
    if (!legacy.ciphertext || legacy.enabled === false || !matchesProfileSelection(legacy, selection)) continue;
    try {
      const uri = decrypt(legacy.ciphertext);
      if (uri) uris.push(uri);
    } catch (_) {}
  }
  const skippedCount = Math.max(0, candidateCount - representedInstanceIds.size);
  return { proxies: assignNativeNames(proxies, identities), uris, skippedCount };
}

function renderSubscription(prepared, format) {
  const { proxies, uris, skippedCount } = prepared;
  switch (format) {
    case "uri": return { body: uris.join("\n") + (uris.length ? "\n" : ""), contentType: "text/plain; charset=utf-8", successCount: uris.length, skippedCount };
    case "mihomo-full": return { body: mihomo(proxies, false), contentType: "application/yaml; charset=utf-8", successCount: proxies.length, skippedCount };
    case "mihomo-provider": return { body: mihomo(proxies, true), contentType: "application/yaml; charset=utf-8", successCount: proxies.length, skippedCount };
    case "singbox-outbounds": return { body: JSON.stringify(singbox(proxies, false), null, 2) + "\n", contentType: "application/json; charset=utf-8", successCount: proxies.length, skippedCount };
    case "singbox-full": return { body: JSON.stringify(singbox(proxies, true), null, 2) + "\n", contentType: "application/json; charset=utf-8", successCount: proxies.length, skippedCount };
    default: throw new Error("Unsupported subscription format.");
  }
}

function buildSubscription(state, profile, format, decrypt) {
  return renderSubscription(prepareSubscription(state, profile, decrypt), format);
}

function buildSubscriptions(state, profile, formats, decrypt) {
  const prepared = prepareSubscription(state, profile, decrypt);
  return Object.fromEntries(formats.map((format) => [format, renderSubscription(prepared, format)]));
}

module.exports = { buildSubscriptions, buildSubscription, commonProxy, encodeUri, filterInstances, hostPort, mihomo, quoteYaml, singbox };
