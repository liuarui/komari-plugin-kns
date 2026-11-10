"use strict";

const { URLSearchParams: URLSearchParamsConstructor } = require("./url");

function quoteYaml(value) { return JSON.stringify(String(value == null ? "" : value)); }

function base64Url(value) {
  return Buffer.from(String(value), "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function cleanLabel(value) {
  return String(value || "node").replace(/[\r\n\u0000-\u001f]/g, " ").trim().slice(0, 80) || "node";
}

const PROTOCOL_DISPLAY_NAMES = { vless: "VLESS", hysteria2: "Hysteria2", trojan: "Trojan", vmess: "VMess", shadowsocks: "Shadowsocks", tuic: "TUIC", anytls: "AnyTLS" };
function protocolDisplayName(protocol) {
  return PROTOCOL_DISPLAY_NAMES[String(protocol || "").toLowerCase()] || String(protocol || "node");
}
function subscriptionNodeName(protocol, machineName, port) {
  const prefix = protocolDisplayName(protocol) + "-";
  const suffix = port ? "-" + String(port) : "";
  const maxMachine = Math.max(1, 80 - prefix.length - suffix.length);
  const machine = cleanLabel(machineName || "").slice(0, maxMachine) || "node";
  return cleanLabel(prefix + machine + suffix);
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

function alpnValue(instance, tls, fallback) {
  const fromTls = Array.isArray(tls && tls.alpn) ? tls.alpn.filter(Boolean) : [];
  if (fromTls.length) return fromTls;
  const options = instance.options || {};
  if (Array.isArray(options.alpn) && options.alpn.length) return options.alpn.filter(Boolean);
  return fallback ? fallback.slice() : [];
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
  if (tls.allowInsecure === true || tls.allow_insecure === true || (instance.options && instance.options.allowInsecure === true)) proxy["skip-cert-verify"] = true;
  switch (protocol) {
    case "vless":
      proxy.uuid = credValue(credential, ["uuid", "id", "value"]);
      proxy.flow = credValue(credential, ["flow"]) || String((instance.options || {}).flow || "");
      proxy.network = String((instance.listen || {}).transport || "tcp").split("+")[0];
      proxy.udp = true;
      if (security) {
        proxy.tls = true;
        proxy.servername = sni;
        if (security === "reality") {
          const options = instance.options || {};
          proxy["client-fingerprint"] = String(options.fingerprint || "chrome");
          proxy["reality-opts"] = {
            "public-key": String(tlsValue(tls, "publicKey", "public_key") || ""),
            "short-id": String(tlsValue(tls, "shortId", "short_id") || ""),
            ...(options.spiderX ? { "spider-x": String(options.spiderX) } : {}),
          };
        }
        const vlessAlpn = alpnValue(instance, tls, []);
        if (vlessAlpn.length) proxy.alpn = vlessAlpn;
      }
      break;
    case "trojan":
    case "anytls":
      proxy.type = protocol === "anytls" ? "anytls" : "trojan";
      proxy.password = credValue(credential, ["password", "value"]);
      proxy.sni = sni;
      proxy.udp = true;
      const tlsAlpn = alpnValue(instance, tls, []);
      if (tlsAlpn.length) proxy.alpn = tlsAlpn;
      if (security) proxy.tls = true;
      break;
    case "vmess":
      proxy.uuid = credValue(credential, ["uuid", "id", "value"]);
      proxy.alterId = Number(credential.alter_id || credential.alterId || (instance.options || {}).alterId || 0);
      proxy.cipher = String(credential.security || credential.cipher || (instance.options || {}).cipher || "auto");
      proxy.network = String((instance.listen || {}).transport || "tcp").split("+")[0];
      if (security) { proxy.tls = true; proxy.servername = sni; }
      const vmessAlpn = alpnValue(instance, tls, []);
      if (vmessAlpn.length) proxy.alpn = vmessAlpn;
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
      proxy.alpn = alpnValue(instance, tls, ["h3"]);
      if (instance.options && instance.options.upMbps) proxy.up = String(instance.options.upMbps) + " Mbps";
      if (instance.options && instance.options.downMbps) proxy.down = String(instance.options.downMbps) + " Mbps";
      if (instance.options && instance.options.obfs) {
        proxy.obfs = String(instance.options.obfs);
        if (instance.options.obfsPassword) proxy["obfs-password"] = String(instance.options.obfsPassword);
      }
      break;
    case "tuic":
      proxy.uuid = credValue(credential, ["uuid", "id"]);
      proxy.password = credValue(credential, ["password", "value"]);
      proxy.sni = sni;
      proxy["congestion-controller"] = String((instance.options || {}).congestionController || "bbr");
      proxy["udp-relay-mode"] = String((instance.options || {}).udpRelayMode || "native");
      proxy.alpn = alpnValue(instance, tls, ["h3"]);
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
        values.fp = String((instance.options || {}).fingerprint || "chrome");
        if ((instance.options || {}).spiderX) values.spx = String(instance.options.spiderX);
      }
      if (proxy.alpn) values.alpn = proxy.alpn.join(",");
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
      const user = base64Url(proxy.cipher + ":" + proxy.password);
      return "ss://" + user + "@" + server + "#" + label;
    }
    case "hysteria2": {
      const options = instance.options || {};
      return "hysteria2://" + encodeURIComponent(proxy.password) + "@" + server + "?" + query({ sni, alpn: proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? 1 : 0, up: options.upMbps || "", down: options.downMbps || "", obfs: options.obfs || "", "obfs-password": options.obfsPassword || "" }) + "#" + label;
    }
    case "tuic": {
      const options = instance.options || {};
      return "tuic://" + encodeURIComponent(proxy.uuid) + ":" + encodeURIComponent(proxy.password) + "@" + server + "?" + query({ sni, alpn: proxy.alpn.join(","), insecure: proxy["skip-cert-verify"] ? 1 : "", congestion_control: options.congestionControl || "bbr", udp_relay_mode: options.udpRelayMode || "native" }) + "#" + label;
    }
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
      if (proxy.type === "hysteria2") {
        if (proxy.up) item.up_mbps = Number(String(proxy.up).replace(/[^0-9]/g, "")) || undefined;
        if (proxy.down) item.down_mbps = Number(String(proxy.down).replace(/[^0-9]/g, "")) || undefined;
        if (proxy.obfs) item.obfs = { type: proxy.obfs, password: proxy["obfs-password"] || "" };
      }
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
  const displayNameFor = (instance) => {
    const endpoint = instance.endpoint || {};
    const port = endpoint.port || (instance.listen && instance.listen.port) || "";
    return subscriptionNodeName(instance.protocol, machineNames.get(instance.machineUuid) || instance.machineUuid || "", port);
  };
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
    restored.name = displayNameFor(instance);
    if (instance.credential && typeof instance.credential === "object") {
      restored.credential = instance.credential;
    } else if (instance.credentialCiphertext) {
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
  const legacyProtocols = Array.isArray(profile.protocols) && profile.protocols.length ? new Set(profile.protocols) : null;
  const legacyTags = Array.isArray(profile.includeTags) && profile.includeTags.length ? new Set(profile.includeTags) : null;
  for (const legacy of profile.legacy ? (state.legacyNodes || []) : []) {
    if (legacy.enabled === false || !matchesProfileSelection(legacy, selection)) continue;
    if (legacyTags && !(Array.isArray(legacy.tags) && legacy.tags.some((tag) => legacyTags.has(tag)))) continue;
    try {
      const uri = legacy.uri || (legacy.ciphertext && decrypt(legacy.ciphertext));
      if (!uri) continue;
      if (legacyProtocols) {
        const match = String(uri).match(/^([a-z][a-z0-9+.-]*):\/\//i);
        const scheme = match && match[1].toLowerCase();
        const protocol = ({ ss: "shadowsocks", hy2: "hysteria2", hysteria: "hysteria2" })[scheme] || scheme;
        if (!legacyProtocols.has(protocol)) continue;
      }
      uris.push(uri);
    } catch (_) {}
  }
  const skippedCount = Math.max(0, candidateCount - representedInstanceIds.size);
  return { proxies: assignNativeNames(proxies, identities), uris, skippedCount };
}

function clientName(proxy) {
  return cleanLabel(proxy.name).replace(/[,=\r\n]/g, " ");
}

function clientSkipped(proxies, included) {
  return Math.max(0, proxies.length - included.length);
}

function loonLine(proxy) {
  const name = clientName(proxy);
  const server = proxy.server;
  const port = proxy.port;
  const sni = proxy.servername || proxy.sni || "";
  const insecure = proxy["skip-cert-verify"] ? "true" : "false";
  const alpn = Array.isArray(proxy.alpn) && proxy.alpn.length ? "alpn=" + JSON.stringify(proxy.alpn.join(",")) : "";
  switch (proxy.type) {
    case "vless": {
      const parts = ["VLESS", server, String(port), JSON.stringify(proxy.uuid || ""), "transport=" + (proxy.network || "tcp"), "over-tls=" + (proxy.tls ? "true" : "false")];
      if (sni) parts.push("sni=" + sni);
      if (proxy.flow) parts.push("flow=" + proxy.flow);
      if (proxy["reality-opts"]) {
        parts.push("public-key=" + JSON.stringify(proxy["reality-opts"]["public-key"] || ""));
        parts.push("short-id=" + (proxy["reality-opts"]["short-id"] || ""));
        const fingerprint = proxy["client-fingerprint"] || "chrome";
        parts.push("tls-profile=" + (["global", "default", "safari-ios18", "safari-ios-26", "chrome", "chrome147"].includes(fingerprint) ? fingerprint : "chrome"));
      }
      if (alpn) parts.push(alpn);
      parts.push("skip-cert-verify=" + insecure);
      return name + " = " + parts.join(", ");
    }
    case "trojan":
    case "anytls":
      return name + " = " + (proxy.type === "anytls" ? "AnyTLS" : "Trojan") + ", " + server + ", " + port + ", " + JSON.stringify(proxy.password || "") + (sni ? ", sni=" + sni : "") + (alpn ? ", " + alpn : "") + ", skip-cert-verify=" + insecure;
    case "vmess": {
      const parts = ["VMess", server, String(port), proxy.cipher || "auto", JSON.stringify(proxy.uuid || ""), "transport=" + (proxy.network || "tcp"), "over-tls=" + (proxy.tls ? "true" : "false")];
      if (sni) parts.push("sni=" + sni);
      if (proxy.alterId != null) parts.push("alterId=" + proxy.alterId);
      if (alpn) parts.push(alpn);
      parts.push("skip-cert-verify=" + insecure);
      return name + " = " + parts.join(", ");
    }
    case "ss":
      return name + " = Shadowsocks, " + server + ", " + port + ", " + (proxy.cipher || "aes-128-gcm") + ", " + JSON.stringify(proxy.password || "") + ", udp=true";
    case "hysteria2": {
      const parts = ["Hysteria2", server, String(port), JSON.stringify(proxy.password || "")];
      if (sni) parts.push("sni=" + sni);
      if (alpn) parts.push(alpn);
      if (proxy.obfs === "salamander" && proxy["obfs-password"]) parts.push("salamander-password=" + JSON.stringify(proxy["obfs-password"]));
      if (proxy.down) parts.push("download-bandwidth=" + parseInt(proxy.down, 10));
      parts.push("skip-cert-verify=" + insecure);
      return name + " = " + parts.join(", ");
    }
    case "tuic":
      return name + " = TUIC, " + server + ", " + port + ", " + JSON.stringify(proxy.uuid || "") + ", " + JSON.stringify(proxy.password || "") + (sni ? ", sni=" + sni : "") + ", skip-cert-verify=" + insecure;
    default:
      return "";
  }
}

function loon(proxies) {
  const supported = new Set(["vless", "trojan", "anytls", "vmess", "ss", "hysteria2"]);
  const included = proxies.filter((proxy) => supported.has(proxy.type));
  const lines = included.map(loonLine).filter(Boolean);
  const names = included.map(clientName);
  const group = "KNS = select, " + (names.length ? names.join(", ") + ", " : "") + "DIRECT";
  const body = ["[Proxy]", ...lines, "", "[Proxy Group]", group, "", "[Rule]", "FINAL,KNS", ""].join("\n");
  return { body, contentType: "text/plain; charset=utf-8", successCount: lines.length, skipped: clientSkipped(proxies, lines) };
}

function surgeLine(proxy, advancedHysteria2) {
  const name = clientName(proxy);
  const server = proxy.server;
  const port = proxy.port;
  const sni = proxy.servername || proxy.sni || "";
  const insecure = proxy["skip-cert-verify"] ? "true" : "false";
  switch (proxy.type) {
    case "trojan":
      return name + " = trojan, " + server + ", " + port + ", password=" + (proxy.password || "") + (sni ? ", sni=" + sni : "") + ", skip-cert-verify=" + insecure;
    case "vmess":
      return name + " = vmess, " + server + ", " + port + ", username=" + (proxy.uuid || "") + ", tls=true" + (sni ? ", sni=" + sni : "") + ", vmess-aead=true, skip-cert-verify=" + insecure;
    case "ss":
      return name + " = ss, " + server + ", " + port + ", encrypt-method=" + (proxy.cipher || "aes-128-gcm") + ", password=" + (proxy.password || "") + ", udp-relay=true";
    case "hysteria2":
      return name + " = hysteria2, " + server + ", " + port + ", password=" + (proxy.password || "") + (sni ? ", sni=" + sni : "") + (advancedHysteria2 && proxy.alpn && proxy.alpn.length ? ", alpn=" + JSON.stringify(proxy.alpn.join(",")) : "") + (advancedHysteria2 && proxy.down ? ", download-bandwidth=" + parseInt(proxy.down, 10) : "") + (advancedHysteria2 && proxy.obfs === "salamander" && proxy["obfs-password"] ? ", salamander-password=" + JSON.stringify(proxy["obfs-password"]) : "") + ", skip-cert-verify=" + insecure;
    default:
      return "";
  }
}

function surge(proxies, advancedHysteria2) {
  const supported = new Set(["trojan", "vmess", "ss", "hysteria2"]);
  const included = proxies.filter((proxy) => supported.has(proxy.type));
  const lines = included.map((proxy) => surgeLine(proxy, advancedHysteria2)).filter(Boolean);
  const names = included.map(clientName);
  const group = "KNS = select, " + (names.length ? names.join(", ") + ", " : "") + "DIRECT";
  const body = ["[Proxy]", ...lines, "", "[Proxy Group]", group, "", "[Rule]", "FINAL,KNS", ""].join("\n");
  return { body, contentType: "text/plain; charset=utf-8", successCount: lines.length, skipped: clientSkipped(proxies, lines) };
}

function quanxLine(proxy) {
  const name = clientName(proxy);
  const server = proxy.server;
  const port = proxy.port;
  const sni = proxy.servername || proxy.sni || "";
  const insecure = proxy["skip-cert-verify"] ? "false" : "true";
  switch (proxy.type) {
    case "vless": {
      const reality = proxy["reality-opts"];
      return "vless=" + hostPort(server, port) + ", method=none, password=" + (proxy.uuid || "") + ", obfs=over-tls" + (sni ? ", obfs-host=" + sni + ", tls-host=" + sni : "") + (reality ? ", reality-base64-pubkey=" + (reality["public-key"] || "") + ", reality-hex-shortid=" + (reality["short-id"] || "") : "") + (proxy.flow ? ", vless-flow=" + proxy.flow : "") + ", tls-verification=" + insecure + ", fast-open=false, udp-relay=true, tag=" + name;
    }
    case "trojan":
      return "trojan=" + server + ":" + port + ", password=" + (proxy.password || "") + ", over-tls=true" + (sni ? ", tls-host=" + sni : "") + ", tls-verification=" + insecure + ", tag=" + name;
    case "vmess":
      return "vmess=" + server + ":" + port + ", method=chacha20-poly1305, password=" + (proxy.uuid || "") + ", obfs=over-tls" + (sni ? ", obfs-host=" + sni + ", tls-host=" + sni : "") + ", tls-verification=" + insecure + ", tag=" + name;
    case "ss":
      return "shadowsocks=" + server + ":" + port + ", method=" + (proxy.cipher || "aes-128-gcm") + ", password=" + (proxy.password || "") + ", tag=" + name;
    default:
      return "";
  }
}

function quanx(proxies) {
  const supported = new Set(["vless", "trojan", "vmess", "ss"]);
  const included = proxies.filter((proxy) => supported.has(proxy.type));
  const lines = included.map(quanxLine).filter(Boolean);
  const names = included.map(clientName);
  const body = ["[server_local]", ...lines, "", "[policy]", "static=KNS, " + (names.length ? names.join(", ") + ", " : "") + "direct", "", "[filter_local]", "final, KNS", ""].join("\n");
  return { body, contentType: "text/plain; charset=utf-8", successCount: lines.length, skipped: clientSkipped(proxies, lines) };
}

function quan(proxies) {
  const result = quanx(proxies);
  const body = result.body.replace("[server_local]", "[server]").replace("[filter_local]", "[filter]");
  return Object.assign({}, result, { body });
}

function base64UriList(uris) {
  const body = uris.length ? Buffer.from(uris.join("\n") + "\n", "utf8").toString("base64") : "";
  return { body, contentType: "text/plain; charset=utf-8", successCount: uris.length, skipped: 0 };
}

function uriByScheme(uris, scheme, total) {
  const lines = uris.filter((uri) => uri.startsWith(scheme + "://"));
  return { body: lines.join("\n") + (lines.length ? "\n" : ""), contentType: "text/plain; charset=utf-8", successCount: lines.length, skipped: Math.max(0, Number(total || 0) - lines.length) };
}

function sssub(uris, total) {
  const lines = uris.filter((uri) => uri.startsWith("ss://"));
  return { body: lines.length ? Buffer.from(lines.join("\n") + "\n", "utf8").toString("base64") : "", contentType: "text/plain; charset=utf-8", successCount: lines.length, skipped: Math.max(0, Number(total || 0) - lines.length) };
}

function ssd(proxies) {
  const servers = proxies.filter((proxy) => proxy.type === "ss").map((proxy) => ({
    server: proxy.server,
    port: proxy.port,
    encryption: proxy.cipher || "aes-128-gcm",
    password: proxy.password || "",
    remarks: clientName(proxy),
  }));
  const payload = { airport: "KNS", port: 1, encryption: "aes-128-gcm", password: "kns", servers };
  return { body: servers.length ? "ssd://" + Buffer.from(JSON.stringify(payload), "utf8").toString("base64") : "", contentType: "text/plain; charset=utf-8", successCount: servers.length, skipped: proxies.length - servers.length };
}

function renderSubscription(prepared, format) {
  const { proxies, uris, skippedCount } = prepared;
  const clientResult = (result) => ({ body: result.body, contentType: result.contentType, successCount: result.successCount, skippedCount: skippedCount + result.skipped });
  switch (format) {
    case "uri": return { body: uris.join("\n") + (uris.length ? "\n" : ""), contentType: "text/plain; charset=utf-8", successCount: uris.length, skippedCount };
    case "mihomo-full": return { body: mihomo(proxies, false), contentType: "application/yaml; charset=utf-8", successCount: proxies.length, skippedCount };
    case "mihomo-provider": return { body: mihomo(proxies, true), contentType: "application/yaml; charset=utf-8", successCount: proxies.length, skippedCount };
    case "singbox-outbounds": return { body: JSON.stringify(singbox(proxies, false), null, 2) + "\n", contentType: "application/json; charset=utf-8", successCount: proxies.length, skippedCount };
    case "singbox-full": return { body: JSON.stringify(singbox(proxies, true), null, 2) + "\n", contentType: "application/json; charset=utf-8", successCount: proxies.length, skippedCount };
    case "loon": return clientResult(loon(proxies));
    case "surge": return clientResult(surge(proxies, true));
    case "surfboard": return clientResult(surge(proxies, false));
    case "quanx": return clientResult(quanx(proxies));
    case "quan": return clientResult(quan(proxies));
    case "stash":
    case "mellow": return { body: mihomo(proxies, false), contentType: "application/yaml; charset=utf-8", successCount: proxies.length, skippedCount };
    case "shadowrocket":
    case "v2rayn":
    case "v2rayng": return clientResult(base64UriList(uris));
    case "ss": return clientResult(uriByScheme(uris, "ss", proxies.length));
    case "sssub": return clientResult(sssub(uris, proxies.length));
    case "ssd": return clientResult(ssd(proxies));
    case "trojan": return clientResult(uriByScheme(uris, "trojan", proxies.length));
    case "vless": return clientResult(uriByScheme(uris, "vless", proxies.length));
    case "hysteria2": return clientResult(uriByScheme(uris, "hysteria2", proxies.length));
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

module.exports = { buildSubscriptions, buildSubscription, commonProxy, encodeUri, filterInstances, hostPort, mihomo, quoteYaml, singbox, subscriptionNodeName };
