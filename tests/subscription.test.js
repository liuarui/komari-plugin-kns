"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const secrets = require("../kns/crypto");
const { buildSubscription, hostPort } = require("../kns/subscription");

const key = Buffer.alloc(32, 9);
function encrypted(value) { return secrets.encryptSecret(JSON.stringify(value), key); }

test("URI encoding brackets IPv6 and preserves protocol credentials", () => {
  const state = {
    legacyNodes: [],
    instances: [{
      id: "vless_1", machineUuid: "machine", name: "東京 node", protocol: "vless", enabled: true, publish: true,
      listen: { port: 443, transport: "tcp" }, endpoint: { host: "2001:db8::8", hosts: ["2001:db8::8"], port: 30443 },
      tls: { security: "reality", sni: "www.example.com", publicKey: "p+key", shortId: "deadbeef" },
      credentialCiphertext: encrypted({ type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", flow: "xtls-rprx-vision" }),
      health: { state: "healthy" }, tags: [],
    }],
  };
  const result = buildSubscription(state, { instanceIds: null, excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.match(result.body, /^vless:\/\/.*@\[2001:db8::8\]:30443\?/);
  assert.match(result.body, /security=reality/);
  assert.match(result.body, /pbk=p%2Bkey/);
  assert.equal(hostPort("2001:db8::8", 443), "[2001:db8::8]:443");
});

test("all supported protocols render native formats", () => {
  const protocols = [
    ["vless", { type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", flow: "xtls-rprx-vision" }, { security: "reality", sni: "example.com", publicKey: "pub", shortId: "01" }, "tcp"],
    ["trojan", { type: "password", value: "p@ss" }, { security: "tls", sni: "example.com", alpn: ["h2"] }, "tcp"],
    ["vmess", { type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", alterId: 0, security: "auto" }, { security: "tls", sni: "example.com", alpn: ["h2"] }, "tcp"],
    ["shadowsocks", { type: "shadowsocks", method: "aes-128-gcm", value: "pw" }, {}, "tcp+udp"],
    ["hysteria2", { type: "password", value: "pw" }, { security: "tls", sni: "example.com", alpn: ["h3"], allowInsecure: true }, "udp"],
    ["tuic", { uuid: "123e4567-e89b-42d3-a456-426614174000", password: "pw" }, { security: "tls", sni: "example.com", alpn: ["h3"] }, "udp"],
    ["anytls", { type: "password", value: "pw" }, { security: "tls", sni: "example.com" }, "tcp"],
  ];
  const instances = protocols.map(([protocol, credential, tls, transport], index) => ({
    id: "instance_" + index, machineUuid: "machine", name: protocol, protocol, enabled: true, publish: true,
    listen: { port: 2000 + index, transport }, endpoint: { host: "node.example.com", port: 3000 + index }, tls,
    credentialCiphertext: encrypted(credential), health: { state: "healthy" }, tags: [],
  }));
  const state = { instances, legacyNodes: [] };
  const decrypt = (box) => secrets.decryptSecret(box, key);
  const uri = buildSubscription(state, { instanceIds: null }, "uri", decrypt).body;
  const schemes = { shadowsocks: "ss" };
  for (const [protocol] of protocols) assert.match(uri, new RegExp("^" + (schemes[protocol] || protocol) + "://", "m"));
  assert.match(uri, /trojan:\/\/.*alpn=h2/);
  const vmessLink = uri.split("\n").find((line) => line.startsWith("vmess://"));
  assert.equal(JSON.parse(Buffer.from(vmessLink.slice("vmess://".length), "base64").toString("utf8")).alpn, "h2");
  const mihomo = buildSubscription(state, { instanceIds: null }, "mihomo-full", decrypt);
  assert.match(mihomo.body, /proxy-groups:/);
  assert.match(mihomo.body, /reality-opts:/);
  assert.match(mihomo.body, /alpn: \["h3"\]/);
  const provider = buildSubscription(state, { instanceIds: null }, "mihomo-provider", decrypt);
  assert.match(provider.body, /^proxies:/);
  assert.doesNotMatch(provider.body, /proxy-groups:/);
  const full = JSON.parse(buildSubscription(state, { instanceIds: null }, "singbox-full", decrypt).body);
  for (const keyName of ["inbounds", "outbounds", "route", "dns"]) assert.ok(keyName in full);
  assert.deepEqual(full.outbounds.find((item) => item.type === "hysteria2").tls.alpn, ["h3"]);
  assert.equal(full.outbounds.find((item) => item.type === "hysteria2").tls.insecure, true);
  assert.deepEqual(full.outbounds.find((item) => item.type === "trojan").tls.alpn, ["h2"]);
  const outbounds = JSON.parse(buildSubscription(state, { instanceIds: null }, "singbox-outbounds", decrypt).body);
  assert.equal(outbounds.outbounds.length, protocols.length);
});

test("Shadowsocks 2022 URIs use URL-safe base64 userinfo", () => {
  const key = Buffer.from(Array.from({ length: 32 }, (_, index) => 255 - index)).toString("base64");
  assert.ok(/[+/]/.test(key), "fixture key must exercise base64 special characters");
  const state = { legacyNodes: [], instances: [{
    id: "ss2022", machineUuid: "machine", name: "ss2022", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 8388, transport: "tcp+udp" }, endpoint: { host: "ss.example.com", port: 8388 },
    credential: { type: "shadowsocks", method: "2022-blake3-aes-256-gcm", value: key }, health: { state: "healthy" }, tags: [],
  }] };
  const uri = buildSubscription(state, { instanceIds: null }, "uri", () => { throw new Error("plaintext"); }).body.trim();
  const userinfo = uri.slice("ss://".length, uri.indexOf("@"));
  assert.match(userinfo, /^[A-Za-z0-9_-]+$/);
  const decoded = Buffer.from(userinfo.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  assert.equal(decoded, "2022-blake3-aes-256-gcm:" + key);
});

test("native client formats generate Loon, Surge, Quantumult X, Shadowrocket, Stash, SSD and URI lists", () => {
  const base = (id, protocol, credential, tls, options = {}) => ({
    id, machineUuid: "machine", name: id, protocol, enabled: true, publish: true,
    listen: { port: 443, transport: protocol === "hysteria2" || protocol === "tuic" ? "udp" : "tcp" },
    endpoint: { host: id + ".example.com", port: 443 }, credential, tls, options,
    health: { state: "healthy" }, tags: [],
  });
  const state = { legacyNodes: [], instances: [
    base("vless", "vless", { type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", flow: "xtls-rprx-vision" }, { security: "reality", sni: "vless.example.com", publicKey: "pk", shortId: "sid" }, { flow: "xtls-rprx-vision", fingerprint: "chrome" }),
    base("trojan", "trojan", { type: "password", value: "trojan-pass" }, { security: "tls", sni: "trojan.example.com" }),
    base("vmess", "vmess", { type: "uuid", value: "123e4567-e89b-42d3-a456-426614174001", alterId: 0, security: "auto" }, { security: "tls", sni: "vmess.example.com" }),
    base("ss", "shadowsocks", { type: "shadowsocks", method: "aes-128-gcm", value: "ss-pass" }, {}),
    base("hy", "hysteria2", { type: "password", value: "hy-pass" }, { security: "tls", sni: "hy.example.com" }),
  ] };
  const decrypt = () => { throw new Error("plaintext must not decrypt"); };
  const build = (format) => buildSubscription(state, { instanceIds: null }, format, decrypt);
  const loon = build("loon").body;
  assert.match(loon, /^\[Proxy\]/);
  assert.match(loon, /VLESS, vless\.example\.com/);
  assert.match(loon, /Trojan, trojan\.example\.com/);
  assert.match(loon, /Shadowsocks, ss\.example\.com/);
  const surge = build("surge").body;
  assert.match(surge, /^\[Proxy\]/);
  assert.match(surge, /trojan, trojan\.example\.com/);
  assert.match(surge, /ss, ss\.example\.com/);
  assert.doesNotMatch(surge, /vless, vless\.example\.com/);
  const quanx = build("quanx").body;
  assert.match(quanx, /^\[server_local\]/);
  assert.match(quanx, /vless=vless\.example\.com:443/);
  assert.match(quanx, /trojan=trojan\.example\.com:443/);
  const quan = build("quan").body;
  assert.match(quan, /^\[server\]/);
  const shadowrocket = Buffer.from(build("shadowrocket").body, "base64").toString("utf8");
  assert.match(shadowrocket, /vless:\/\//);
  assert.match(shadowrocket, /ss:\/\//);
  const v2rayn = Buffer.from(build("v2rayn").body, "base64").toString("utf8");
  assert.match(v2rayn, /trojan:\/\//);
  assert.match(build("stash").body, /^proxies:/);
  assert.match(build("mellow").body, /^proxies:/);
  assert.equal(build("vless").body.trim().split("\n").length, 1);
  assert.match(build("vless").body, /^vless:\/\//);
  assert.match(build("trojan").body, /^trojan:\/\//);
  assert.match(build("hysteria2").body, /^hysteria2:\/\//);
  assert.match(build("ss").body, /^ss:\/\//);
  const sssub = Buffer.from(build("sssub").body, "base64").toString("utf8");
  assert.match(sssub, /^ss:\/\//);
  const ssd = build("ssd").body;
  assert.match(ssd, /^ssd:\/\//);
  const ssdJson = JSON.parse(Buffer.from(ssd.slice("ssd://".length), "base64").toString("utf8"));
  assert.equal(ssdJson.servers.length, 1);
  assert.equal(ssdJson.servers[0].server, "ss.example.com");
});

test("protocol tuning options render in URI, Mihomo and sing-box outputs", () => {
  const state = { legacyNodes: [], instances: [{
    id: "hy", machineUuid: "machine", name: "hy", protocol: "hysteria2", enabled: true, publish: true,
    listen: { port: 443, transport: "udp" }, endpoint: { host: "hy.example.com", port: 443 },
    tls: { security: "tls", sni: "hy.example.com", alpn: ["h3"] },
    credential: { type: "password", value: "pw" },
    options: { upMbps: 100, downMbps: 200, obfs: "salamander", obfsPassword: "op", allowInsecure: true },
    health: { state: "healthy" }, tags: [],
  }] };
  const profile = { instanceIds: null };
  const decrypt = () => { throw new Error("plaintext must not decrypt"); };
  const uri = buildSubscription(state, profile, "uri", decrypt).body;
  assert.match(uri, /up=100/);
  assert.match(uri, /down=200/);
  assert.match(uri, /obfs=salamander/);
  assert.match(uri, /obfs-password=op/);
  const mihomo = buildSubscription(state, profile, "mihomo-full", decrypt).body;
  assert.match(mihomo, /up: "100 Mbps"/);
  assert.match(mihomo, /down: "200 Mbps"/);
  assert.match(mihomo, /obfs: "salamander"/);
  assert.match(mihomo, /obfs-password: "op"/);
  assert.match(mihomo, /skip-cert-verify: true/);
  const singbox = JSON.parse(buildSubscription(state, profile, "singbox-full", decrypt).body);
  const outbound = singbox.outbounds.find((item) => item.type === "hysteria2");
  assert.equal(outbound.up_mbps, 100);
  assert.equal(outbound.down_mbps, 200);
  assert.deepEqual(outbound.obfs, { type: "salamander", password: "op" });
  assert.equal(outbound.tls.insecure, true);
});

test("plaintext instance credentials render without invoking decryption", () => {
  const state = { legacyNodes: [], instances: [{
    id: "plain", machineUuid: "machine", name: "plain", protocol: "vless", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "plain.example", port: 443 },
    credential: { type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", flow: "xtls-rprx-vision" },
    tls: { security: "reality", sni: "example.com", publicKey: "pub", shortId: "01" }, health: { state: "healthy" }, tags: [],
  }] };
  const result = buildSubscription(state, { instanceIds: null }, "uri", () => { throw new Error("plaintext must not decrypt"); });
  assert.match(result.body, /^vless:\/\/.*@plain\.example:443/);
  assert.match(result.body, /security=reality/);
});

test("one unreadable credential does not block the whole subscription snapshot", () => {
  const state = { legacyNodes: [], instances: [
    { id: "good", machineUuid: "machine", name: "good", protocol: "vless", enabled: true, publish: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "good.example", port: 443 }, credentialCiphertext: encrypted({ type: "uuid", value: "uuid-good" }), health: { state: "healthy" }, tags: [] },
    { id: "bad", machineUuid: "machine", name: "bad", protocol: "vless", enabled: true, publish: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "bad.example", port: 443 }, credentialCiphertext: "unreadable", health: { state: "healthy" }, tags: [] },
  ] };
  const result = buildSubscription(state, { instanceIds: null }, "uri", (box) => {
    if (box === "unreadable") throw new Error("Unsupported state or unable to authenticate data");
    return secrets.decryptSecret(box, key);
  });
  assert.match(result.body, /good\.example/);
  assert.doesNotMatch(result.body, /bad\.example/);
  assert.equal(result.skippedCount, 1);
});

test("profile filters and never includes hidden or unhealthy instances", () => {
  const state = { legacyNodes: [], instances: [
    { id: "a", enabled: true, publish: true, endpoint: { host: "one.example", port: 443 }, listen: { port: 443 }, protocol: "vless", credentialCiphertext: encrypted({ uuid: "x" }), health: { state: "healthy" } },
    { id: "b", enabled: true, publish: false, endpoint: { host: "two.example", port: 443 }, listen: { port: 443 }, protocol: "vless", credentialCiphertext: encrypted({ uuid: "y" }), health: { state: "healthy" } },
    { id: "c", enabled: true, publish: true, endpoint: { host: "three.example", port: 443 }, listen: { port: 443 }, protocol: "vless", credentialCiphertext: encrypted({ uuid: "z" }), health: { state: "unhealthy" } },
  ] };
  const result = buildSubscription(state, { instanceIds: null, excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.match(result.body, /one\.example/);
  assert.doesNotMatch(result.body, /two\.example|three\.example/);
});

test("subscription de-duplicates equivalent connections but keeps IPv4 and IPv6 distinct", () => {
  const credentialCiphertext = encrypted({ type: "uuid", value: "123e4567-e89b-42d3-a456-426614174000", flow: "xtls-rprx-vision" });
  const base = {
    machineUuid: "machine", name: "node", protocol: "vless", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, tls: { security: "reality", sni: "example.com", publicKey: "key", shortId: "01" },
    credentialCiphertext, health: { state: "healthy" }, tags: [],
  };
  const instances = [
    { ...base, id: "a", endpoint: { host: "192.0.2.4", port: 443 } },
    { ...base, id: "b", endpoint: { host: "192.0.2.4", port: 443 } },
    { ...base, id: "c", endpoint: { host: "2001:db8::4", port: 443 } },
  ];
  const result = buildSubscription({ instances, legacyNodes: [] }, { instanceIds: null }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.equal(result.body.trim().split("\n").length, 2);
  assert.match(result.body, /192\.0\.2\.4/);
  assert.match(result.body, /\[2001:db8::4\]/);
});

test("profile machine, protocol, tag, address-family filters and sorting are applied", () => {
  const instances = [
    { id: "v4", machineUuid: "machine-a", name: "Zulu", protocol: "vless", enabled: true, publish: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "192.0.2.4", port: 443 }, credentialCiphertext: encrypted({ type: "uuid", value: "uuid-a" }), health: { state: "healthy" }, tags: ["prod"] },
    { id: "v6", machineUuid: "machine-a", name: "Alpha", protocol: "trojan", enabled: true, publish: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "2001:db8::4", port: 443 }, credentialCiphertext: encrypted({ type: "password", value: "pw-a" }), tls: { security: "tls", sni: "example.com" }, health: { state: "healthy" }, tags: ["prod"] },
    { id: "other", machineUuid: "machine-b", name: "Beta", protocol: "vless", enabled: true, publish: true, listen: { port: 443, transport: "tcp" }, endpoint: { host: "192.0.2.5", port: 443 }, credentialCiphertext: encrypted({ type: "uuid", value: "uuid-b" }), health: { state: "healthy" }, tags: ["dev"] },
  ];
  const state = { instances, machines: [{ uuid: "machine-a", name: "Alpha machine" }, { uuid: "machine-b", name: "Beta machine" }], legacyNodes: [] };
  const decrypt = (box) => secrets.decryptSecret(box, key);
  const profile = { machineUuids: ["machine-a", "machine-b"], excludeMachineUuids: ["machine-b"], protocols: ["vless"], includeTags: ["prod"], addressMode: "ipv4", sortBy: "name", excludeUnhealthy: true };
  const result = buildSubscription(state, profile, "uri", decrypt);
  assert.equal(result.body.trim().split("\n").length, 1);
  assert.match(result.body, /192\.0\.2\.4/);
  assert.doesNotMatch(result.body, /2001:db8|192\.0\.2\.5/);

  const sorted = buildSubscription(state, { sortBy: "protocol" }, "uri", decrypt).body.trim().split("\n");
  assert.match(sorted[0], /^trojan:\/\//);
  assert.match(sorted[1], /^vless:\/\//);
});

test("empty legacy filter arrays mean unrestricted selection and hostname survives family filter", () => {
  const state = { legacyNodes: [], instances: [
    { id: "domain", machineUuid: "machine", name: "domain", protocol: "vless", enabled: true, publish: true, listen: { port: 443 }, endpoint: { host: "node.example.com", port: 443 }, credentialCiphertext: encrypted({ type: "uuid", value: "uuid-domain" }), health: { state: "healthy" } },
  ] };
  const result = buildSubscription(state, { instanceIds: [], machineUuids: [], protocols: [], addressMode: "ipv6" }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.match(result.body, /node\.example\.com/);
});

test("native clients receive protocol-specific fields and no TCP transport wrapper", () => {
  const state = { instances: [
    { id: "ss", name: "ss", protocol: "shadowsocks", enabled: true, listen: { port: 443, transport: "tcp+udp" }, endpoint: { host: "node.example", port: 443 }, credential: { method: "aes-128-gcm", password: "secret" } },
    { id: "vmess", name: "vmess", protocol: "vmess", enabled: true, listen: { port: 444, transport: "tcp" }, endpoint: { host: "node.example", port: 444 }, credential: { uuid: "uuid", security: "auto" } },
    { id: "vless", name: "vless", protocol: "vless", enabled: true, listen: { port: 445, transport: "tcp" }, endpoint: { host: "node.example", port: 445 }, credential: { uuid: "uuid" }, tls: { security: "reality", publicKey: "key", shortId: "01" } },
  ] };
  const yaml = buildSubscription(state, {}, "mihomo-provider").body;
  assert.match(yaml, /type: "ss"/);
  assert.doesNotMatch(yaml, /type: "shadowsocks"/);
  assert.match(buildSubscription(state, {}, "uri").body, /^ss:\/\//m);
  const { outbounds } = JSON.parse(buildSubscription(state, {}, "singbox-outbounds").body);
  assert.equal(outbounds.find((item) => item.type === "shadowsocks").method, "aes-128-gcm");
  const vmess = outbounds.find((item) => item.type === "vmess");
  assert.equal(vmess.security, "auto");
  assert.equal(vmess.method, undefined);
  assert.equal(vmess.transport, undefined);
  const vless = outbounds.find((item) => item.type === "vless");
  assert.equal(vless.transport, undefined);
  assert.deepEqual(vless.tls.utls, { enabled: true, fingerprint: "chrome" });
});

test("multi-format generation decrypts each selected instance once and matches single-format output", () => {
  const { buildSubscriptions } = require("../kns/subscription");
  const state = { instances: [{ id: "node", protocol: "vless", enabled: true, endpoint: { host: "node.example", port: 443 }, credentialCiphertext: encrypted({ uuid: "uuid" }) }] };
  const formats = ["uri", "mihomo-full", "mihomo-provider", "singbox-full", "singbox-outbounds"];
  let decryptions = 0;
  const results = buildSubscriptions(state, {}, formats, (box) => { decryptions += 1; return secrets.decryptSecret(box, key); });
  assert.equal(decryptions, 1);
  for (const format of formats) assert.deepEqual(results[format], buildSubscription(state, {}, format, (box) => secrets.decryptSecret(box, key)));
});

test("legacy leftover URIs obey profile machine and instance filters", () => {
  const leftover = { id: "legacy-a", machineUuid: "machine-a", ciphertext: "vless://legacy-a", enabled: true };
  const other = { id: "legacy-b", machineUuid: "machine-b", ciphertext: "vless://legacy-b", enabled: true };
  const unowned = { id: "legacy-orphan", ciphertext: "vless://orphan", enabled: true };
  const state = { instances: [], legacyNodes: [leftover, other, unowned] };
  const result = (profile) => buildSubscription(state, Object.assign({ legacy: true }, profile), "uri", (value) => value);
  assert.equal(result({ excludeMachineUuids: ["machine-a"] }).body, "vless://legacy-b\n");
  assert.equal(result({ machineUuids: ["machine-b"] }).body, "vless://legacy-b\n");
  assert.equal(result({ instanceIds: ["legacy-b"] }).body, "vless://legacy-b\n");
  assert.equal(result({ machineUuids: ["machine-a"], excludeMachineUuids: ["machine-a"] }).successCount, 0);
  assert.equal(result({}).successCount, 3, "unrestricted leftover profiles keep unowned URIs");
});

test("legacy leftover nodes remain URI-only and do not generate empty native configs", () => {
  const state = { instances: [], legacyNodes: [{ ciphertext: "vless://example", enabled: true }] };
  const uri = buildSubscription(state, { legacy: true, formats: ["uri"] }, "uri", (value) => value);
  assert.equal(uri.successCount, 1);
  assert.equal(uri.body, "vless://example\n");
  const native = buildSubscription(state, { legacy: true, formats: ["uri"] }, "mihomo-full", (value) => value);
  assert.equal(native.successCount, 0);
});

test("disabled legacy nodes are not published", () => {
  const state = { instances: [], legacyNodes: [
    { ciphertext: "enabled", enabled: true }, { ciphertext: "disabled", enabled: false }, { ciphertext: "old-record" },
  ] };
  assert.equal(buildSubscription(state, { legacy: true }, "uri", (value) => value).body, "enabled\nold-record\n");
});

function collidingNodes() {
  return ["shared", "shared", "direct", "block", "DIRECT", "KNS", "unique", "shared-IPv4", "shared-IPv4"].map((name, index) => ({
    id: "batch_" + index, machineUuid: "machine_" + index, name, protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp+udp" }, endpoint: { host: "node" + index + ".example", port: 443 },
    credential: { method: "aes-128-gcm", password: "secret" },
  }));
}

test("native subscriptions assign unique identifiers to batch nodes and reserve built-in names", () => {
  const instances = collidingNodes();
  instances.push({ ...instances[0], id: "dual", name: "shared", endpoint: { host: "8.8.8.8", hosts: ["8.8.8.8", "2606:4700:4700::1111"], port: 443 } });
  const state = { instances };
  const reserved = ["direct", "block", "DIRECT", "KNS"];
  const full = JSON.parse(buildSubscription(state, {}, "singbox-full").body);
  const tags = full.outbounds.map((item) => item.tag);
  const nativeTags = full.outbounds.filter((item) => item.server).map((item) => item.tag);
  assert.equal(new Set(tags).size, tags.length);
  assert.equal(nativeTags.length, instances.length + 1);
  for (const name of reserved) assert.ok(!nativeTags.includes(name), name);
  assert.ok(nativeTags.every((tag) => /^Shadowsocks-/.test(tag)));
  assert.ok(nativeTags.includes(full.route.final), "route final must refer to a generated node");
  const outboundTags = JSON.parse(buildSubscription(state, {}, "singbox-outbounds").body).outbounds.map((item) => item.tag);
  assert.deepEqual(outboundTags, nativeTags);
  for (const format of ["mihomo-provider", "mihomo-full"]) {
    const yaml = buildSubscription(state, {}, format).body;
    const names = Array.from(yaml.matchAll(/^  name: (.+)$/gm), (match) => JSON.parse(match[1]));
    assert.equal(new Set(names).size, names.length);
    assert.deepEqual(names, nativeTags);
    if (format === "mihomo-full") {
      const group = JSON.parse(yaml.match(/^    proxies: (.+)$/m)[1]);
      assert.deepEqual(group, [...names, "DIRECT"]);
      assert.match(yaml, /MATCH,KNS/);
    }
  }
  const uri = buildSubscription(state, {}, "uri").body;
  assert.match(uri, /#Shadowsocks-machine_0-443-IPv4\n/);
  assert.match(uri, /#Shadowsocks-machine_0-443-IPv6\n/);
});

test("native collision suffixes stay stable across input and profile sorting changes", () => {
  const instances = collidingNodes();
  const names = (nodes, profile) => Object.fromEntries(JSON.parse(buildSubscription({ instances: nodes }, profile, "singbox-outbounds").body).outbounds.map((item) => [item.server, item.tag]));
  const expected = names(instances, {});
  assert.deepEqual(names(instances.slice().reverse(), { sortBy: "endpoint" }), expected);
  const suffixCollision = { ...instances[0], id: "preexisting", machineUuid: instances[0].machineUuid, endpoint: { host: "extra.example", port: 443 } };
  const actual = names([...instances, suffixCollision], {});
  assert.equal(new Set(Object.values(actual)).size, Object.values(actual).length, "generated suffixes must not collide with an existing label");
  assert.notEqual(actual["extra.example"], actual[instances[0].endpoint.host], "same machine/protocol/port must get a stable suffix");
});


test("default subscriptions keep the reachable dual-stack family when the other is unhealthy", () => {
  const credentialCiphertext = encrypted({ type: "shadowsocks", method: "aes-128-gcm", value: "secret" });
  const base = {
    id: "dual", name: "dual", protocol: "shadowsocks", enabled: true, publish: true,
    listen: { port: 443, transport: "tcp" }, endpoint: { host: "8.8.8.8", hosts: ["8.8.8.8", "2606:4700:4700::1111"], port: 443 },
    credentialCiphertext, health: { state: "suspect", hosts: { "8.8.8.8": { state: "unhealthy", consecutiveFailures: 3 }, "2606:4700:4700::1111": { state: "healthy", consecutiveSuccesses: 2 } } },
  };
  const ipv4Down = buildSubscription({ instances: [base] }, { excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.equal(ipv4Down.successCount, 1);
  assert.match(ipv4Down.body, /2606:4700:4700::1111/);
  assert.doesNotMatch(ipv4Down.body, /8\.8\.8\.8/);
  base.health.hosts = { "8.8.8.8": { state: "healthy", consecutiveSuccesses: 2 }, "2606:4700:4700::1111": { state: "unhealthy", consecutiveFailures: 3 } };
  const ipv6Down = buildSubscription({ instances: [base] }, { excludeUnhealthy: true }, "uri", (box) => secrets.decryptSecret(box, key));
  assert.equal(ipv6Down.successCount, 1);
  assert.match(ipv6Down.body, /8\.8\.8\.8/);
  assert.doesNotMatch(ipv6Down.body, /2606:4700:4700::1111/);
});
