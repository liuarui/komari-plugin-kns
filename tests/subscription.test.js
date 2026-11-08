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
