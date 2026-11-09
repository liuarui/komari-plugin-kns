"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(require.resolve("../kns/index"), "utf8");
const context = {
  require, now: () => new Date().toISOString(),
  fail(code, message) { throw Object.assign(new Error(message), { code }); },
};
vm.runInNewContext(
  source.slice(source.indexOf("function preferredObservedAddress("), source.indexOf("function safeMachine(")) +
  source.slice(source.indexOf("function validHostname("), source.indexOf("function validatePort(")),
  context,
);
const ipv4 = "8.8.8.8";
const ipv6 = "2606:4700:4700::1111";
const state = { settings: { privateSite: false } };
const instance = { listen: { port: 443 } };
function machine(addressMode, extra = {}) {
  return { ipv4, ipv6, policy: { addressMode }, ...extra };
}
function endpoint(node, target = instance) {
  return context.candidateAddress(node, state, target);
}

for (const [mode, address] of [["ipv4", ipv4], ["ipv6", ipv6]]) {
  test(mode + " selects its family on the first sync", () => {
    const result = endpoint(machine(mode));
    assert.equal(result.host, address);
    assert.deepEqual(Array.from(result.hosts), [address]);
  });

  test(mode + " rejects stale observations of the other family after a policy switch", () => {
    const node = machine(mode, { observedAddress: mode === "ipv4" ? ipv6 : ipv4 });
    const result = endpoint(node);
    assert.equal(result.host, address);
    assert.deepEqual(Array.from(result.hosts), [address]);
    node.observedAddress = ipv6 + "," + ipv4;
    assert.deepEqual(Array.from(endpoint(node).hosts), [address]);
  });

  test(mode + " does not fall back to the other family when its address is missing", () => {
    const node = machine(mode, { [mode]: "", observedAddress: ipv4 + "," + ipv6, sourceIp: mode === "ipv4" ? ipv6 : ipv4 });
    assert.equal(endpoint(node), null);
  });
}

test("matching stable observations remain preferred over changing source addresses", () => {
  const stable = "2606:4700:4700::1001";
  assert.equal(endpoint(machine("ipv6", { observedAddress: stable })).host, stable);
});

test("auto, dual, manual, DDNS and instance override precedence remain supported", () => {
  assert.equal(endpoint(machine("auto")).host, ipv4);
  assert.deepEqual(Array.from(endpoint(machine("dual")).hosts), [ipv4, ipv6]);
  assert.equal(endpoint(machine("ipv6", { policy: { addressMode: "ipv6", manualAddress: "manual.example" } })).host, "manual.example");
  assert.equal(endpoint(machine("ipv6", { policy: { addressMode: "ipv6", ddnsHostname: "ddns.example" } })).host, "ddns.example");
  assert.equal(endpoint(machine("ipv6"), { ...instance, endpointOverride: { host: "override.example", port: 8443 } }).host, "override.example");
});


test("equivalent IPv6 private and loopback addresses share the same classification", () => {
  const privateAddresses = [
    "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001",
    "fc00::1", "fc00:0:0:0:0:0:0:1", "fd12::1", "fe80::1", "febf::1", "fe80::1%eth0",
    "2001:db8::1", "2001:0db8:0:0:0:0:0:1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:a00:1",
    "::ffff:169.254.1.1", "::ffff:a9fe:101", "::ffff:100.64.0.1", "::ffff:6440:1",
    "::ffff:172.16.0.1", "::ffff:ac10:1", "::ffff:192.168.0.1", "::ffff:c0a8:1",
    "::ffff:192.0.0.1", "::ffff:c000:1", "::ffff:198.18.0.1", "::ffff:c612:1",
    "::ffff:203.0.113.1", "::ffff:cb00:7101",
  ];
  for (const address of privateAddresses) {
    assert.throws(() => context.normalizeHost(address, false), (error) => error.code === "private_endpoint", address);
    assert.equal(context.normalizeHost(address, true), address, address + " is allowed only with privateSite");
  }
});

test("unspecified and multicast addresses are rejected even for private sites", () => {
  for (const address of ["::", "0:0:0:0:0:0:0:0", "ff02::1", "FF02:0:0:0:0:0:0:1", "::ffff:0.0.0.0", "::ffff:0:0", "::ffff:224.0.0.1", "::ffff:e000:1", "::ffff:255.255.255.255"]) {
    for (const allowPrivate of [false, true]) assert.throws(() => context.normalizeHost(address, allowPrivate), (error) => error.code === "invalid_host", address);
  }
});

test("public IPv6 and mapped IPv4 keep their accepted spelling", () => {
  for (const address of ["2606:4700:4700::1111", "2606:4700:4700:0:0:0:0:1111", "::ffff:8.8.8.8", "::ffff:808:808", "0:0:0:0:0:ffff:808:808"]) {
    assert.equal(context.normalizeHost(address, false), address);
  }
});
