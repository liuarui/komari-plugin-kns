"use strict";

let nodeUrl = null;
if (typeof URL !== "function" || typeof URLSearchParams !== "function") {
  try { nodeUrl = require("node:url"); }
  catch (_) { nodeUrl = require("url"); }
}

module.exports = {
  URL: typeof URL === "function" ? URL : nodeUrl.URL,
  URLSearchParams: typeof URLSearchParams === "function" ? URLSearchParams : nodeUrl.URLSearchParams,
};
