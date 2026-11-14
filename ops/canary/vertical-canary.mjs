#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// F-10 synthetic canary: one real end-to-end journey per vertical.
//
// Modes:
//   node vertical-canary.mjs --base-url https://gateway.example --token-file token \
//       --vertical cold-chain --output /var/lib/node_exporter/textfile/tirbase-canary.prom
//   node vertical-canary.mjs --serve --port 9101 --base-url ... --token-file ...
//
// The serve mode runs every 30 seconds and exposes Prometheus metrics. A failed
// journey leaves `tirbase_canary_last_success_timestamp_seconds` at its previous
// value and sets `tirbase_canary_success{vertical} 0`, so the stale-canary alert
// fires within one minute without relying on log ingestion.
//
// Journeys only use the F-08 OpenAPI routes. They never inspect another tenant,
// never log tokens/card data, and clean up the objects they create.

import { createServer } from "node:http";
import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const VERTICALS = ["cold-chain", "pos", "venues"];
const DEFAULT_INTERVAL_MS = 30_000;

function parseArgs(argv) {
  const args = {
    baseUrl: process.env.TIRBASE_CANARY_BASE_URL ?? "",
    tokenFile: process.env.TIRBASE_CANARY_TOKEN_FILE ?? "",
    token: process.env.TIRBASE_CANARY_TOKEN ?? "",
    vertical: "all",
    output: process.env.TIRBASE_CANARY_TEXTFILE ?? "",
    stateFile: process.env.TIRBASE_CANARY_STATE_FILE ?? "",
    intervalMs: Number(process.env.TIRBASE_CANARY_INTERVAL_MS ?? DEFAULT_INTERVAL_MS),
    timeoutMs: Number(process.env.TIRBASE_CANARY_TIMEOUT_MS ?? 10_000),
    serve: false,
    port: Number(process.env.TIRBASE_CANARY_PORT ?? 9101),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) throw new Error(`missing value for ${arg}`);
      return argv[index];
    };
    switch (arg) {
      case "--base-url": args.baseUrl = next(); break;
      case "--token-file": args.tokenFile = next(); break;
      case "--token": args.token = next(); break;
      case "--vertical": args.vertical = next(); break;
      case "--output": args.output = next(); break;
      case "--state-file": args.stateFile = next(); break;
      case "--interval-ms": args.intervalMs = Number(next()); break;
      case "--timeout-ms": args.timeoutMs = Number(next()); break;
      case "--serve": args.serve = true; break;
      case "--port": args.port = Number(next()); break;
      case "--help":
        console.log(`Usage: vertical-canary.mjs [--vertical cold-chain|pos|venues|all]
  --base-url URL --token-file FILE|--token TOKEN [--output FILE] [--state-file FILE]
  [--serve --port 9101] [--interval-ms 30000] [--timeout-ms 10000]`);
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument ${arg}`);
    }
  }
  if (!args.baseUrl) throw new Error("--base-url or TIRBASE_CANARY_BASE_URL is required");
  if (!args.token && !args.tokenFile) {
    throw new Error("--token-file/--token (or TIRBASE_CANARY_TOKEN_FILE) is required");
  }
  if (args.vertical !== "all" && !VERTICALS.includes(args.vertical)) {
    throw new Error(`unknown vertical ${args.vertical}`);
  }
  return args;
}

function normaliseBase(url) {
  return url.replace(/\/+$/, "");
}

async function readToken(args) {
  if (args.token) return args.token.trim();
  return (await readFile(args.tokenFile, "utf8")).trim();
}

async function request(ctx, method, path, body) {
  const url = `${ctx.baseUrl}${path}`;
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${ctx.token}`,
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(ctx.timeoutMs),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // A canary failure should report the status, never echo a response body
    // that might contain tenant data.
  }
  if (!response.ok) {
    throw new Error(`${method} ${path} -> HTTP ${response.status}${json?.code ? ` (${json.code})` : ""}`);
  }
  return json;
}

async function cleanup(ctx, path) {
  try {
    await request(ctx, "DELETE", path);
  } catch {
    // Cleanup is best effort: a stale canary object must not turn a successful
    // journey into a failure. Operators can prune canary-* objects.
  }
}

async function coldChain(ctx) {
  const tenant = `canary-${ctx.suffix}`;
  const id = `canary-site-${ctx.suffix}`;
  const site = await request(ctx, "POST", "/admin/cold-chain/sites", {
    tenant,
    id,
    name: "Synthetic canary site",
  });
  if (!site?.object?.id) throw new Error("cold-chain create did not return an object");
  try {
    const reading = await request(ctx, "POST", `/admin/cold-chain/sites/${id}/readings`, {
      tenant,
      celsius_milli: 4200,
    });
    if (!reading?.object?.id) throw new Error("cold-chain reading append did not return an object");
    const list = await request(
      ctx,
      "GET",
      `/admin/cold-chain/sites/${id}/readings?tenant=${encodeURIComponent(tenant)}&limit=10`,
    );
    if (!Array.isArray(list?.items) || list.items.length < 1) {
      throw new Error("cold-chain reading is not visible after append");
    }
  } finally {
    await cleanup(ctx, `/admin/cold-chain/sites/${id}?tenant=${encodeURIComponent(tenant)}`);
  }
}

async function pos(ctx) {
  const tenant = `canary-${ctx.suffix}`;
  const order = await request(ctx, "POST", "/admin/pos/orders", {
    tenant,
    currency: "USD",
    total_minor: 100,
    payment_status: "pending",
  });
  const id = order?.object?.id;
  if (!id) throw new Error("POS order create did not return an object");
  try {
    const line = await request(ctx, "POST", `/admin/pos/orders/${id}/lines`, {
      tenant,
      sku: "CANARY-SKU",
      quantity: 1,
      unit_price_minor: 100,
    });
    if (!line?.object?.id) throw new Error("POS line append did not return an object");
    const paid = await request(ctx, "PATCH", `/admin/pos/orders/${id}`, {
      tenant,
      payment_status: "completed",
    });
    if (paid?.object?.data?.payment_status !== "completed") {
      throw new Error("POS payment intent did not reach completed");
    }
    const read = await request(ctx, "GET", `/admin/pos/orders/${id}?tenant=${encodeURIComponent(tenant)}`);
    if (read?.object?.revision < 2) throw new Error("POS order revision did not advance");
  } finally {
    await cleanup(ctx, `/admin/pos/orders/${id}?tenant=${encodeURIComponent(tenant)}`);
  }
}

async function venues(ctx) {
  const tenant = `canary-${ctx.suffix}`;
  const venue = await request(ctx, "POST", "/admin/venues", {
    tenant,
    id: `canary-venue-${ctx.suffix}`,
    name: "Synthetic canary venue",
  });
  const id = venue?.object?.id;
  if (!id) throw new Error("venue create did not return an object");
  try {
    const gate = await request(ctx, "POST", `/admin/venues/${id}/gates`, {
      tenant,
      name: "Canary Gate",
      status: "open",
    });
    if (!gate?.object?.id) throw new Error("venue gate create did not return an object");
    const gates = await request(
      ctx,
      "GET",
      `/admin/venues/${id}/gates?tenant=${encodeURIComponent(tenant)}&limit=10`,
    );
    if (!Array.isArray(gates?.items) || gates.items.length < 1) {
      throw new Error("venue gate decision is not visible after create");
    }
  } finally {
    await cleanup(ctx, `/admin/venues/${id}?tenant=${encodeURIComponent(tenant)}`);
  }
}

const JOURNEYS = { "cold-chain": coldChain, pos, venues };

async function loadState(stateFile) {
  if (!stateFile) return {};
  try {
    const raw = JSON.parse(await readFile(stateFile, "utf8"));
    return raw && typeof raw === "object" ? raw : {};
  } catch {
    return {};
  }
}

async function saveState(stateFile, state) {
  if (!stateFile) return;
  await mkdir(dirname(resolve(stateFile)), { recursive: true });
  await writeFile(resolve(stateFile), `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

function metricsText(state) {
  const lines = [];
  lines.push("# HELP tirbase_canary_last_success_timestamp_seconds Unix time of the last successful synthetic journey.");
  lines.push("# TYPE tirbase_canary_last_success_timestamp_seconds gauge");
  for (const vertical of VERTICALS) {
    const value = state[vertical]?.last_success ?? 0;
    lines.push(`tirbase_canary_last_success_timestamp_seconds{vertical="${vertical}"} ${value}`);
  }
  lines.push("# HELP tirbase_canary_success Whether the most recent journey succeeded.");
  lines.push("# TYPE tirbase_canary_success gauge");
  for (const vertical of VERTICALS) {
    lines.push(`tirbase_canary_success{vertical="${vertical}"} ${state[vertical]?.success ? 1 : 0}`);
  }
  lines.push("# HELP tirbase_canary_duration_seconds Duration of the most recent journey.");
  lines.push("# TYPE tirbase_canary_duration_seconds gauge");
  for (const vertical of VERTICALS) {
    lines.push(`tirbase_canary_duration_seconds{vertical="${vertical}"} ${state[vertical]?.duration ?? 0}`);
  }
  lines.push("# HELP tirbase_canary_consecutive_failures Consecutive failed journeys.");
  lines.push("# TYPE tirbase_canary_consecutive_failures gauge");
  for (const vertical of VERTICALS) {
    lines.push(`tirbase_canary_consecutive_failures{vertical="${vertical}"} ${state[vertical]?.failures ?? 0}`);
  }
  return `${lines.join("\n")}\n`;
}

async function writeOutput(output, state) {
  if (!output) return;
  await mkdir(dirname(resolve(output)), { recursive: true });
  const temp = `${resolve(output)}.tmp`;
  await writeFile(temp, metricsText(state), "utf8");
  await rename(temp, resolve(output));
}

async function runOnce(args, state) {
  const token = await readToken(args);
  const selected = args.vertical === "all" ? VERTICALS : [args.vertical];
  const ctx = {
    baseUrl: normaliseBase(args.baseUrl),
    token,
    timeoutMs: args.timeoutMs,
    suffix: `${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`,
  };
  let allOk = true;
  for (const vertical of selected) {
    const started = Date.now();
    const previous = state[vertical] ?? { last_success: 0, success: false, duration: 0, failures: 0 };
    try {
      await JOURNEYS[vertical](ctx);
      state[vertical] = {
        last_success: Math.floor(Date.now() / 1000),
        success: true,
        duration: (Date.now() - started) / 1000,
        failures: 0,
      };
      console.log(`canary ${vertical}: ok ${(state[vertical].duration * 1000).toFixed(0)}ms`);
    } catch (error) {
      allOk = false;
      state[vertical] = {
        ...previous,
        success: false,
        duration: (Date.now() - started) / 1000,
        failures: Number(previous.failures ?? 0) + 1,
        error: String(error?.message ?? error).slice(0, 240),
      };
      console.error(`canary ${vertical}: FAILED ${state[vertical].error}`);
    }
  }
  await saveState(args.stateFile, state);
  await writeOutput(args.output, state);
  return allOk;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let state = await loadState(args.stateFile);
  if (!args.serve) {
    const ok = await runOnce(args, state);
    process.exitCode = ok ? 0 : 1;
    return;
  }

  const server = createServer(async (req, res) => {
    if (req.url === "/metrics" || req.url === "/") {
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(metricsText(state));
      return;
    }
    if (req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: 404, error: "not found" }));
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(args.port, "127.0.0.1", resolveListen);
  });
  console.log(`tirbase canary: metrics on http://127.0.0.1:${args.port}/metrics`);

  const cycle = async () => {
    await runOnce(args, state).catch((error) => {
      console.error(`canary cycle error: ${error?.message ?? error}`);
    });
  };
  await cycle();
  const timer = setInterval(cycle, Math.max(5_000, args.intervalMs));
  const shutdown = () => {
    clearInterval(timer);
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error) => {
  console.error(`tirbase canary: ${error?.message ?? error}`);
  process.exit(1);
});
