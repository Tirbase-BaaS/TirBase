// SPDX-License-Identifier: AGPL-3.0-only
//
// Hermetic contract test for the F-10 synthetic canary. It serves the F-08
// route shapes in-process and asserts that all three vertical journeys complete
// and emit the metrics the stale-canary alert consumes.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const script = join(here, "vertical-canary.mjs");

function startGateway(handler) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          const parsed = body ? JSON.parse(body) : undefined;
          const result = handler(req.method, req.url, parsed) ?? { status: 200, body: {} };
          res.writeHead(result.status ?? 200, { "content-type": "application/json" });
          res.end(JSON.stringify(result.body ?? result));
        } catch (error) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: String(error) }));
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

function run(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...args], { timeout: 20_000 }, (error, stdout, stderr) => {
      resolve({ code: error?.code ?? 0, stdout, stderr });
    });
  });
}

function successfulGateway() {
  const objects = new Map();
  return (method, url, body) => {
    const path = url.split("?")[0];
    if (method === "POST" && path === "/admin/cold-chain/sites") {
      const object = { id: body.id, data: body, revision: 1, created_est: 1 };
      objects.set(`${path}/${body.id}`, object);
      return { status: 201, body: { object } };
    }
    if (method === "POST" && /^\/admin\/cold-chain\/sites\/[^/]+\/readings$/.test(path)) {
      return { status: 201, body: { object: { id: "reading-1", data: body } } };
    }
    if (method === "GET" && /^\/admin\/cold-chain\/sites\/[^/]+\/readings$/.test(path)) {
      return { body: { items: [{ id: "reading-1" }] } };
    }
    if (method === "POST" && path === "/admin/pos/orders") {
      return { status: 201, body: { object: { id: "order-1", data: body, revision: 1, created_est: 1 } } };
    }
    if (method === "POST" && path === "/admin/pos/orders/order-1/lines") {
      return { status: 201, body: { object: { id: "line-1", data: body } } };
    }
    if (method === "PATCH" && path === "/admin/pos/orders/order-1") {
      return {
        body: {
          object: {
            id: "order-1",
            data: { currency: "USD", total_minor: 100, payment_status: "completed" },
            revision: 2,
            created_est: 1,
          },
        },
      };
    }
    if (method === "GET" && path === "/admin/pos/orders/order-1") {
      return { body: { object: { id: "order-1", revision: 2 } } };
    }
    if (method === "POST" && path === "/admin/venues") {
      return { status: 201, body: { object: { id: body.id ?? "venue-1", data: body } } };
    }
    if (method === "POST" && /^\/admin\/venues\/[^/]+\/gates$/.test(path)) {
      return { status: 201, body: { object: { id: "gate-1", data: body } } };
    }
    if (method === "GET" && /^\/admin\/venues\/[^/]+\/gates$/.test(path)) {
      return { body: { items: [{ id: "gate-1" }] } };
    }
    if (method === "DELETE") return { body: { deleted: true } };
    return { status: 404, body: { status: 404, code: "NOT_FOUND" } };
  };
}

test("all vertical journeys complete and emit canary metrics", async () => {
  const dir = await mkdtemp(join(tmpdir(), "tirbase-canary-"));
  const output = join(dir, "canary.prom");
  const { server, url } = await startGateway(successfulGateway());
  try {
    const result = await run([
      "--base-url", url,
      "--token", "test-token",
      "--vertical", "all",
      "--output", output,
    ]);
    assert.equal(result.code, 0, result.stderr);
    const metrics = await readFile(output, "utf8");
    for (const vertical of ["cold-chain", "pos", "venues"]) {
      assert.match(metrics, new RegExp(`tirbase_canary_success\\{vertical="${vertical}"\\} 1`));
      assert.match(metrics, new RegExp(`tirbase_canary_last_success_timestamp_seconds\\{vertical="${vertical}"\\} [1-9]`));
    }
  } finally {
    server.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("a failed journey exits non-zero and reports success 0", async () => {
  const dir = await mkdtemp(join(tmpdir(), "tirbase-canary-fail-"));
  const output = join(dir, "canary.prom");
  const { server, url } = await startGateway((method, requestUrl, body) => {
    if (requestUrl.startsWith("/admin/pos/orders")) {
      return { status: 503, body: { status: 503, code: "UNAVAILABLE" } };
    }
    return successfulGateway()(method, requestUrl, body);
  });
  try {
    const result = await run([
      "--base-url", url,
      "--token", "test-token",
      "--vertical", "pos",
      "--output", output,
    ]);
    assert.notEqual(result.code, 0);
    const metrics = await readFile(output, "utf8");
    assert.match(metrics, /tirbase_canary_success\{vertical="pos"\} 0/);
    assert.match(metrics, /tirbase_canary_consecutive_failures\{vertical="pos"\} 1/);
  } finally {
    server.close();
    await rm(dir, { recursive: true, force: true });
  }
});
