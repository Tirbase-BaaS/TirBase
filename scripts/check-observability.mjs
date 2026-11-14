#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// F-10 structural gate. It verifies the operational contract without requiring
// Prometheus or Grafana binaries:
//   * every SLO has an alert and a runbook,
//   * every alert carries severity and runbook_url,
//   * the canary is visible within one minute (45s stale + 15s evaluation),
//   * dashboards are valid JSON and route to the provisioned datasource,
//   * Alertmanager has critical/warning routing.
//
// `promtool check rules` remains the authoritative PromQL syntax check and is
// recommended in deployment CI; this script is the dependency-free repo gate.

import { readFile, access } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];
const checked = [];

function fail(message) {
  failures.push(message);
}

async function exists(path) {
  try {
    await access(join(root, path));
    return true;
  } catch {
    return false;
  }
}

async function read(path) {
  return readFile(join(root, path), "utf8");
}

const rulesPath = "ops/prometheus/rules/tirbase-slo.yml";
const rules = await read(rulesPath);
const alertBlocks = rules
  .split(/\n(?=      - alert: )/)
  .filter((block) => block.trimStart().startsWith("- alert:"));
const alerts = new Map();
for (const block of alertBlocks) {
  const name = block.match(/- alert:\s*([A-Za-z0-9_]+)/)?.[1];
  if (!name) {
    fail(`unparseable alert block in ${rulesPath}`);
    continue;
  }
  if (alerts.has(name)) fail(`duplicate alert ${name}`);
  const severity = block.match(/severity:\s*([a-z]+)/)?.[1];
  const runbookUrl = block.match(/runbook_url:\s*(\S+)/)?.[1];
  if (!severity) fail(`alert ${name} has no severity`);
  if (!runbookUrl) fail(`alert ${name} has no runbook_url`);
  alerts.set(name, { block, severity, runbookUrl });
  checked.push(`alert ${name}`);
}

const expectedAlerts = {
  availability: ["TirBaseAvailabilityFastBurn", "TirBaseAvailabilitySlowBurn"],
  ledger_append_latency: ["TirBaseLedgerAppendLatencyHigh", "TirBaseLedgerAppendSLOBreach"],
  alarm_delivery: ["TirBaseAlarmDeliveryLatencyHigh", "TirBaseAlarmDeliveryFailureBudgetBurn"],
  gate_decision_latency: ["TirBaseGateDecisionLatencyHigh", "TirBaseGateDecisionSLOBreach"],
  payment_intent_completion: [
    "TirBasePaymentIntentCompletionLatencyHigh",
    "TirBasePaymentIntentFailureBudgetBurn",
  ],
  synthetic_canary: ["TirBaseCanaryStale", "TirBaseCanaryFailing", "TirBaseCanaryMissing"],
};

const runbooks = {
  availability: "docs/runbooks/slo-availability.md",
  ledger_append_latency: "docs/runbooks/slo-ledger-append.md",
  alarm_delivery: "docs/runbooks/slo-alarm-delivery.md",
  gate_decision_latency: "docs/runbooks/slo-gate-latency.md",
  payment_intent_completion: "docs/runbooks/slo-payment-completion.md",
  synthetic_canary: "docs/runbooks/canary-failure.md",
};

for (const [slo, names] of Object.entries(expectedAlerts)) {
  for (const name of names) {
    const alert = alerts.get(name);
    if (!alert) {
      fail(`SLO ${slo} is missing alert ${name}`);
      continue;
    }
    if (!alert.runbookUrl.endsWith(runbooks[slo])) {
      fail(`alert ${name} must point at ${runbooks[slo]}`);
    }
  }
  if (!(await exists(runbooks[slo]))) fail(`missing runbook ${runbooks[slo]}`);
  checked.push(`SLO ${slo} -> ${runbooks[slo]}`);
}

for (const [slo, path] of Object.entries(runbooks)) {
  if (!(await exists(path))) continue;
  const body = (await read(path)).toLowerCase();
  for (const term of ["severity", "escalation", "rollback"]) {
    if (!body.includes(term)) fail(`${path} (SLO ${slo}) is missing ${term}`);
  }
}

// Every alert must name a runbook that actually exists.
for (const [name, alert] of alerts) {
  const relative = alert.runbookUrl.replace(/^.*\/docs\//, "docs/");
  if (!(await exists(relative))) fail(`alert ${name} points at missing runbook ${relative}`);
}

// The canary guarantee: 45s staleness + 15s evaluation <= 60s.
const stale = alerts.get("TirBaseCanaryStale");
if (!stale) fail("missing TirBaseCanaryStale");
else {
  if (!/> 45/.test(stale.block)) fail("TirBaseCanaryStale must use a 45s staleness threshold");
  if (!/for:\s*0m/.test(stale.block)) fail("TirBaseCanaryStale must use for: 0m");
  if (!/tirbase_canary_last_success_timestamp_seconds/.test(stale.block)) {
    fail("TirBaseCanaryStale must use the canary last-success timestamp");
  }
}
if (!/for:\s*1m/.test(alerts.get("TirBaseCanaryMissing")?.block ?? "")) {
  fail("TirBaseCanaryMissing must use for: 1m");
}

// Prometheus scrape/evaluation must be no slower than 15s.
const prometheus = await read("ops/prometheus/prometheus.yml");
if (!/evaluation_interval:\s*15s/.test(prometheus)) {
  fail("prometheus.yml must evaluate rules every 15s for the one-minute canary SLO");
}
if (!/job_name:\s*tirbase-gateway/.test(prometheus) || !/job_name:\s*tirbase-canary/.test(prometheus)) {
  fail("prometheus.yml must scrape both tirbase-gateway and tirbase-canary");
}

const alertmanager = await read("ops/alertmanager/alertmanager.yml");
for (const needle of ["oncall-pager", "oncall-chat", "severity=\"critical\"", "severity=\"warning\""]) {
  if (!alertmanager.includes(needle)) fail(`alertmanager.yml is missing ${needle}`);
}

for (const dashboard of [
  "ops/grafana/dashboards/tirbase-slo.json",
  "ops/grafana/dashboards/tirbase-verticals.json",
]) {
  let parsed;
  try {
    parsed = JSON.parse(await read(dashboard));
  } catch (error) {
    fail(`${dashboard} is not valid JSON: ${error.message}`);
    continue;
  }
  if (!parsed.uid) fail(`${dashboard} has no uid`);
  if (!parsed.panels?.length) fail(`${dashboard} has no panels`);
  for (const panel of parsed.panels ?? []) {
    if (panel.type === "row" || panel.type === "text") continue;
    if (panel.datasource?.uid !== "tirbase-prometheus") {
      fail(`${dashboard} panel ${panel.id} does not use the provisioned datasource`);
    }
  }
  if (!parsed.tags?.includes("apache-2.0")) fail(`${dashboard} must carry the apache-2.0 tag`);
  checked.push(`dashboard ${parsed.uid}`);
}

// Runtime wiring: logs are redacted and metrics are exposed.
const main = await read("tirbase-gateway/src/main.rs");
if (!main.includes("redacting_stdout()")) fail("main.rs does not install the redacting log writer");
if (!main.includes("init_trace_exporter_from_env()")) fail("main.rs does not initialise trace export");
const metrics = await read("tirbase-gateway/src/metrics.rs");
for (const metric of [
  "tirbase_guard_decision_seconds",
  "tirbase_ledger_append_seconds",
  "tirbase_alarm_delivery_seconds",
  "tirbase_gate_decision_seconds",
  "tirbase_payment_intent_completion_seconds",
]) {
  if (!metrics.includes(metric)) fail(`metrics.rs does not expose ${metric}`);
}
const telemetry = await read("tirbase-gateway/src/telemetry.rs");
for (const rule of ["PRIVATE KEY", "luhn_valid", "latitude", "longitude", "email"]) {
  if (!telemetry.toLowerCase().includes(rule.toLowerCase())) fail(`telemetry.rs is missing redaction rule ${rule}`);
}

if (failures.length) {
  console.error(`observability check failed (${failures.length}):`);
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}
console.log(`observability check passed (${alerts.size} alerts, ${Object.keys(runbooks).length} SLOs, ${checked.length} checks)`);
