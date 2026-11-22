// SPDX-License-Identifier: Apache-2.0
// Static console for the AGPL command-center API. No runtime code is linked.

const API_BASE = window.TIRBASE_COMMAND_CENTER_API || "http://127.0.0.1:4190";
const ACTORS = {
  operator: "ops-1",
  supervisor: "sup-1",
  safety_officer: "safety-1",
  auditor: "auditor-1",
};

const $ = (selector) => document.querySelector(selector);
const roleSelect = $("#role-select");
const errorBox = $("#error");

let state = null;
let role = roleSelect.value;

function actor() {
  return ACTORS[role] || role;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function can(capability) {
  return Boolean(state && state.capabilities.includes(capability));
}

function formatTime(us) {
  return new Date(us / 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      "x-actor": actor(),
      "x-role": role,
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.message || body.code || `Request failed (${response.status})`);
  }
  return body;
}

async function refresh() {
  try {
    state = await api("/api/state");
    showError("");
    render();
  } catch (error) {
    showError(`Command center unavailable: ${error.message}`);
  }
}

function render() {
  if (!state) return;
  $("#actor-label").textContent = state.actor;
  renderMode();
  renderRoleNote();
  renderMap();
  renderLockdown();
  renderIncidents();
  renderAudit();
  renderReports();
}

function renderMode() {
  const banner = $("#mode-banner");
  const drill = state.mode === "drill";
  banner.classList.toggle("drill", drill);
  banner.classList.toggle("live", !drill);
  banner.querySelector("strong").textContent = drill ? "DRILL MODE" : "LIVE VENUE";
  $("#mode-detail").textContent = drill
    ? "Isolated drill state. Live gates and occupancy cannot be changed from here."
    : "Controls affect real gates and real people.";
  const start = $("#start-drill");
  const end = $("#end-drill");
  start.hidden = drill;
  start.disabled = !can("drill.control");
  start.title = can("drill.control") ? "" : "Only supervisors and safety officers may run a drill";
  end.hidden = !drill;
  end.disabled = !can("drill.control");
}

function renderRoleNote() {
  const note = $("#role-note");
  const readOnly = role === "auditor";
  note.hidden = false;
  note.textContent = readOnly
    ? "Read-only auditor view: incident, lockdown and drill mutations are disabled; the full audit trail and after-action reports remain visible."
    : `${roleLabel(role)} view: ${state.capabilities.filter((value) => value !== "view").join(", ")}`;
}

function roleLabel(value) {
  return (
    {
      operator: "Operator",
      supervisor: "Supervisor",
      safety_officer: "Safety officer",
      auditor: "Auditor",
    }[value] || value
  );
}

function renderMap() {
  const venue = state.venue;
  $("#venue-total").textContent = `${venue.occupancy.toLocaleString()} / ${venue.capacity.toLocaleString()} in venue`;
  $("#venue-map").innerHTML = venue.zones
    .map((zone) => {
      const percent = Math.min(100, Math.round((zone.occupancy / zone.hard_limit) * 100));
      const tone = zone.alarm_state === "critical" ? "critical" : zone.alarm_state === "warning" ? "warning" : "";
      const gates = zone.gates
        .map(
          (gate) => `
          <div class="gate ${gate.posture}" id="gate-${escapeHtml(gate.gate_id)}" data-testid="gate-${escapeHtml(gate.gate_id)}" data-posture="${escapeHtml(gate.posture)}">
            <span class="gate-name">${escapeHtml(gate.name)} <span class="gate-detail">${escapeHtml(gate.gate_id)}</span></span>
            <span class="gate-state">${escapeHtml(gate.posture.replaceAll("_", " "))}</span>
            <span class="gate-detail">${gate.occupancy.toLocaleString()} through · ${gate.ingress_allowed ? "ingress" : "no ingress"} · ${gate.egress_allowed ? "egress open" : "egress blocked"}</span>
          </div>`,
        )
        .join("");
      return `
        <article class="zone alarm-${escapeHtml(zone.alarm_state)}" data-testid="zone-${escapeHtml(zone.zone_id)}">
          <div class="zone-head">
            <div>
              <h3>${escapeHtml(zone.name)}</h3>
              <p class="zone-meta">${zone.occupancy.toLocaleString()} of ${zone.hard_limit.toLocaleString()} hard limit · soft ${zone.soft_limit.toLocaleString()}</p>
            </div>
            <span class="badge ${escapeHtml(zone.alarm_state)}">${escapeHtml(zone.alarm_state)}</span>
          </div>
          <div class="occupancy-bar" aria-hidden="true"><span class="${tone}" style="width:${percent}%"></span></div>
          <div class="gates">${gates}</div>
        </article>`;
    })
    .join("");
}

function renderLockdown() {
  const locks = state.active_lockdowns;
  $("#lockdown-count").textContent = `${locks.length} active`;
  $("#lockdown-active").innerHTML = locks.length
    ? locks
        .map(
          (lock) => `
          <div class="lockdown-card" data-testid="lockdown-${escapeHtml(lock.request_id)}">
            <strong>${escapeHtml(lock.scope)} locked</strong>
            ${escapeHtml(lock.reason)} · requested by ${escapeHtml(lock.requested_by)} · approved by ${escapeHtml(lock.approvers.join(", "))}
          </div>`,
        )
        .join("")
    : "";
  const allowed = can("lockdown.request");
  $("#lockdown-reason").disabled = !allowed;
  $("#lockdown-scope").disabled = !allowed;
  $("#request-lockdown").disabled = !allowed || locks.length > 0;
  $("#release-lockdown").disabled = !allowed || locks.length === 0;
  document
    .querySelectorAll('#lockdown-form input[type="checkbox"]')
    .forEach((checkbox) => (checkbox.disabled = !allowed));
  if (!allowed) {
    $("#request-lockdown").title = "Only supervisors and safety officers may command a lockdown";
  }
}

const NEXT_ACTIONS = {
  open: ["acknowledge", "dispatch", "escalate"],
  acknowledged: ["dispatch", "escalate", "resolve"],
  dispatched: ["escalate", "resolve"],
  escalated: ["resolve"],
  resolved: ["report"],
  reported: [],
};

const ACTION_CAPABILITY = {
  acknowledge: "incident.acknowledge",
  dispatch: "incident.dispatch",
  escalate: "incident.escalate",
  resolve: "incident.resolve",
  report: "incident.report",
};

function actionLabel(action) {
  return action === "report" ? "Generate report" : action.charAt(0).toUpperCase() + action.slice(1);
}

function renderIncidents() {
  const incidents = state.incidents;
  const active = incidents.filter((incident) => incident.status !== "reported").length;
  $("#incident-count").textContent = `${active} active`;
  const actionable = can("incident.acknowledge");
  $("#incidents").innerHTML = incidents
    .map((incident) => {
      const next = NEXT_ACTIONS[incident.status].filter((action) => can(ACTION_CAPABILITY[action]));
      const controls = actionable
        ? `<input class="incident-note" data-note-for="${escapeHtml(incident.id)}" aria-label="Note for ${escapeHtml(incident.title)}" placeholder="${incident.status === "resolved" ? "Report note (optional)" : "Operator note — required to escalate or resolve"}" />
           <div class="incident-actions">${next
             .map(
               (action) =>
                 `<button class="btn small ${action === "resolve" ? "danger" : ""}" type="button" data-testid="${escapeHtml(incident.id)}-${action}" data-incident="${escapeHtml(incident.id)}" data-action="${action}">${actionLabel(action)}</button>`,
             )
             .join("") || '<span class="readonly">No further actions for your role.</span>'}</div>`
        : `<p class="readonly">Read-only role. No incident mutations are available.</p>`;
      const history = incident.actions.length
        ? `<ol class="incident-history">${incident.actions
            .slice()
            .reverse()
            .map(
              (entry) =>
                `<li>${escapeHtml(entry.kind)} by ${escapeHtml(entry.actor)} (${escapeHtml(entry.role)})${entry.note ? `: ${escapeHtml(entry.note)}` : ""}</li>`,
            )
            .join("")}</ol>`
        : "";
      return `
        <article class="incident severity-${escapeHtml(incident.severity)}" data-testid="incident-${escapeHtml(incident.id)}">
          <div class="incident-top">
            <div>
              <h3>${escapeHtml(incident.title)}</h3>
              <p class="incident-meta">${escapeHtml(incident.id)} · ${escapeHtml(incident.zone_id)}${incident.gate_id ? ` / ${escapeHtml(incident.gate_id)}` : ""} · ${escapeHtml(incident.severity)}</p>
            </div>
            <span class="badge ${incident.severity === "critical" ? "critical" : incident.severity === "warning" ? "warning" : "info"}" data-testid="status-${escapeHtml(incident.id)}">${escapeHtml(incident.status)}</span>
          </div>
          ${controls}
          ${history}
        </article>`;
    })
    .join("");
}

function renderAudit() {
  const rows = state.audit.slice().reverse();
  $("#audit-list").innerHTML = rows
    .map(
      (entry) => `
      <li class="${entry.drill ? "drill-row" : ""}" data-testid="audit-${entry.seq}">
        <span class="audit-time">${formatTime(entry.at_utc_us)}</span>
        <div>
          <span class="audit-actor">${escapeHtml(entry.actor)}</span>
          <span class="audit-action"> ${escapeHtml(entry.action)}</span>
          <span class="audit-detail">${escapeHtml(entry.detail)}</span>
        </div>
      </li>`,
    )
    .join("");
}

function renderReports() {
  const reports = state.after_action_reports.slice().reverse();
  $("#report-count").textContent = String(reports.length);
  $("#reports").innerHTML = reports.length
    ? reports
        .map(
          (report) => `
          <article class="report" data-testid="report-${escapeHtml(report.report_id)}">
            <h3>${escapeHtml(report.report_id)} ${report.drill ? "· drill" : ""}</h3>
            <p>${escapeHtml(report.summary)}</p>
            <p>Generated by ${escapeHtml(report.generated_by)} · participants ${escapeHtml(report.participants.join(", ") || "none")}</p>
            ${report.drill ? `<p class="${report.live_gate_state_unchanged ? "safe" : "unsafe"}" data-testid="drill-safety">Live gate state: ${report.live_gate_state_unchanged ? "unchanged" : "CHANGED"}</p>` : ""}
          </article>`,
        )
        .join("")
    : '<p class="readonly">No after-action reports yet.</p>';
}

async function incidentAction(incidentId, action) {
  const note = document.querySelector(`[data-note-for="${CSS.escape(incidentId)}"]`);
  try {
    await api(`/api/incidents/${encodeURIComponent(incidentId)}/actions`, {
      method: "POST",
      body: JSON.stringify({ action, note: note ? note.value : "", actor: actor(), role }),
    });
    showError("");
    await refresh();
  } catch (error) {
    showError(error.message);
  }
}

async function submitLockdown(command) {
  const approvers = Array.from(
    document.querySelectorAll('#lockdown-form input[type="checkbox"]:checked'),
  ).map((checkbox) => checkbox.value);
  let reason = $("#lockdown-reason").value.trim();
  if (!reason) {
    reason = command === "release" ? "Release approved in the command center" : "";
  }
  if (!reason) {
    showError("Record a reason before requesting a lockdown.");
    return;
  }
  try {
    await api("/api/lockdown", {
      method: "POST",
      body: JSON.stringify({
        command,
        scope: $("#lockdown-scope").value,
        reason,
        approvers,
        actor: actor(),
        role,
      }),
    });
    showError("");
    $("#lockdown-reason").value = "";
    await refresh();
  } catch (error) {
    showError(error.message);
  }
}

async function drill(start) {
  try {
    const result = await api(start ? "/api/drill/start" : "/api/drill/end", {
      method: "POST",
      body: JSON.stringify({ actor: actor(), role }),
    });
    showError("");
    await refresh();
    if (!start && result && result.summary) {
      $("#reports").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  } catch (error) {
    showError(error.message);
  }
}

roleSelect.addEventListener("change", () => {
  role = roleSelect.value;
  refresh();
});

$("#lockdown-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitLockdown("lockdown");
});
$("#release-lockdown").addEventListener("click", () => submitLockdown("release"));
$("#start-drill").addEventListener("click", () => drill(true));
$("#end-drill").addEventListener("click", () => drill(false));

$("#incidents").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-incident]");
  if (!button) return;
  incidentAction(button.dataset.incident, button.dataset.action);
});

refresh();
