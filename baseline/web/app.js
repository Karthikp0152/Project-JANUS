const TOKEN = "prod-secret-abc";
const headers = {
  "Content-Type": "application/json",
  Authorization: `Bearer ${TOKEN}`,
};

const logEl = document.getElementById("actionLog");
const statusChip = document.getElementById("statusChip");

function log(msg, cls = "info") {
  const row = document.createElement("div");
  row.className = cls;
  row.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  logEl.prepend(row);
}

function setPhases(active, done = []) {
  document.querySelectorAll(".phase").forEach((el) => {
    const name = el.dataset.phase;
    el.classList.toggle("active", name === active);
    el.classList.toggle("done", done.includes(name));
  });
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...headers, ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function renderLight(data) {
  document.getElementById("payrollAcl").textContent = (data.folders?.payroll?.acl || []).join(", ");
  document.getElementById("emailCount").textContent = String(data.emails?.length || 0);
  document.getElementById("telCount").textContent = String(data.telemetry_tail?.length || 0);
  document.getElementById("defensePill").textContent = `${data.defenses?.length || 0} defenses`;

  const list = document.getElementById("defenseList");
  list.innerHTML = "";
  if (!data.defenses?.length) {
    list.innerHTML = `<li class="muted">None yet</li>`;
  } else {
    data.defenses.forEach((d) => {
      const li = document.createElement("li");
      li.textContent = `${d.kind}: ${d.artifact}`;
      list.appendChild(li);
    });
  }

  const tel = (data.telemetry_tail || []).slice().reverse();
  document.getElementById("telemetryBox").textContent = tel.length
    ? tel
        .map((e) => {
          const copy = { ...e };
          if (copy.token) copy.token = "[REDACTED]";
          return JSON.stringify(copy);
        })
        .join("\n")
    : "No telemetry yet";
}

function renderRun(run) {
  if (!run || run.empty) return;
  setPhases("deploy", ["duplicate", "attack", "learn", "deploy"]);
  document.getElementById("shadowPill").textContent = run.attack?.broke_shadow
    ? "shadow breached"
    : "shadow held";
  document.getElementById("phaseDetail").innerHTML = `
    <p>Loop: <strong>${(run.loop || []).join(" → ")}</strong> · N=${run.n}</p>
    <p class="muted">Gate payload escaped: <strong>${run.deploy?.payload_escaped}</strong></p>
  `;
  document.getElementById("dupBox").textContent = JSON.stringify(
    {
      twin_ready: run.duplicate?.digital_twin_ready,
      redactions: run.duplicate?.redactions,
      files: run.duplicate?.shadow_file_contents,
      telemetry: run.duplicate?.sanitized_telemetry,
    },
    null,
    2
  );
  document.getElementById("atkBox").textContent = JSON.stringify(
    {
      broke_shadow: run.attack?.broke_shadow,
      violations: run.attack?.violations_found,
      best_trace: run.attack?.best_trace,
    },
    null,
    2
  );
  document.getElementById("learnBox").textContent = JSON.stringify(run.learn, null, 2);
  document.getElementById("deployBox").textContent = JSON.stringify(run.deploy, null, 2);
}

async function refresh() {
  const status = await fetch("/api/status").then((r) => r.json());
  statusChip.textContent = `live · ${status.defenses} defenses · ${status.telemetry_events} events`;
  statusChip.classList.add("live");
  const light = await api("/api/light");
  renderLight(light);
  const last = await fetch("/api/aswa/last").then((r) => r.json());
  if (!last.empty) renderRun(last);
}

async function withBusy(fn) {
  const buttons = [...document.querySelectorAll(".btn, .scenario-card")];
  buttons.forEach((b) => (b.disabled = true));
  try {
    await fn();
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

async function loadScenarios() {
  const data = await fetch("/api/scenarios").then((r) => r.json());
  const grid = document.getElementById("scenarioGrid");
  grid.innerHTML = "";
  data.scenarios.forEach((s) => {
    const btn = document.createElement("button");
    btn.className = `scenario-card ${s.risk}`;
    btn.innerHTML = `
      <span class="risk">${s.risk}</span>
      <span class="sc-title">${s.title}</span>
      <span class="sc-blurb">${s.blurb}</span>
    `;
    btn.onclick = () =>
      withBusy(async () => {
        setPhases("duplicate");
        const res = await api("/api/scenario", {
          method: "POST",
          body: JSON.stringify({ scenario: s.id }),
        });
        log(`Use case: ${res.title || s.title}`, "info");
        res.results.forEach((r) => {
          if (r.blocked) log(`${r.action} BLOCKED by defense`, "ok");
          else if (r.ok) log(`${r.action} happened in production`, s.risk === "unsafe" ? "bad" : "ok");
          else log(`${r.action} failed`, "bad");
        });
        await refresh();
      });
    grid.appendChild(btn);
  });
}

document.getElementById("btnRun").onclick = () =>
  withBusy(async () => {
    setPhases("duplicate");
    log("Duplicate: make a safe copy of the company computer…", "info");
    await new Promise((r) => setTimeout(r, 160));
    setPhases("attack", ["duplicate"]);
    log("Attack: practice bad guys only on the copy…", "info");
    const run = await api("/api/aswa/run", {
      method: "POST",
      body: JSON.stringify({ n: 3, asa_episodes: 28 }),
    });
    setPhases("learn", ["duplicate", "attack"]);
    log(
      run.attack.broke_shadow
        ? `Learn: found ${run.learn.vulnerabilities_logged.length} weak spot(s) and designed fixes`
        : "Learn: copy held — no new weak spot",
      "info"
    );
    await new Promise((r) => setTimeout(r, 100));
    setPhases("deploy", ["duplicate", "attack", "learn"]);
    log(
      `Deploy: installed ${run.production_deploy.installed.length} shield(s); bad stuff stayed in the copy`,
      "ok"
    );
    renderRun(run);
    await refresh();
  });

document.querySelectorAll(".probe").forEach((btn) => {
  btn.onclick = () =>
    withBusy(async () => {
      const payload = JSON.parse(btn.dataset.probe);
      const res = await api("/api/probe", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (res.blocked) log(`Probe ${res.kind} blocked: ${res.rule}`, "ok");
      else log(`Probe ${res.kind} still succeeded — not hardened yet`, "bad");
      await refresh();
    });
});

document.getElementById("btnReset").onclick = () =>
  withBusy(async () => {
    await api("/api/reset", { method: "POST", body: "{}" });
    setPhases(null);
    document.getElementById("shadowPill").textContent = "idle";
    document.getElementById("phaseDetail").innerHTML =
      `<p class="muted">World reset. Pick a use case, then run ASWA.</p>`;
    ["dupBox", "atkBox", "learnBox", "deployBox"].forEach((id) => {
      document.getElementById(id).textContent = "—";
    });
    log("Light World reset", "info");
    await refresh();
  });

Promise.all([loadScenarios(), refresh()]).catch((err) => {
  statusChip.textContent = "offline";
  log(`Failed to connect: ${err.message}`, "bad");
});
setInterval(() => {
  refresh().catch(() => {});
}, 5000);
