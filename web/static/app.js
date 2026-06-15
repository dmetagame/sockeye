"use strict";

const state = {
  apiKey: sessionStorage.getItem("sockeye_api_key") || "",
  authRequired: false,
  jobs: [],
  activeJob: null,
  timer: null,
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  authButton: $("#auth-button"),
  authDialog: $("#auth-dialog"),
  authError: $("#auth-error"),
  authForm: $("#auth-form"),
  apiKeyInput: $("#api-key-input"),
  form: $("#investigation-form"),
  launchPanel: $("#launch-panel"),
  runView: $("#run-view"),
  startButton: $("#start-button"),
  newRunButton: $("#new-run-button"),
  historyList: $("#history-list"),
  systemDot: $("#system-dot"),
  systemStatus: $("#system-status"),
  runKicker: $("#run-kicker"),
  runTitle: $("#run-title"),
  runSubtitle: $("#run-subtitle"),
  runStatus: $("#run-status"),
  metricStatus: $("#metric-status"),
  metricQueries: $("#metric-queries"),
  metricTurns: $("#metric-turns"),
  metricElapsed: $("#metric-elapsed"),
  activityFeed: $("#activity-feed"),
  liveIndicator: $("#live-indicator"),
  reportState: $("#report-state"),
  reportEmpty: $("#report-empty"),
  reportContent: $("#report-content"),
  downloadButton: $("#download-button"),
  toast: $("#toast"),
};

function headers(json = false) {
  const result = {};
  if (json) result["Content-Type"] = "application/json";
  if (state.apiKey) result.Authorization = `Bearer ${state.apiKey}`;
  return result;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...headers(Boolean(options.body)), ...(options.headers || {}) },
  });
  if (response.status === 401) {
    showAuth("The access key was rejected.");
    throw new Error("Authentication required");
  }
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { message = (await response.json()).detail || message; } catch (_) { /* no-op */ }
    throw new Error(message);
  }
  return response;
}

function showAuth(message = "") {
  elements.authError.textContent = message;
  elements.authError.classList.toggle("hidden", !message);
  elements.apiKeyInput.value = state.apiKey;
  if (!elements.authDialog.open) elements.authDialog.showModal();
  requestAnimationFrame(() => elements.apiKeyInput.focus());
}

function toast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.remove("hidden");
  clearTimeout(elements.toast.timer);
  elements.toast.timer = setTimeout(() => elements.toast.classList.add("hidden"), 4200);
}

function formatDate(value) {
  if (!value) return "Pending";
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function statusLabel(status) {
  return ({ queued: "Queued", running: "Investigating", succeeded: "Complete", failed: "Failed" })[status] || status;
}

function renderHistory() {
  elements.historyList.replaceChildren();
  if (!state.jobs.length) {
    const empty = document.createElement("p");
    empty.className = "muted compact";
    empty.textContent = "No investigations yet.";
    elements.historyList.append(empty);
    return;
  }
  for (const job of state.jobs) {
    const button = document.createElement("button");
    button.className = `history-item${state.activeJob?.id === job.id ? " active" : ""}`;
    button.type = "button";
    const dot = document.createElement("span");
    dot.className = `history-state ${job.status}`;
    const title = document.createElement("strong");
    title.textContent = `index=${job.index}`;
    const detail = document.createElement("small");
    detail.textContent = `${statusLabel(job.status)} · ${formatDate(job.created_at)}`;
    button.append(dot, title, detail);
    button.addEventListener("click", () => openJob(job.id));
    elements.historyList.append(button);
  }
}

function setSystem(ok, label) {
  elements.systemDot.className = `status-dot ${ok ? "ok" : "bad"}`;
  elements.systemStatus.textContent = label;
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const config = await response.json();
    state.authRequired = config.auth_required;
    elements.authButton.classList.toggle("hidden", !state.authRequired);
    if (config.configuration_error) {
      setSystem(false, "Configuration needed");
      toast("Set SOCKEYE_WEB_API_KEY on the server before using the dashboard.");
      return false;
    }
    if (state.authRequired && !state.apiKey) showAuth();
    return true;
  } catch (_) {
    setSystem(false, "Unavailable");
    return false;
  }
}

async function loadJobs() {
  try {
    const response = await api("/api/jobs");
    state.jobs = (await response.json()).jobs;
    renderHistory();
    setSystem(true, "Operational");
    return true;
  } catch (error) {
    if (error.message !== "Authentication required") setSystem(false, "Configuration needed");
    return false;
  }
}

function showLaunch() {
  state.activeJob = null;
  clearInterval(state.timer);
  elements.runView.classList.add("hidden");
  elements.launchPanel.classList.remove("hidden");
  renderHistory();
}

function resetRunView(job) {
  elements.launchPanel.classList.add("hidden");
  elements.runView.classList.remove("hidden");
  elements.runKicker.textContent = `Investigation · ${job.earliest}`;
  elements.runTitle.textContent = `index=${job.index}`;
  elements.runSubtitle.textContent = `Created ${formatDate(job.created_at)}`;
  elements.activityFeed.replaceChildren();
  elements.reportContent.replaceChildren();
  elements.reportContent.classList.add("hidden");
  elements.reportEmpty.classList.remove("hidden");
  elements.downloadButton.classList.add("hidden");
  updateJobMetrics(job);
}

function updateJobMetrics(job) {
  state.activeJob = job;
  const label = statusLabel(job.status);
  elements.runStatus.textContent = label;
  elements.runStatus.className = `run-status ${job.status}`;
  elements.metricStatus.textContent = label;
  elements.metricQueries.textContent = job.tool_calls ?? 0;
  elements.metricTurns.textContent = job.turns ?? "-";
  elements.liveIndicator.classList.toggle("offline", ["succeeded", "failed"].includes(job.status));
  elements.liveIndicator.lastChild.textContent = job.status === "running" ? " Live" : " Finished";
  if (job.status === "failed") {
    elements.reportState.textContent = "Investigation failed";
    elements.reportEmpty.querySelector("strong").textContent = "No report generated";
    elements.reportEmpty.querySelector("p").textContent = job.error || "Review the activity trace.";
  }
  if (job.status === "succeeded") {
    elements.downloadButton.classList.remove("hidden");
  }
  startElapsedTimer(job);
  renderHistory();
}

function startElapsedTimer(job) {
  clearInterval(state.timer);
  const started = new Date(job.started_at || job.created_at).getTime();
  const render = () => {
    const end = job.completed_at ? new Date(job.completed_at).getTime() : Date.now();
    const seconds = Math.max(0, Math.floor((end - started) / 1000));
    elements.metricElapsed.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  };
  render();
  if (!job.completed_at) state.timer = setInterval(render, 1000);
}

function eventTitle(event) {
  return ({
    queued: "Investigation queued",
    running: "Agent process started",
    started: "Triage policy loaded",
    mcp_connected: "Connected to Splunk MCP",
    tool_call: `SPL query ${event.number || ""}`,
    completed: "Report validated and saved",
    failed: "Investigation failed",
  })[event.type] || event.message || event.type;
}

function appendActivity(event) {
  if (elements.activityFeed.querySelector(`[data-event-id="${event.id}"]`)) return;
  const item = document.createElement("div");
  item.className = `activity-item${event.type === "failed" ? " error" : ""}`;
  item.dataset.eventId = event.id;
  const title = document.createElement("strong");
  title.textContent = eventTitle(event);
  const time = document.createElement("time");
  time.textContent = formatDate(event.at);
  item.append(title, time);
  const query = event.input?.query;
  if (query) {
    const code = document.createElement("pre");
    code.textContent = query;
    item.append(code);
  } else if (event.message && event.message !== title.textContent) {
    const detail = document.createElement("pre");
    detail.textContent = event.message;
    item.append(detail);
  }
  elements.activityFeed.append(item);
  elements.activityFeed.scrollTop = elements.activityFeed.scrollHeight;
  if (event.type === "tool_call") elements.metricQueries.textContent = event.number;
}

async function consumeEvents(jobId, after = 0) {
  const response = await api(`/api/jobs/${jobId}/events?after=${after}`, { headers: { Accept: "text/event-stream" } });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop();
    for (const chunk of chunks) {
      let type = "message";
      let data = "";
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) type = line.slice(6).trim();
        if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (!data) continue;
      const payload = JSON.parse(data);
      if (type === "progress") appendActivity(payload);
      if (type === "end") {
        updateJobMetrics(payload);
        await loadJobs();
        if (payload.status === "succeeded") await loadReport(payload.id);
      }
    }
  }
}

function renderMarkdown(markdown) {
  elements.reportContent.replaceChildren();
  const lines = markdown.replace(/\r/g, "").split("\n");
  let list = null;
  let code = null;
  let table = null;
  const flushList = () => { if (list) { elements.reportContent.append(list); list = null; } };
  const flushTable = () => { if (table) { elements.reportContent.append(table); table = null; } };
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.startsWith("```")) {
      flushList(); flushTable();
      if (code) { elements.reportContent.append(code); code = null; }
      else { code = document.createElement("pre"); }
      continue;
    }
    if (code) { code.textContent += `${line}\n`; continue; }
    if (/^\|.*\|$/.test(line) && !/^\|[-: |]+\|$/.test(line)) {
      flushList();
      if (!table) table = document.createElement("table");
      const row = document.createElement("tr");
      for (const value of line.slice(1, -1).split("|")) {
        const cell = document.createElement(table.children.length ? "td" : "th");
        cell.textContent = value.trim().replace(/\*\*/g, "").replace(/`/g, "");
        row.append(cell);
      }
      table.append(row);
      continue;
    }
    if (/^\|[-: |]+\|$/.test(line)) continue;
    flushTable();
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      flushList();
      const node = document.createElement(`h${heading[1].length}`);
      node.textContent = heading[2].replace(/\*\*/g, "").replace(/`/g, "");
      elements.reportContent.append(node);
      continue;
    }
    const bullet = line.match(/^\s*(?:[-*]|\d+\.)\s+(.+)$/);
    if (bullet) {
      if (!list) list = document.createElement(/^\s*\d+\./.test(line) ? "ol" : "ul");
      const item = document.createElement("li");
      item.textContent = bullet[1].replace(/\*\*/g, "");
      list.append(item);
      continue;
    }
    flushList();
    if (!line.trim() || line === "---") continue;
    const node = document.createElement(line.startsWith("> ") ? "blockquote" : "p");
    node.textContent = line.replace(/^>\s?/, "").replace(/\*\*/g, "");
    elements.reportContent.append(node);
  }
  flushList(); flushTable();
  if (code) elements.reportContent.append(code);
}

async function loadReport(jobId) {
  try {
    const response = await api(`/api/jobs/${jobId}/report`);
    const markdown = await response.text();
    renderMarkdown(markdown);
    elements.reportEmpty.classList.add("hidden");
    elements.reportContent.classList.remove("hidden");
    elements.reportState.textContent = "Evidence-backed markdown";
  } catch (error) {
    toast(error.message);
  }
}

async function openJob(jobId) {
  try {
    const response = await api(`/api/jobs/${jobId}`);
    const job = await response.json();
    resetRunView(job);
    updateJobMetrics(job);
    if (job.status === "succeeded") await loadReport(job.id);
    consumeEvents(job.id).catch((error) => toast(error.message));
  } catch (error) {
    toast(error.message);
  }
}

async function createInvestigation(event) {
  event.preventDefault();
  elements.startButton.disabled = true;
  try {
    const response = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({ index: $("#index-input").value.trim(), earliest: $("#range-input").value }),
    });
    const job = await response.json();
    state.jobs.unshift(job);
    resetRunView(job);
    renderHistory();
    consumeEvents(job.id).catch((error) => toast(error.message));
  } catch (error) {
    if (error.message !== "Authentication required") toast(error.message);
  } finally {
    elements.startButton.disabled = false;
  }
}

async function downloadReport() {
  if (!state.activeJob) return;
  try {
    const response = await api(`/api/jobs/${state.activeJob.id}/report?download=true`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sockeye-${state.activeJob.id}.md`;
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) { toast(error.message); }
}

elements.form.addEventListener("submit", createInvestigation);
elements.newRunButton.addEventListener("click", showLaunch);
elements.authButton.addEventListener("click", () => showAuth());
elements.downloadButton.addEventListener("click", downloadReport);
elements.authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.apiKey = elements.apiKeyInput.value;
  sessionStorage.setItem("sockeye_api_key", state.apiKey);
  try {
    if (await loadJobs()) elements.authDialog.close();
  } catch (_) { /* loadJobs displays auth errors */ }
});

async function boot() {
  const configured = await loadConfig();
  if (configured && (!state.authRequired || state.apiKey)) await loadJobs();
}

boot();
