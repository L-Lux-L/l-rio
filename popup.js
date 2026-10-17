"use strict";

/**
 * CyberGuard MVP - popup.js
 * Cliente leve: apenas coleta dados do navegador (aba ativa / histórico)
 * e envia para o backend Python, que concentra toda a inteligência.
 *
 * Cuidado com XSS: NUNCA usamos innerHTML com dados vindos do backend.
 * Toda renderização usa createElement/textContent.
 */

const API_BASE = "http://localhost:8000";

const els = {
  modeSelect: document.getElementById("mode-select"),
  btnAnalyzeSite: document.getElementById("btn-analyze-site"),
  btnAnalyzeHistory: document.getElementById("btn-analyze-history"),
  loading: document.getElementById("loading"),
  errorBox: document.getElementById("error-box"),
  result: document.getElementById("result"),
  trialStatus: document.getElementById("trial-status"),
  accountStatus: document.getElementById("account-status"),
  btnFullPanel: document.getElementById("btn-full-panel"),
  miniLoginEmail: document.getElementById("mini-login-email"),
  miniLoginPassword: document.getElementById("mini-login-password"),
  btnMiniLogin: document.getElementById("btn-mini-login"),
  miniLoginError: document.getElementById("mini-login-error"),
};

// Fase 2: URL da aplicação web (dashboard) servida pelo backend Python.
const DASHBOARD_URL = `${API_BASE}/dashboard/`;

// --------------------------------------------------------------------------
// Utilitários de UI
// --------------------------------------------------------------------------

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function showLoading(isLoading) {
  els.loading.classList.toggle("hidden", !isLoading);
  els.btnAnalyzeSite.disabled = isLoading;
  els.btnAnalyzeHistory.disabled = isLoading;
}

function showError(message) {
  els.errorBox.textContent = message;
  els.errorBox.classList.remove("hidden");
}

function clearError() {
  els.errorBox.textContent = "";
  els.errorBox.classList.add("hidden");
}

function getSelectedMode() {
  return els.modeSelect.value === "profissional" ? "profissional" : "amador";
}

// --------------------------------------------------------------------------
// Comunicação com o backend Python
// --------------------------------------------------------------------------

async function apiPost(path, body, { auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = await getStoredToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    // resposta sem corpo JSON válido
  }

  if (!response.ok) {
    const detail =
      (data && typeof data.detail === "string" && data.detail) ||
      `Erro HTTP ${response.status}`;
    throw new Error(detail);
  }

  return data;
}

async function apiGet(path) {
  const response = await fetch(`${API_BASE}${path}`);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.detail || `Erro HTTP ${response.status}`);
  }
  return data;
}

// --------------------------------------------------------------------------
// Renderização segura (sem innerHTML com dados externos)
// --------------------------------------------------------------------------

function renderAccountStatus(profile) {
  if (!profile) {
    els.accountStatus.classList.add("hidden");
    return;
  }

  els.accountStatus.classList.remove("hidden", "pro", "dev");

  if (profile.role === "developer") {
    els.accountStatus.textContent = "Conta Pro / Dev Ativa";
    els.accountStatus.classList.add("dev");
  } else if (profile.pro_access) {
    els.accountStatus.textContent = "Conta Pro / Dev Ativa";
    els.accountStatus.classList.add("pro");
  } else {
    els.accountStatus.classList.add("hidden");
  }
}

function renderTrial(trial) {
  if (!trial) return;
  if (trial.trial_active) {
    els.trialStatus.textContent = `Trial ativo — ${trial.days_left} dia(s) restante(s).`;
    els.trialStatus.classList.remove("expired");
  } else {
    els.trialStatus.textContent = "Trial expirado. Funcionalidades bloqueadas.";
    els.trialStatus.classList.add("expired");
  }
}

function buildFindingNode(finding) {
  const wrapper = document.createElement("div");
  wrapper.className = "finding";

  const sevSpan = document.createElement("span");
  sevSpan.className = `sev sev-${String(finding.severity || "baixa")}`;
  sevSpan.textContent = String(finding.severity || "");
  wrapper.appendChild(sevSpan);

  const msg = document.createElement("span");
  msg.textContent = String(finding.message || "");
  wrapper.appendChild(msg);

  return wrapper;
}

function buildReportCard(report) {
  const card = document.createElement("div");
  const classification = String(report.classification || "").toLowerCase();
  card.className = `report-card ${["seguro", "atencao", "risco"].includes(classification) ? classification : ""}`;

  const urlEl = document.createElement("div");
  urlEl.className = "url";
  urlEl.textContent = String(report.url || "");
  card.appendChild(urlEl);

  const summaryEl = document.createElement("div");
  summaryEl.className = "summary";
  summaryEl.textContent = String(report.summary || "");
  card.appendChild(summaryEl);

  const findings = Array.isArray(report.findings) ? report.findings : [];
  findings.forEach((finding) => {
    card.appendChild(buildFindingNode(finding));
  });

  if (findings.length === 0) {
    const okMsg = document.createElement("div");
    okMsg.className = "finding";
    okMsg.textContent = "Nenhum ponto de atenção encontrado.";
    card.appendChild(okMsg);
  }

  return card;
}

function renderSiteResult(payload) {
  clearChildren(els.result);
  renderTrial(payload.trial);
  els.result.appendChild(buildReportCard(payload.report));
}

function renderHistoryResult(payload) {
  clearChildren(els.result);
  renderTrial(payload.trial);

  const metrics = payload.metrics || {};
  const metricsBox = document.createElement("div");
  metricsBox.className = "metrics";

  const m1 = document.createElement("span");
  m1.textContent = `Analisados: ${metrics.total_analisado ?? 0}`;
  const m2 = document.createElement("span");
  m2.textContent = `Score médio: ${metrics.score_medio ?? 0}`;
  const m3 = document.createElement("span");
  m3.textContent = `Alto risco: ${metrics.quantidade_risco_alto ?? 0}`;

  metricsBox.appendChild(m1);
  metricsBox.appendChild(m2);
  metricsBox.appendChild(m3);
  els.result.appendChild(metricsBox);

  const reports = Array.isArray(payload.reports) ? payload.reports : [];
  reports.forEach((report) => {
    els.result.appendChild(buildReportCard(report));
  });
}

// --------------------------------------------------------------------------
// Ações principais
// --------------------------------------------------------------------------

async function handleAnalyzeSite() {
  clearError();
  showLoading(true);
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      throw new Error("Não foi possível obter a URL da aba ativa.");
    }

    const payload = await apiPost("/api/analyze-site", {
      url: tab.url,
      mode: getSelectedMode(),
    });

    renderSiteResult(payload);
  } catch (err) {
    showError(err.message || "Falha ao analisar o site atual.");
  } finally {
    showLoading(false);
  }
}

async function handleAnalyzeHistory() {
  clearError();
  showLoading(true);
  try {
    const historyItems = await chrome.history.search({
      text: "",
      maxResults: 5,
      startTime: 0,
    });

    const urls = historyItems
      .map((item) => item.url)
      .filter((url) => typeof url === "string" && url.length > 0);

    if (urls.length === 0) {
      throw new Error("Nenhum item de histórico encontrado.");
    }

    const payload = await apiPost("/api/analyze-history", {
      urls,
      mode: getSelectedMode(),
    });

    renderHistoryResult(payload);
  } catch (err) {
    showError(err.message || "Falha ao analisar o histórico.");
  } finally {
    showLoading(false);
  }
}

async function loadInitialTrialStatus() {
  try {
    const trial = await apiGet("/api/license/status");
    renderTrial(trial);
  } catch (err) {
    els.trialStatus.textContent = "Backend Python offline.";
    els.trialStatus.classList.add("expired");
  }
}

// --------------------------------------------------------------------------
// Fase 2: sessão (token guardado em chrome.storage.local, escopo da extensão)
// --------------------------------------------------------------------------

async function getStoredToken() {
  const stored = await chrome.storage.local.get("authToken");
  return stored?.authToken || null;
}

async function loadAccountStatus() {
  const token = await getStoredToken();
  if (!token) {
    renderAccountStatus(null);
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/api/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      renderAccountStatus(null);
      return;
    }
    const profile = await response.json();
    renderAccountStatus(profile);
  } catch (_) {
    renderAccountStatus(null);
  }
}

async function handleMiniLogin() {
  els.miniLoginError.classList.add("hidden");
  const email = els.miniLoginEmail.value.trim();
  const password = els.miniLoginPassword.value;

  if (!email || !password) {
    els.miniLoginError.textContent = "Preencha e-mail e senha.";
    els.miniLoginError.classList.remove("hidden");
    return;
  }

  try {
    const data = await apiPost("/api/login", { email, password });
    await chrome.storage.local.set({ authToken: data.token });
    els.miniLoginPassword.value = "";
    renderAccountStatus(data);
  } catch (err) {
    els.miniLoginError.textContent = err.message || "Falha no login.";
    els.miniLoginError.classList.remove("hidden");
  }
}

function handleOpenFullPanel() {
  chrome.tabs.create({ url: DASHBOARD_URL });
}

// --------------------------------------------------------------------------
// Inicialização
// --------------------------------------------------------------------------

els.btnAnalyzeSite.addEventListener("click", handleAnalyzeSite);
els.btnAnalyzeHistory.addEventListener("click", handleAnalyzeHistory);
els.btnFullPanel.addEventListener("click", handleOpenFullPanel);
els.btnMiniLogin.addEventListener("click", handleMiniLogin);

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const stored = await chrome.storage.local.get("preferredMode");
    if (stored?.preferredMode) {
      els.modeSelect.value = stored.preferredMode;
    }
  } catch (_) {
    // storage indisponível, segue com padrão
  }
  loadInitialTrialStatus();
  loadAccountStatus();
});

els.modeSelect.addEventListener("change", () => {
  chrome.storage.local.set({ preferredMode: getSelectedMode() });
});
