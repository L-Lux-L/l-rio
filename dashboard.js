"use strict";

/**
 * CyberGuard MVP - dashboard.js (Fase 2)
 * Aplicação web do SaaS. Consome a mesma API Python do backend.
 * Token de sessão é salvo em localStorage (escopo desta aplicação web).
 *
 * XSS: nunca usamos innerHTML com dados vindos do backend — toda
 * renderização usa textContent/createElement.
 */

// O dashboard é servido pelo próprio backend Python (StaticFiles em /dashboard),
// então a API vive na mesma origem (window.location.origin).
const API_BASE = window.location.origin;

const STORAGE_KEY = "cyberguard_session";

const els = {
  accountBadge: document.getElementById("account-badge"),
  btnLoginNav: document.getElementById("btn-login-nav"),
  btnLogout: document.getElementById("btn-logout"),

  urlInput: document.getElementById("url-input"),
  modeSelect: document.getElementById("mode-select"),
  btnAnalyze: document.getElementById("btn-analyze"),
  analyzeResult: document.getElementById("analyze-result"),

  profileContent: document.getElementById("profile-content"),
  profileLockedOverlay: document.getElementById("profile-locked-overlay"),
  profileEmail: document.getElementById("profile-email"),
  profileRole: document.getElementById("profile-role"),
  profileTrial: document.getElementById("profile-trial"),
  mTotal: document.getElementById("m-total"),
  mAvg: document.getElementById("m-avg"),
  mRisk: document.getElementById("m-risk"),
  btnGotoSubscribe: document.getElementById("btn-goto-subscribe"),

  btnSubscribeNow: document.getElementById("btn-subscribe-now"),
  btnAlreadySubscriber: document.getElementById("btn-already-subscriber"),
  subscribeInfo: document.getElementById("subscribe-info"),

  loginEmail: document.getElementById("login-email"),
  loginPassword: document.getElementById("login-password"),
  btnDoLogin: document.getElementById("btn-do-login"),
  loginError: document.getElementById("login-error"),

  navButtons: document.querySelectorAll(".nav-btn"),
  views: document.querySelectorAll(".view"),
};

// --------------------------------------------------------------------------
// Sessão (localStorage)
// --------------------------------------------------------------------------

function saveSession(session) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

function loadSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

function clearSession() {
  localStorage.removeItem(STORAGE_KEY);
}

// --------------------------------------------------------------------------
// API helpers
// --------------------------------------------------------------------------

async function apiRequest(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  const session = loadSession();
  if (auth && session?.token) {
    headers["Authorization"] = `Bearer ${session.token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    /* sem corpo JSON */
  }

  if (!response.ok) {
    throw new Error(data?.detail || `Erro HTTP ${response.status}`);
  }
  return data;
}

// --------------------------------------------------------------------------
// Navegação entre "views"
// --------------------------------------------------------------------------

function showView(viewId) {
  els.views.forEach((v) => v.classList.toggle("hidden", v.id !== viewId));
  els.navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.view === viewId));

  if (viewId === "view-profile") {
    refreshProfile();
  }
}

els.navButtons.forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});

els.btnLoginNav.addEventListener("click", () => showView("view-login"));
els.btnGotoSubscribe.addEventListener("click", () => showView("view-subscribe"));
els.btnAlreadySubscriber.addEventListener("click", () => showView("view-login"));

els.btnSubscribeNow.addEventListener("click", () => {
  els.subscribeInfo.textContent =
    "Checkout ainda não integrado neste MVP. Em produção, este botão abriria o fluxo de pagamento (ex: Stripe).";
  els.subscribeInfo.classList.remove("hidden");
});

// --------------------------------------------------------------------------
// Badge de conta (topo)
// --------------------------------------------------------------------------

function renderAccountBadge(profile) {
  els.accountBadge.classList.remove("badge-trial", "badge-pro", "badge-dev");

  if (!profile) {
    els.accountBadge.textContent = "Trial";
    els.accountBadge.classList.add("badge-trial");
    els.btnLoginNav.classList.remove("hidden");
    els.btnLogout.classList.add("hidden");
    return;
  }

  if (profile.role === "developer") {
    els.accountBadge.textContent = "Conta Dev";
    els.accountBadge.classList.add("badge-dev");
  } else if (profile.pro_access) {
    els.accountBadge.textContent = "Assinante Pro";
    els.accountBadge.classList.add("badge-pro");
  } else {
    els.accountBadge.textContent = "Trial";
    els.accountBadge.classList.add("badge-trial");
  }

  els.btnLoginNav.classList.add("hidden");
  els.btnLogout.classList.remove("hidden");
}

// --------------------------------------------------------------------------
// Login / Logout
// --------------------------------------------------------------------------

els.btnDoLogin.addEventListener("click", async () => {
  els.loginError.classList.add("hidden");
  const email = els.loginEmail.value.trim();
  const password = els.loginPassword.value;

  if (!email || !password) {
    els.loginError.textContent = "Preencha e-mail e senha.";
    els.loginError.classList.remove("hidden");
    return;
  }

  try {
    const data = await apiRequest("/api/login", {
      method: "POST",
      auth: false,
      body: { email, password },
    });

    saveSession({
      token: data.token,
      role: data.role,
      email: data.email,
      pro_access: data.pro_access,
    });

    els.loginPassword.value = "";
    renderAccountBadge(data);
    showView("view-profile");
  } catch (err) {
    els.loginError.textContent = err.message || "Falha no login.";
    els.loginError.classList.remove("hidden");
  }
});

els.btnLogout.addEventListener("click", () => {
  clearSession();
  renderAccountBadge(null);
  showView("view-home");
});

// --------------------------------------------------------------------------
// Perfil (rota Pro protegida no backend)
// --------------------------------------------------------------------------

async function refreshProfile() {
  const session = loadSession();

  if (!session?.token) {
    lockProfile();
    return;
  }

  try {
    const data = await apiRequest("/api/profile");
    unlockProfile(data);
  } catch (err) {
    // 403 (trial tentando acessar perfil Pro) ou token expirado
    lockProfile();
  }
}

function lockProfile() {
  els.profileLockedOverlay.classList.remove("hidden");
}

function unlockProfile(profileData) {
  els.profileLockedOverlay.classList.add("hidden");

  els.profileEmail.textContent = profileData.email || "—";
  els.profileRole.textContent =
    profileData.role === "developer" ? "Desenvolvedor (acesso total)" :
    profileData.pro_access ? "Assinante Pro" : "Trial";
  els.profileTrial.textContent = profileData.trial?.trial_active
    ? `Ativo — ${profileData.trial.days_left} dia(s) restante(s)`
    : "Expirado";

  renderAccountBadge(profileData);
  loadHistoryMetricsIntoProfile();
}

async function loadHistoryMetricsIntoProfile() {
  // Demonstração das "métricas avançadas": roda uma mini-análise mock
  // sobre um conjunto fixo de URLs de exemplo, só para popular o painel.
  try {
    const data = await apiRequest("/api/analyze-history", {
      method: "POST",
      body: {
        urls: [
          "https://www.exemplo-seguro.com",
          "http://login-verify-account.xyz",
          "https://192.168.0.1/admin",
        ],
        mode: "profissional",
      },
    });
    els.mTotal.textContent = data.metrics.total_analisado ?? 0;
    els.mAvg.textContent = data.metrics.score_medio ?? 0;
    els.mRisk.textContent = data.metrics.quantidade_risco_alto ?? 0;
  } catch (_) {
    // silencioso — métricas são um extra, não bloqueiam o perfil
  }
}

// --------------------------------------------------------------------------
// Análise sob demanda (home)
// --------------------------------------------------------------------------

function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function renderAnalyzeResult(payload) {
  clearChildren(els.analyzeResult);
  const report = payload.report;

  const summary = document.createElement("div");
  summary.style.fontWeight = "700";
  summary.textContent = String(report.summary || "");
  els.analyzeResult.appendChild(summary);

  (report.findings || []).forEach((f) => {
    const line = document.createElement("div");
    line.className = "report-line";

    const sev = document.createElement("span");
    sev.className = `finding-sev sev-${String(f.severity || "baixa")}`;
    sev.textContent = String(f.severity || "");
    line.appendChild(sev);

    const msg = document.createElement("span");
    msg.textContent = String(f.message || "");
    line.appendChild(msg);

    els.analyzeResult.appendChild(line);
  });

  if (report.mode_downgraded) {
    const note = document.createElement("div");
    note.className = "upgrade-note";
    note.textContent = String(report.upgrade_message || "Recurso Pro necessário.");
    els.analyzeResult.appendChild(note);
  }

  if (report.pro_insights) {
    const insights = document.createElement("div");
    insights.className = "report-line";
    insights.textContent = `Pro insights — ${String(report.pro_insights.technical_notes || "")}`;
    els.analyzeResult.appendChild(insights);
  }
}

els.btnAnalyze.addEventListener("click", async () => {
  clearChildren(els.analyzeResult);
  const url = els.urlInput.value.trim();
  if (!url) {
    els.analyzeResult.textContent = "Informe uma URL.";
    return;
  }

  els.analyzeResult.textContent = "Analisando...";

  try {
    const data = await apiRequest("/api/analyze-site", {
      method: "POST",
      body: { url, mode: els.modeSelect.value },
    });
    renderAnalyzeResult(data);
  } catch (err) {
    els.analyzeResult.textContent = err.message || "Falha ao analisar.";
  }
});

// --------------------------------------------------------------------------
// Inicialização
// --------------------------------------------------------------------------

(function init() {
  const session = loadSession();
  renderAccountBadge(session);
  showView("view-home");
})();
