"""
MVP - Backend de Cibersegurança
--------------------------------
Servidor local em Python (FastAPI) que serve como "cérebro" do SaaS.
A extensão de navegador é apenas um cliente leve que consome esta API.

Rotas:
  POST /api/analyze-site      -> analisa uma URL (modo amador/profissional)
  POST /api/analyze-history   -> analisa uma lista de URLs do histórico
  GET  /api/license/status    -> status do trial (mock, 7 dias)
  POST /api/login             -> autentica usuário (trial/subscriber/developer)
  GET  /api/profile           -> retorna perfil + nível de acesso do usuário logado
  GET  /dashboard             -> aplicação web (SaaS) servida como arquivos estáticos

FASE 2 — RBAC (Role Based Access Control):
  Papéis suportados: "trial", "subscriber", "developer".
  Recursos Pro (perfil completo, gráficos avançados, relatório profissional
  completo, análise profunda de histórico) exigem "subscriber" ou "developer".
  A conta "developer" é uma conta mock permanente usada apenas para testes
  internos do time — ver seção AUTENTICAÇÃO / RBAC abaixo.

  ATENÇÃO (segurança): as credenciais da conta developer estão hardcoded
  neste arquivo apenas para fins de MVP local. Antes de qualquer deploy
  público ou versionamento em repositório compartilhado, mova-as para
  variáveis de ambiente / secrets manager e nunca reutilize essa senha em
  outro lugar.

Rodar:
  uvicorn app:app --reload --port 8000
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator

# --------------------------------------------------------------------------
# Configuração da aplicação
# --------------------------------------------------------------------------

app = FastAPI(title="CyberGuard MVP API", version="0.1.0")

# CORS liberado para a extensão (chrome-extension:// / edge-extension://)
# Em produção, restrinja isso a IDs de extensão específicos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

TRIAL_FILE = Path(__file__).parent / "trial_state.json"
TRIAL_DAYS = 7

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "work", "loan"}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "wallet", "free", "bonus", "prize", "urgent",
}
MAX_URL_LENGTH = 2048
MAX_HISTORY_ITEMS = 50


# --------------------------------------------------------------------------
# RBAC (Role Based Access Control) — Fase 2
# --------------------------------------------------------------------------
# Papéis de usuário suportados pelo sistema.
Role = Literal["trial", "subscriber", "developer"]

# Papéis que têm direito aos recursos PAGOS (Pro): perfil completo,
# gráficos avançados, análise profunda de histórico, relatório profissional.
PRO_ROLES: set[str] = {"subscriber", "developer"}

# Hash de senha simples com PBKDF2-HMAC-SHA256 (biblioteca padrão do Python,
# sem dependências extras). Cada usuário mock tem seu próprio "salt".
_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return digest.hex()


def _make_user_record(email: str, password: str, role: Role) -> dict:
    salt = secrets.token_bytes(16)
    return {
        "email": email.lower(),
        "role": role,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
    }


# Credenciais da conta DEV — sobrescrevíveis por variáveis de ambiente
# (recomendado para qualquer ambiente que não seja 100% local/MVP).
_DEV_EMAIL = os.environ.get("CYBERGUARD_DEV_EMAIL", "dahoraluisgabriel@gmail.com")
_DEV_PASSWORD = os.environ.get("CYBERGUARD_DEV_PASSWORD", "2l3u8i6s070711")

# "Banco de dados" de usuários em memória (MVP). Trocar por banco real
# (Postgres, etc.) antes de produção — nunca versionar senhas em texto puro.
USERS_DB: dict[str, dict] = {
    # ------------------------------------------------------------------
    # >>> CONTA DEV PERMANENTE <<<
    # Regra de negócio: autenticar com este e-mail/senha SEMPRE resulta
    # em role="developer", concedendo acesso total e irrestrito a todos
    # os recursos Pro/assinante — ver bypass explícito em `_resolve_access()`.
    # ------------------------------------------------------------------
    _DEV_EMAIL.lower(): _make_user_record(_DEV_EMAIL, _DEV_PASSWORD, "developer"),
    # Conta de assinante mock, apenas para testar o fluxo "subscriber" sem
    # usar a conta dev.
    "assinante@teste.com": _make_user_record("assinante@teste.com", "assinante123", "subscriber"),
}

# Sessões/tokens emitidos no login. MVP simples em memória — trocar por
# JWT assinado ou sessão em banco/redis antes de produção.
TOKENS: dict[str, dict] = {}
TOKEN_TTL_HOURS = 12


def _issue_token(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {
        "email": user["email"],
        "role": user["role"],
        "issued_at": datetime.now(timezone.utc),
    }
    return token


def _resolve_access(authorization: Optional[str]) -> dict:
    """Resolve o nível de acesso da requisição a partir do header Authorization.

    Retorna sempre um dict com: role, email (ou None), pro_access (bool).
    Se não houver token válido, o usuário é tratado como "trial" anônimo,
    sujeito ao contador de 7 dias do arquivo trial_state.json.
    """
    trial = _get_trial_status()

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        session = TOKENS.get(token)

        if session:
            expires_at = session["issued_at"] + timedelta(hours=TOKEN_TTL_HOURS)
            if datetime.now(timezone.utc) <= expires_at:
                role = session["role"]

                # ------------------------------------------------------
                # >>> SUPER-PERMISSÃO DO PAPEL "developer" <<<
                # Qualquer sessão com role == "developer" ignora
                # completamente o estado do trial (mesmo expirado) e
                # qualquer outra restrição de assinatura: pro_access
                # é sempre True. Este é o bypass automático exigido
                # pela regra de negócio da conta dev.
                # ------------------------------------------------------
                if role == "developer":
                    return {
                        "role": role,
                        "email": session["email"],
                        "pro_access": True,
                        "trial": trial,
                    }

                # subscriber pagante: também tem acesso Pro, independente
                # do estado do trial (ele já não depende mais do trial).
                if role in PRO_ROLES:
                    return {
                        "role": role,
                        "email": session["email"],
                        "pro_access": True,
                        "trial": trial,
                    }

            # token expirado: remove da memória
            TOKENS.pop(token, None)

    # Sem token válido -> usuário anônimo em modo trial.
    return {
        "role": "trial",
        "email": None,
        "pro_access": False,
        "trial": trial,
    }


def get_access(authorization: Optional[str] = Header(default=None)) -> dict:
    """Dependency do FastAPI: injeta o contexto de acesso (role/pro_access)."""
    return _resolve_access(authorization)


def require_pro_access(access: dict = Depends(get_access)) -> dict:
    """Dependency que BLOQUEIA a rota inteira se o usuário não for Pro.

    Usada nas rotas exclusivamente pagas (ex: perfil completo do dashboard).
    Usuários "developer" sempre passam por aqui (pro_access é sempre True
    para esse papel, conforme `_resolve_access`).
    """
    if not access["pro_access"]:
        raise HTTPException(
            status_code=403,
            detail="Recurso exclusivo para assinantes (Pro). Faça upgrade da sua conta.",
        )
    return access


# --------------------------------------------------------------------------
# Modelos (Pydantic) - validação e sanitização de entrada
# --------------------------------------------------------------------------

Mode = Literal["amador", "profissional"]


def _sanitize_and_validate_url(raw: str) -> str:
    """Sanitiza e valida uma URL recebida do cliente.

    - Limita tamanho
    - Exige esquema http/https
    - Exige host válido
    - Remove espaços/controles
    """
    if not raw or not isinstance(raw, str):
        raise ValueError("URL vazia ou inválida.")

    candidate = raw.strip()
    # remove caracteres de controle
    candidate = re.sub(r"[\x00-\x1f\x7f]", "", candidate)

    if len(candidate) == 0 or len(candidate) > MAX_URL_LENGTH:
        raise ValueError("Tamanho de URL inválido.")

    parsed = urlparse(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Apenas URLs http/https são aceitas.")

    if not parsed.netloc:
        raise ValueError("URL sem host válido.")

    return candidate


class AnalyzeSiteRequest(BaseModel):
    url: str = Field(..., description="URL completa do site a ser analisado")
    mode: Mode = Field(default="amador")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            return _sanitize_and_validate_url(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class AnalyzeHistoryRequest(BaseModel):
    urls: list[str] = Field(..., description="Lista de URLs do histórico do navegador")
    mode: Mode = Field(default="amador")

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list):
            raise ValueError("O campo 'urls' deve ser uma lista.")
        if len(v) == 0:
            raise ValueError("Lista de URLs vazia.")
        if len(v) > MAX_HISTORY_ITEMS:
            v = v[:MAX_HISTORY_ITEMS]

        sanitized: list[str] = []
        for item in v:
            try:
                sanitized.append(_sanitize_and_validate_url(item))
            except ValueError:
                # ignora silenciosamente entradas inválidas do histórico
                continue

        if not sanitized:
            raise ValueError("Nenhuma URL válida encontrada na lista.")
        return sanitized


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)


# --------------------------------------------------------------------------
# Motor de análise (heurísticas simples / mock algorítmico)
# --------------------------------------------------------------------------

def _is_ip_host(host: str) -> bool:
    host_clean = host.split(":")[0]
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False


def _analyze_url_risk(url: str) -> dict:
    """Aplica heurísticas simples de risco sobre a URL.

    Isto é um MOCK algorítmico para o MVP — não substitui engines reais
    de threat intelligence, apenas simula a estrutura do relatório.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    findings: list[dict] = []
    score = 100  # começa em 100 (seguro) e vai perdendo pontos

    is_https = parsed.scheme == "https"
    if not is_https:
        score -= 30
        findings.append({
            "id": "no_https",
            "severity": "alta",
            "message_amador": "O site não usa uma conexão segura (cadeado).",
            "message_profissional": "Conexão sem TLS/HTTPS — tráfego passível de interceptação (MITM).",
        })

    if _is_ip_host(host):
        score -= 25
        findings.append({
            "id": "ip_as_host",
            "severity": "alta",
            "message_amador": "O endereço do site é um número estranho, não um nome normal.",
            "message_profissional": "Host representado por endereço IP literal — padrão comum em phishing/C2.",
        })

    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score -= 15
        findings.append({
            "id": "suspicious_tld",
            "severity": "media",
            "message_amador": f"O final do endereço ('.{tld}') é usado com frequência em golpes.",
            "message_profissional": f"TLD '.{tld}' possui alta incidência histórica em campanhas de phishing.",
        })

    subdomain_count = max(host.count("."), 0)
    if subdomain_count >= 4:
        score -= 10
        findings.append({
            "id": "too_many_subdomains",
            "severity": "media",
            "message_amador": "O endereço do site é muito longo e confuso.",
            "message_profissional": "Excesso de subdomínios — técnica comum para ofuscar o domínio real.",
        })

    lowered_host = host.lower()
    hit_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered_host]
    if hit_keywords:
        score -= 10
        findings.append({
            "id": "suspicious_keywords",
            "severity": "baixa",
            "message_amador": "O nome do site contém palavras usadas em golpes (ex: 'login', 'verify').",
            "message_profissional": f"Palavras-chave sensíveis detectadas no host: {', '.join(hit_keywords)}.",
        })

    if "@" in url or url.count("//") > 1:
        score -= 20
        findings.append({
            "id": "url_obfuscation",
            "severity": "alta",
            "message_amador": "O link parece estar tentando esconder o site verdadeiro.",
            "message_profissional": "Estrutura da URL sugere ofuscação (uso de '@' ou múltiplos '//').",
        })

    score = max(0, min(100, score))

    if score >= 80:
        classification = "seguro"
    elif score >= 50:
        classification = "atencao"
    else:
        classification = "risco"

    return {
        "url": url,
        "host": host,
        "https": is_https,
        "score": score,
        "classification": classification,
        "findings": findings,
    }


def _build_pro_insights(analysis: dict) -> dict:
    """Camada de dados extra, exclusiva para role Pro (subscriber/developer).

    Simula os "gráficos avançados" e o "relatório profissional completo"
    mencionados nos requisitos — aqui como métricas mock adicionais que a
    aplicação web (dashboard) pode plotar em gráficos.
    """
    severity_breakdown = {"alta": 0, "media": 0, "baixa": 0}
    for f in analysis["findings"]:
        severity_breakdown[f["severity"]] = severity_breakdown.get(f["severity"], 0) + 1

    return {
        "severity_breakdown": severity_breakdown,
        "risk_delta_100": 100 - analysis["score"],
        "technical_notes": (
            f"host={analysis['host']} | https={analysis['https']} | "
            f"achados_totais={len(analysis['findings'])}"
        ),
    }


def _build_report(analysis: dict, mode: Mode, pro_access: bool = False) -> dict:
    """Monta o relatório final, adaptando a linguagem ao modo escolhido.

    `pro_access` controla se o campo extra `pro_insights` (recurso pago)
    é incluído na resposta.
    """
    key = "message_amador" if mode == "amador" else "message_profissional"

    findings_view = [
        {
            "id": f["id"],
            "severity": f["severity"],
            "message": f[key],
        }
        for f in analysis["findings"]
    ]

    if mode == "amador":
        summary = {
            "seguro": "Este site parece seguro para navegação. 🟢",
            "atencao": "Este site tem alguns pontos de atenção. 🟡",
            "risco": "Este site apresenta sinais de risco elevado. 🔴",
        }[analysis["classification"]]
    else:
        summary = (
            f"Score de risco: {analysis['score']}/100 | "
            f"Classificação: {analysis['classification'].upper()} | "
            f"HTTPS: {'sim' if analysis['https'] else 'não'} | "
            f"Achados: {len(findings_view)}"
        )

    report = {
        "url": analysis["url"],
        "host": analysis["host"],
        "mode": mode,
        "score": analysis["score"],
        "classification": analysis["classification"],
        "summary": summary,
        "findings": findings_view,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pro_locked": not pro_access,
    }

    # Recurso PAGO: relatório profissional completo + dados para gráficos
    # avançados. Só entra na resposta se o usuário tiver pro_access=True
    # (subscriber ou developer — ver `_resolve_access`).
    if pro_access:
        report["pro_insights"] = _build_pro_insights(analysis)

    return report


# --------------------------------------------------------------------------
# Mock de licença / trial (persistido em arquivo local simples)
# --------------------------------------------------------------------------

def _load_trial_state() -> dict:
    if TRIAL_FILE.exists():
        try:
            return json.loads(TRIAL_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    # primeira execução: registra o início do trial agora
    state = {"trial_start": datetime.now(timezone.utc).isoformat()}
    TRIAL_FILE.write_text(json.dumps(state), encoding="utf-8")
    return state


def _get_trial_status() -> dict:
    state = _load_trial_state()
    try:
        start = datetime.fromisoformat(state["trial_start"])
    except (KeyError, ValueError):
        start = datetime.now(timezone.utc)

    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)

    elapsed = datetime.now(timezone.utc) - start
    remaining = timedelta(days=TRIAL_DAYS) - elapsed
    days_left = max(0, remaining.days + (1 if remaining.seconds > 0 else 0))
    active = remaining.total_seconds() > 0

    return {
        "trial_active": active,
        "days_left": days_left,
        "trial_start": start.isoformat(),
        "trial_days_total": TRIAL_DAYS,
    }


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": time.time()}


@app.get("/api/license/status")
def license_status() -> dict:
    return _get_trial_status()


@app.post("/api/login")
def login(payload: LoginRequest) -> dict:
    """Autentica um usuário e emite um token de sessão (Bearer).

    A conta DEV (`_DEV_EMAIL` / `_DEV_PASSWORD`) está pré-cadastrada em
    USERS_DB com role="developer" — ao logar com essas credenciais, o
    usuário recebe automaticamente um token com super-permissão (ver
    bypass em `_resolve_access`), sem nenhum passo manual adicional.
    """
    user = USERS_DB.get(payload.email.lower())

    # Comparação em tempo constante para reduzir risco de timing attack.
    valid = False
    if user is not None:
        candidate_hash = _hash_password(payload.password, user["salt"])
        valid = hmac.compare_digest(candidate_hash, user["password_hash"])

    if not user or not valid:
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos.")

    token = _issue_token(user)

    return {
        "token": token,
        "role": user["role"],
        "email": user["email"],
        "pro_access": user["role"] in PRO_ROLES,  # developer/subscriber => True
    }


@app.get("/api/profile")
def profile(access: dict = Depends(require_pro_access)) -> dict:
    """Rota Pro: retorna o perfil completo do usuário logado.

    Protegida por `require_pro_access` — usuários "trial" recebem 403.
    Usuários "developer" sempre passam (super-permissão automática).
    """
    return {
        "email": access["email"],
        "role": access["role"],
        "pro_access": access["pro_access"],
        "is_developer": access["role"] == "developer",
        "trial": access["trial"],
    }


@app.post("/api/analyze-site")
def analyze_site(payload: AnalyzeSiteRequest, access: dict = Depends(get_access)) -> dict:
    # Usuários "trial" seguem bloqueados quando o período de 7 dias expira.
    # Usuários Pro (subscriber/developer) NÃO dependem mais do trial —
    # a super-permissão do "developer" já é aplicada dentro de `get_access`.
    if access["role"] == "trial" and not access["trial"]["trial_active"]:
        raise HTTPException(status_code=402, detail="Período de teste grátis expirado.")

    requested_mode = payload.mode
    mode_downgraded = False
    # Recurso PAGO: relatório em modo "profissional" completo. Se o
    # usuário não é Pro, o modo é rebaixado para "amador" automaticamente
    # (em vez de bloquear a chamada inteira).
    if requested_mode == "profissional" and not access["pro_access"]:
        requested_mode = "amador"
        mode_downgraded = True

    try:
        analysis = _analyze_url_risk(payload.url)
        report = _build_report(analysis, requested_mode, pro_access=access["pro_access"])
    except Exception as exc:  # pragma: no cover - proteção defensiva do MVP
        raise HTTPException(status_code=500, detail=f"Falha ao analisar URL: {exc}") from exc

    if mode_downgraded:
        report["mode_downgraded"] = True
        report["upgrade_message"] = "Assine o plano Pro para relatórios profissionais completos."

    return {
        "trial": access["trial"],
        "role": access["role"],
        "pro_access": access["pro_access"],
        "report": report,
    }


@app.post("/api/analyze-history")
def analyze_history(payload: AnalyzeHistoryRequest, access: dict = Depends(get_access)) -> dict:
    if access["role"] == "trial" and not access["trial"]["trial_active"]:
        raise HTTPException(status_code=402, detail="Período de teste grátis expirado.")

    urls = payload.urls
    # Recurso PAGO: análise PROFUNDA de histórico. Usuários trial ficam
    # limitados a 5 URLs por chamada; Pro (subscriber/developer) pode
    # analisar a lista completa enviada (até MAX_HISTORY_ITEMS).
    if not access["pro_access"]:
        urls = urls[:5]

    requested_mode = payload.mode
    if requested_mode == "profissional" and not access["pro_access"]:
        requested_mode = "amador"

    reports = []
    total_score = 0
    risky_count = 0

    for url in urls:
        try:
            analysis = _analyze_url_risk(url)
        except Exception:
            continue
        report = _build_report(analysis, requested_mode, pro_access=access["pro_access"])
        reports.append(report)
        total_score += report["score"]
        if report["classification"] == "risco":
            risky_count += 1

    avg_score = round(total_score / len(reports), 1) if reports else 0

    metrics = {
        "total_analisado": len(reports),
        "score_medio": avg_score,
        "quantidade_risco_alto": risky_count,
    }

    # Camada Pro: agregados extras para os gráficos avançados do dashboard.
    if access["pro_access"]:
        classification_counts = {"seguro": 0, "atencao": 0, "risco": 0}
        for r in reports:
            classification_counts[r["classification"]] = classification_counts.get(r["classification"], 0) + 1
        metrics["pro_distribuicao_classificacao"] = classification_counts

    return {
        "trial": access["trial"],
        "role": access["role"],
        "pro_access": access["pro_access"],
        "metrics": metrics,
        "reports": reports,
    }


# --------------------------------------------------------------------------
# Aplicação Web (dashboard do SaaS) — servida pelo próprio backend Python
# --------------------------------------------------------------------------
_WEBAPP_DIR = Path(__file__).parent.parent / "webapp"
if _WEBAPP_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_WEBAPP_DIR), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
