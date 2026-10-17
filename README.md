# CyberGuard MVP — Backend Python + Extensão Edge (Manifest V3)

Estrutura:
```
security-mvp/
├── backend/
│   ├── app.py
│   └── requirements.txt
└── extension/
    ├── manifest.json
    ├── popup.html
    ├── popup.css
    ├── popup.js
    └── background.js
```

## 1. Rodar o backend Python

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Teste rápido:
```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/license/status
```

O servidor cria automaticamente um arquivo `trial_state.json` na primeira
execução, marcando o início do trial de 7 dias (mock).

## 2. Carregar a extensão no Microsoft Edge (Developer Mode)

1. Abra `edge://extensions`
2. Ative **Modo de desenvolvedor** (canto inferior esquerdo)
3. Clique em **Carregar sem pacote (Load unpacked)**
4. Selecione a pasta `extension/`
5. Com o backend rodando em `http://localhost:8000`, clique no ícone da
   extensão, escolha o modo (Amador/Profissional) e use:
   - **Analisar Site Atual** → analisa a URL da aba ativa
   - **Analisar Histórico** → envia os 5 últimos itens do histórico

## Fase 2 — RBAC, Dashboard Web e Conta Dev

Novos arquivos:
```
backend/app.py            (atualizado: RBAC, /api/login, /api/profile, mount /dashboard)
backend/requirements.txt  (atualizado: + email-validator)
extension/popup.html      (atualizado: botão "Painel Completo" + mini-login)
extension/popup.css       (atualizado: estilos novos)
extension/popup.js        (atualizado: status de conta + login)
webapp/dashboard.html     (novo: aplicação web do SaaS)
webapp/dashboard.css      (novo: paleta rosa/branco)
webapp/dashboard.js       (novo: login, perfil Pro, overlay de bloqueio)
```

O dashboard é servido pelo próprio backend Python em:
`http://localhost:8000/dashboard/`

### Conta Dev (mock, permanente)
- E-mail: `dahoraluisgabriel@gmail.com`
- Senha: `2l3u8i6s070711`
- Ao logar com essas credenciais, o backend concede automaticamente
  `role="developer"`, que ignora o estado do trial e libera todos os
  recursos Pro (ver comentários `>>> SUPER-PERMISSÃO ... <<<` em `app.py`,
  função `_resolve_access`).

Conta de assinante mock adicional, para testar o fluxo "subscriber" sem
usar a conta dev: `assinante@teste.com` / `assinante123`.

**⚠️ Importante:** essas credenciais estão hardcoded em `app.py` apenas
para o MVP local. Antes de qualquer deploy público, versionamento em
repositório compartilhado ou uso em produção:
- Mova e-mail/senha para variáveis de ambiente (`CYBERGUARD_DEV_EMAIL` /
  `CYBERGUARD_DEV_PASSWORD`, já suportadas no código) ou um secrets manager.
- Troque essa senha por uma nova, gerada aleatoriamente, e nunca a
  reutilize em outro sistema.
- Substitua o "banco" em memória (`USERS_DB`, `TOKENS`) por um banco real
  e tokens JWT assinados com expiração adequada.

### O que é Trial vs Pro (subscriber/developer) agora
- **Trial**: análise básica de site, métricas simplificadas, histórico
  limitado a 5 URLs por chamada, sem acesso a `/api/profile` (403).
- **Pro (subscriber/developer)**: relatório profissional completo
  (`pro_insights`), análise de histórico sem limite de 5 itens, acesso à
  aba de Perfil no dashboard, e `developer` ainda ignora o contador do
  trial completamente.

### Observações de segurança do MVP

- CORS está aberto (`allow_origins=["*"]`) apenas para facilitar o teste
  local. Em produção, restrinja para o ID real da extensão.
- Todas as URLs recebidas passam por validação/sanitização no backend
  (`_sanitize_and_validate_url`) antes de qualquer processamento.
- O popup.js nunca usa `innerHTML` com dados vindos do backend — toda
  renderização usa `textContent`/`createElement` para evitar XSS.
- A "análise de risco" é um mock algorítmico (heurísticas simples sobre a
  própria URL: HTTPS, IP literal como host, TLDs suspeitos, palavras-chave,
  ofuscação). Não há fetch real do conteúdo do site neste MVP — é o ponto
  de partida para acoplar engines reais de threat intelligence depois.
- A licença/trial é mockada em arquivo local (`trial_state.json`); trocar
  por banco de dados + autenticação real antes de produção.
