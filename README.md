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

## Observações de segurança do MVP

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
