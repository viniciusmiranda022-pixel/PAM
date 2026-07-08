# Auditoria função-por-função — o que funciona x o que é fachada

Este documento responde à pergunta do dono do produto: *"quais funções realmente
funcionam e quais só parecem existir?"* — antes de qualquer ajuste do pivot
multiprotocolo (ver [`adr/0001-pivot-multiprotocolo.md`](adr/0001-pivot-multiprotocolo.md)).

Ele é **honesto por design**: nada que seja parcial ou ausente é descrito como
pronto.

## Legenda

- **FUNCIONA** — lógica implementada e **validada** contra Postgres real ou contra
  um fake fiel que usa a criptografia/protocolo reais (ex.: DES conferido com
  vetores NIST, RS256/JWKS com RSA real, TLS real do Node).
- **PARCIAL** — a lógica é real e testada, mas **nunca foi validada contra o
  servidor/asset/browser reais** (ex.: RFB simulado, nunca um TigerVNC real; portal
  nunca aberto em um navegador real).
- **AUSENTE** — citado ou desejado, mas **não existe** no código.

> "PARCIAL" **não** significa mock enganoso. Significa: a implementação existe e
> passa nos testes automatizados, mas falta a prova ponta-a-ponta contra o mundo
> real. É exatamente essa lacuna que o hardening (PR-13) e os PRs de adapter
> endereçam.

## Matriz

| Área / Função | Componente | Status | Evidência atual | Ação recomendada |
|---|---|---|---|---|
| Login local (senha + cookie assinado) | `POST /auth/login` | FUNCIONA | Postgres real; cookie assinado | decidir KDF Argon2id×scrypt em ADR (PR-13) |
| MFA TOTP (RFC 6238) | `/auth/mfa/*` | FUNCIONA | vetores oficiais do RFC | manter |
| SSO / OIDC (Authorization Code, RS256/JWKS) | `/auth/oidc/*` | PARCIAL | RSA real + verificação de produção, mas só contra **IdP simulado** in-process | validar contra IdP real (Keycloak/Azure AD); consolidar (PR-15) |
| LDAP / ADFS | — | AUSENTE | não existe | implementar via OIDC/SAML/LDAPS (PR-15) |
| Criar sessão (só `assetId`, token efêmero uso-único/TTL) | `POST /sessions` | FUNCIONA | corrida de token e expiração testadas contra Postgres real | manter; adicionar `protocol` ao modelo (PR-16) |
| Rejeição de `host`/`port` no start de sessão | `POST /sessions` (schema) | FUNCIONA | teste de contrato | manter; estender p/ rejeitar `protocol` do cliente |
| Adapter VNC — terminação RFB (`None`/`VNCAuth`) | `gateway/` | PARCIAL | DES conferido com vetores NIST + **servidor RFB simulado**; **nunca** TigerVNC nem browser reais | formalizar como adapter VNC + smoke test contra TigerVNC real |
| Portal + cliente noVNC (tela no browser) | `frontend/public` | PARCIAL | fluxo exercitado via automação; **nunca** aberto em navegador real | validar em browser real; refatorar p/ Fluent (PR-14) |
| Gravação de sessão (PAMREC01) | `gateway` | PARCIAL | gravação testada em unidade | validar contra tráfego RFB real |
| Playback de gravação (replay no browser) | `frontend` `replay.html` | PARCIAL | **nunca** assistido em navegador real | validar playback real |
| Cofre AES-GCM (provider `enc`) | backend + gateway | FUNCIONA | e2e: backend cifra → gateway decifra | manter |
| Cofre HashiCorp Vault (provider `vault`) | backend + gateway | PARCIAL | testado contra **fake KV v2**; nunca Vault real | validar contra Vault real |
| VeNCrypt (TLS gateway→asset) | gateway | PARCIAL | **TLS real do Node**, mas contra servidor VeNCrypt **simulado**; nunca TigerVNC+VeNCrypt real | validar contra TigerVNC com VeNCrypt real |
| Admin CRUD (assets/users/groups/perms/ports) | `/admin/*` | FUNCIONA | integração contra Postgres real | manter |
| Acesso just-in-time (janela/catálogo/aprovação/justificativa) | `/access-requests`, `/admin/access-requests/*` | FUNCIONA | integração contra Postgres real | manter |
| Rate limit (login / criação de sessão) | backend | FUNCIONA | testado | manter (nota HA: store compartilhado p/ multi-instância) |
| Health / métricas | backend + gateway | FUNCIONA | testado | manter |
| Encerramento forçado (kill ao vivo, watchdog) | backend + gateway | FUNCIONA | derruba WebSocket ao vivo no teste | manter |
| Auditoria de sessão/eventos | `audit_logs` | FUNCIONA na gravação, **mas IP de origem é spoofável** | XFF confiado sem restrição de proxy | corrigir XFF: nginx `$remote_addr` + `trustProxy` restrito (PR-13) |
| Auditoria append-only (grants no banco) | `audit_logs` | PARCIAL | documentado como "app sem UPDATE/DELETE", **não aplicado** — app usa um único usuário DB | usuário DB de runtime com privilégio mínimo (PR-13) |
| CI/CD | `.github/` | AUSENTE | não existe pipeline versionado | criar CI mínimo (PR-13) |
| Suíte de testes de integração versionada | `tests/` | AUSENTE | só testes **unitários** estão no repo; a integração foi executada de forma descartável | versionar a suíte de integração (PR-13) |
| "Build" do frontend | `frontend` | AUSENTE (é estático) | não há passo de build | CI usa `npm ci` + syntax-check, não `npm run build` |
| Adapters RDP / SSH | — | AUSENTE | planejados | um adapter por PR (PR-17+), RDP antes de SSH |

## Conclusão

A **lógica é sólida e bem testada** contra fakes fiéis e Postgres real: criptografia
conferida com vetores oficiais, fluxos de auth/sessão/admin exercitados de ponta a
ponta em processo. **Nenhuma função é um mock que finge existir de forma enganosa.**

O risco real é outro — **"parece pronto, mas não foi provado ponta-a-ponta"**:

1. **Nada foi validado contra o mundo real:** nenhum TigerVNC/servidor VNC real,
   nenhum navegador real, nenhum IdP/Vault real. Tudo contra fakes in-process
   (fiéis, mas fakes).
2. **A suíte de integração não está no repositório** — só os testes unitários estão
   versionados; a integração rodou de forma descartável.
3. **Não há CI** — nenhuma garantia automática contra regressão a cada mudança.
4. **Há um defeito de segurança real:** o IP de origem na auditoria é spoofável via
   `X-Forwarded-For` (o gateway/backend confia no header sem restringir o proxy).
5. **Funções enterprise ausentes:** LDAP/ADFS e uma UI de nível corporativo não
   existem.

Esses cinco pontos são exatamente o conteúdo dos próximos PRs (PR-13 hardening/CI,
PR-14 UI, PR-15 auth enterprise) antes de abrir novos protocolos por adapter
(PR-16/PR-17+).
