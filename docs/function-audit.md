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
| Login local (senha + cookie assinado) | `POST /auth/login` | FUNCIONA | Postgres real; cookie assinado; KDF scrypt (N=2^17) com rehash transparente | ✅ KDF decidido em [`adr/0002-kdf-scrypt.md`](adr/0002-kdf-scrypt.md) (PR-13) |
| MFA TOTP (RFC 6238) | `/auth/mfa/*` | FUNCIONA | vetores oficiais do RFC | manter |
| SSO / OIDC (Authorization Code + PKCE, RS256/JWKS) | `/auth/oidc/*` | PARCIAL | Consolidado (PR-15): PKCE S256, rotação de JWKS, `client_secret_basic`, grupo→role. RSA real, mas só contra **IdP simulado** | validar contra IdP real (Entra/ADFS) |
| ADFS | `/auth/oidc/*` (2019+) · `/auth/saml/*` (legado) | PARCIAL | Coberto por OIDC e por SAML (assinatura XML real via `@node-saml`), mas só contra IdP simulado | validar contra ADFS real |
| SAML 2.0 (SP) | `/auth/saml/*` | PARCIAL | Assertion assinada validada (lib madura); IdP SAML simulado com assinatura real | validar contra ADFS/Shibboleth real |
| LDAP / LDAPS | — | AUSENTE | adiado ao **PR-15B** (só LDAPS interno; nunca LDAP exposto) | implementar se necessário (PR-15B) |
| Criar sessão (só `assetId`, token efêmero uso-único/TTL) | `POST /sessions` | FUNCIONA | corrida de token e expiração testadas contra Postgres real | manter; adicionar `protocol` ao modelo (PR-16) |
| Rejeição de `host`/`port` no start de sessão | `POST /sessions` (schema) | FUNCIONA | teste de contrato | manter; estender p/ rejeitar `protocol` do cliente |
| Adapter registry (resolve protocolo, recusa desconhecido) | `gateway/src/adapters/` | FUNCIONA | ✅ registry + interface `ProtocolAdapter` (PR-16); e2e in-process recusa protocolo sem adapter | manter |
| Adapter VNC — terminação RFB (`None`/`VNCAuth`) | `gateway/src/adapters/vnc/` | PARCIAL | ✅ isolado atrás do contrato (PR-16); DES×NIST + **RFB simulado** + e2e com par WebSocket real; **nunca** TigerVNC real | smoke test contra TigerVNC real |
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
| Auditoria de sessão/eventos | `audit_logs` | FUNCIONA | ✅ IP não mais spoofável: nginx sobrescreve XFF com `$remote_addr`, `trustProxy` restrito, teste `tests/security/xff-spoof` prova | manter |
| Auditoria append-only (grants no banco) | `audit_logs` | FUNCIONA (opt-in) | ✅ role `pam_app` de runtime: UPDATE/DELETE em `audit_logs` negados, provado em `tests/security/audit-append-only` | ativar em produção (`PAM_APP_PASSWORD` + `DATABASE_URL` da role) |
| CI/CD | `.github/workflows/ci.yml` | FUNCIONA | ✅ typecheck+test+build (backend/gateway), syntax-check (frontend), integração c/ Postgres, scans, `compose config` (PR-13) | manter |
| Suíte de testes de integração versionada | `tests/` | FUNCIONA | ✅ `tests/integration` + `tests/security` versionadas (14 casos) contra Postgres real (PR-13) | expandir por adapter |
| "Build" do frontend | `frontend` | AUSENTE (é estático) | por design; CI faz `node --check` em `server.mjs`/`public/*.js` (não `npm run build`) | manter |
| Seed com senha default em log | `backend/src/seed.ts` | FUNCIONA | ✅ senhas obrigatórias via env, sem default, sem senha no stdout (HR-06, PR-13) | manter |
| Adapter RDP — decisão da engine | `docs/adr/0005` | EM DECISÃO | ADR `Accepted — Conditional` (PR-17A): **RDP Worker próprio + libfreerdp** preferencial (matriz preenchida; guacd rejeitado por decisão de produto). **Condicionada apenas ao gate P0** (é decisão de engine) | PR-17B: spike isolado do worker; depois smoke P0 |
| Adapter RDP — worker (spike) | — | AUSENTE | worker/harness isolado, sem integração; **validado no P0** (Windows/xrdp) | PR-17B (fora do sandbox p/ smoke P0) |
| Adapter RDP — integrado (adapter+broker) | — | AUSENTE | **desenvolvido nos PRs 17C–17F** em perfil de laboratório; `SUPPORTED_PROTOCOLS=["vnc"]`; gateway recusa `rdp`; sem UI/rota/asset RDP de produção | PR-17C **bloqueado até P0 verde**; PRs 17D/17E/17F na sequência |
| Suporte RDP de produção | — | AUSENTE | **condicionado ao gate P1** (produto integrado end-to-end, executado **após o PR-17F**) | Gate P1 |
| Habilitação de RDP em runtime | — | AUSENTE | `SUPPORTED_PROTOCOLS = ["vnc","rdp"]` **somente no PR-17G**, após P1 verde | PR-17G |
| Adapter SSH | — | AUSENTE | planejado, depois do RDP | PR-18+ |

## Conclusão

A **lógica é sólida e bem testada** contra fakes fiéis e Postgres real: criptografia
conferida com vetores oficiais, fluxos de auth/sessão/admin exercitados de ponta a
ponta em processo. **Nenhuma função é um mock que finge existir de forma enganosa.**

O risco real é outro — **"parece pronto, mas não foi provado ponta-a-ponta"**.
Estado após o **PR-13 (hardening & CI)**:

1. **Nada foi validado contra o mundo real** — ⏳ pendente: nenhum TigerVNC/servidor
   VNC real, nenhum navegador real, nenhum IdP/Vault real. Tudo contra fakes
   in-process (fiéis, mas fakes). Exige host com `docker pull` liberado.
2. ~~A suíte de integração não está no repositório~~ — ✅ **resolvido (PR-13):**
   `tests/integration` e `tests/security` versionadas (14 casos, Postgres real).
3. ~~Não há CI~~ — ✅ **resolvido (PR-13):** `.github/workflows/ci.yml`.
4. ~~IP de origem spoofável via `X-Forwarded-For`~~ — ✅ **resolvido (PR-13):**
   nginx `$remote_addr` + `trustProxy` restrito, com teste dedicado.
5. **Funções enterprise ausentes** — ⏳ pendente: LDAP/ADFS (PR-15) e uma UI de
   nível corporativo (PR-14) ainda não existem.

Também no PR-13: senhas removidas do seed (sem default, sem log), role de banco
com privilégio mínimo (auditoria append-only) e decisão de KDF em ADR. Restam os
pontos 1 e 5, endereçados pelos PR-14/PR-15 e pelos smoke tests reais, antes de
abrir novos protocolos por adapter (PR-16/PR-17+).
