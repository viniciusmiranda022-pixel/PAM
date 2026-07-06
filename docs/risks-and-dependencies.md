# Riscos técnicos e dependências externas

## 1. Riscos técnicos

Ordenados por severidade × probabilidade.

| # | Risco | Impacto | Mitigação |
|---|-------|---------|-----------|
| R1 | **Terminação RFB no gateway** é a peça mais complexa: versões (3.3/3.7/3.8) e security types variados (None, VNCAuth, Tight, VeNCrypt, RA2, Apple ARD…). Servidores como UltraVNC/RealVNC usam extensões proprietárias. | Assets incompatíveis com o MVP | Escopo fechado: RFB 3.8 + `None`/`VNC Authentication`. Matriz de servidores homologados (TigerVNC, x11vnc, TightVNC) testada em CI com containers. Incompatibilidade → erro claro + auditoria, nunca fallback inseguro |
| R2 | **Gateway virar proxy genérico** por regressão (ex.: alguém "flexibiliza" para debug) | Quebra do produto inteiro (HR-08) | Defesa em camadas: destino só via sessão→asset→banco; FK de allowlist; denylist em código; validação de banner RFB; teste de segurança automatizado que tenta abusar do gateway a cada build |
| R3 | **Vazamento do token efêmero** (log, histórico, referer) | Sequestro de sessão | Token em subprotocolo WS (não em URL), TTL 30s, uso único, hash no banco, WSS obrigatório |
| R4 | **Senha VNC vazar** em log/erro/stacktrace | Comprometimento do asset | `pino.redact`; credencial confinada ao módulo do cofre no gateway; teste sentinela (semear senha única e grepar logs+HAR) |
| R5 | **Limitações do protocolo VNC**: senha DES truncada em 8 chars; RFB sem criptografia nativa no trecho gateway→asset | Exposição na rede de assets | Documentar aos operadores; `assets_net` segregada com firewall; VeNCrypt/TLS no backlog (Fase 5) |
| R6 | **Conexões WebSocket longas** × deploy/restart do gateway | Sessões caem em manutenção | Drain no shutdown com `end_reason=gateway_shutdown`; janela de manutenção; múltiplas instâncias (token validado no banco → qualquer instância atende) |
| R7 | **Auditoria no mesmo Postgres** pode ser alterada por quem tem acesso ao banco | Perda de valor probatório | Papel da app sem UPDATE/DELETE em `audit_logs`; Fase 4+: ship para store externo (syslog/SIEM) |
| R8 | **Cofre como ponto único de falha** (Vault selado/fora) | Nenhuma sessão nova abre | Sessões ativas não dependem do cofre (senha usada só no handshake); health check inclui cofre; runbook de unseal |
| R9 | **Exfiltração via clipboard VNC** (`ClientCutText`/`ServerCutText`) | Vazamento de dados do asset | Flag por asset para o gateway filtrar mensagens de clipboard (Fase 3+) |
| R10 | **Desempenho noVNC** em telas grandes/latência alta | Experiência ruim | Encodings Tight/ZRLE habilitados; qualidade ajustável; metas de latência definidas na Fase 4 |
| R11 | **Enumeração de assets** por IDs sequenciais ou mensagens de erro distintas | Reconhecimento por usuário malicioso | UUIDs v4; listagem já filtra por permissão; 403 padronizado sem detalhes |

## 2. Dependências externas

| Dependência | Uso | Tipo | Observação |
|---|---|---|---|
| noVNC (`@novnc/novnc`) | cliente VNC no navegador | biblioteca (MPL-2.0) | componente central do frontend; versão pinada |
| PostgreSQL 16 | estado + auditoria | serviço | imagem oficial |
| HashiCorp Vault | cofre de credenciais (Fase 3) | serviço (BUSL) | avaliar OpenBao (fork MPL) se licença for restrição |
| Nginx | TLS/WSS, reverse proxy | serviço | imagem oficial |
| Node.js 22 LTS | backend, gateway, build do frontend | runtime | — |
| Fastify, Zod, Drizzle, `ws`, argon2, pino, prom-client | backend/gateway | bibliotecas npm | auditadas via `npm audit`/lockfile em CI |
| React + Vite | portal web | bibliotecas npm | — |
| Docker / Docker Compose | ambiente local e deploy inicial | ferramenta | — |
| Servidor VNC de laboratório (ex.: `theasp/novnc`-like desktop, TigerVNC em container) | asset de teste das Fases 1–2 | imagem de teste | qualquer servidor RFB 3.8 serve |
| Certificados TLS (ACME/Let's Encrypt ou PKI interna) | HTTPS/WSS em produção | serviço externo | autoassinado no lab |
| Vitest / Playwright | testes | bibliotecas | Playwright já disponível no ambiente de CI |

**Não-dependências deliberadas:** Guacamole (multiprotocolo — violaria HR-09),
websockify (túnel puro — não permite terminação RFB/HR-05), qualquer SDK de
RDP/SSH.
