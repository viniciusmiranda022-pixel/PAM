# tests

Suítes transversais (unitários vivem dentro de cada componente):

- `integration/` — fluxo completo portal → sessão → gateway → asset de lab
- `security/` — testes que travam os hard requirements:
  - start de sessão rejeita `host`/`port` (HR-01/02)
  - porta fora da allowlist bloqueada na API, no banco e no gateway (HR-04)
  - token expira e é de uso único, inclusive sob corrida (Fase 3)
  - teste-sentinela: senha semeada não aparece em nenhum log nem no HAR (HR-05/06)
  - gateway recusa destino sem banner RFB (HR-08)
  - lockfiles sem bibliotecas de outros protocolos (HR-09)
- `e2e/` — Playwright: login, abrir sessão VNC, encerrar, kill por admin
