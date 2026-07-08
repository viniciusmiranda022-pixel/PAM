# frontend — Portal web + cliente de sessão

Portal estático (HTML + CSS + JS vanilla, **sem build e sem framework**) servido
por `server.mjs`. A camada visual enterprise (Fluent-like) vive em
`public/style.css` como um design system por tokens, com tema claro/escuro.

Responsabilidades: login (senha, MFA, SSO), lista de ativos autorizados, catálogo
just-in-time, tela de sessão com `@novnc/novnc` (adapter VNC), playback de
gravação e telas administrativas.

Regras deste diretório:
- Não existe (e não existirá) campo para o usuário digitar destino técnico —
  IP, hostname, porta, URL ou comando (HR-01).
- O cliente recebe apenas `gatewayUrl` + token efêmero; nunca credencial (HR-05).
  O usuário comum não vê IP/porta/credencial/token em nenhuma tela.
- O cliente de sessão embarcado é o **noVNC**, correspondente ao adapter VNC.
  Novos protocolos entram por adapter próprio (nunca proxy genérico, HR-09).
- Sem inline script: todo JS/CSS é externo, para respeitar a CSP do Nginx.

## Estrutura

```text
public/
  index.html   portal (login → ativos → sessão)
  admin.html   administração (shell com navegação lateral)
  replay.html  playback de gravação
  style.css    design system enterprise (tokens, claro/escuro)
  app.js       portal
  admin.js     administração (CRUDs, sessões, auditoria)
  replay.js    player da gravação PAMREC01
server.mjs     servidor estático (serve public/ e a lib noVNC em /novnc/)
```
