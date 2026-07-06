# frontend — Portal web + noVNC

Implementação a partir da **Fase 1** (página mínima de sessão) e **Fase 2** (portal).

Responsabilidades: login, lista de assets autorizados, tela de sessão com
`@novnc/novnc`, telas administrativas (Fase 4).

Regras deste diretório:
- Não existe (e não existirá) campo para digitar IP/hostname/porta (HR-01).
- O cliente recebe apenas `gatewayUrl` + token efêmero; nunca credencial (HR-05).
- Único cliente de protocolo permitido: noVNC (HR-09).
