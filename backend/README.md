# backend — API + Session Broker

Implementação a partir da **Fase 1** (mínimo) e **Fase 2** (MVP).

Responsabilidades: autenticação, usuários/grupos, permissões, CRUD de assets
(admin), criação/encerramento de sessão, emissão do token efêmero, auditoria.

Regras deste diretório:
- Validação estrita de entrada: start de sessão aceita **somente** `assetId`
  (HR-02); payload com `host`/`port` retorna 400.
- Respostas para usuário comum nunca contêm IP/porta do asset.
- Senha VNC é write-only: entra no cadastro, vai ao cofre, nunca retorna.
- Logger com redaction estrutural de segredos (HR-06).
