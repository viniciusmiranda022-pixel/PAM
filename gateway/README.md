# gateway — VNC Gateway (WebSocket → TCP)

Componente mais sensível do projeto. Implementação a partir da **Fase 1**.

Responsabilidades:
- Upgrade WebSocket + consumo atômico do token efêmero (uso único, TTL 30s)
- Conexão TCP **somente** para `(ip, porta)` da sessão válida (nunca do cliente)
- Validação de banner `RFB` antes de qualquer splice
- Terminação RFB 3.8: `None` lado navegador, `VNC Authentication` lado asset
- Encerramento simétrico: WS fecha ⇒ TCP fecha (e vice-versa) + auditoria

Regras deste diretório:
- Dependências mínimas (`ws` + driver de banco). **Nenhuma** biblioteca de
  RDP/SSH/Telnet/etc. (HR-09) — CI bloqueia.
- Nenhum caminho de código que aceite host/porta vindos do cliente (HR-08).
- Credencial do cofre confinada ao módulo de handshake; jamais em log (HR-06).
