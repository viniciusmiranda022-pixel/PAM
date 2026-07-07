# Fase 5.1 — Gravação de sessão + playback

Primeiro recurso avançado (a ordem que o brief define: administração → gravação →
SSO/MFA). O gateway grava a tela de cada sessão VNC; o admin assiste depois no
navegador. Mantém o escopo VNC-only e as garantias das fases anteriores.

## O que foi construído

| Componente | Entregue |
|---|---|
| **Gravador (gateway)** | Grava o stream **servidor→cliente** (a tela) em `recordings/<sessionId>.pamrec`, formato binário `PAMREC01`. Ligado pela flag `record_sessions` do asset e por `RECORDINGS_DIR`. |
| **API (backend)** | `GET /api/v1/admin/sessions/:id/recording` — **admin-only**, faz stream do arquivo e **audita** cada visualização (`recording.viewed`). `has_recording` na listagem de sessões; `recordSessions` no CRUD de assets. |
| **Playback (frontend)** | `/replay?sessionId=…`: baixa o `.pamrec` e reproduz no **noVNC** via um canal de replay, com controle de velocidade (1×–8×). Botão "assistir" na aba Sessões. |

## Decisão de privacidade: só a tela, nunca o teclado

O gravador captura **apenas o sentido servidor→cliente** (framebuffer). Os eventos
do cliente→servidor (teclado/mouse) **não** são gravados: podem conter senhas
digitadas *dentro* da sessão VNC. Isso é coerente com HR-06 (segredo nunca em
repouso onde não precisa estar) e verificado por teste (`direction === 0` em
todos os frames).

## Formato `PAMREC01`

```text
header:  "PAMREC01"                       (8 bytes ascii)
         u32BE len(ServerInit) + ServerInit
frame*:  u8  direção (0 = servidor→cliente)
         u32BE delta_ms desde o início
         u32BE len + payload
```

O parser tolera **arquivo truncado** (sessão interrompida/gateway derrubado):
descarta o último frame incompleto sem erro.

## Como o playback funciona

O `.pamrec` guarda o ServerInit e os frames **pós-handshake**, não o handshake
RFB. Para reproduzir, o frontend cria um "canal" que o noVNC usa no lugar do
WebSocket e que **re-emite o mesmo handshake sintético que o gateway faz ao
vivo** (RFB 3.8, security `None`, depois o ServerInit gravado); em seguida
entrega os frames com o `delta_ms` original (ajustado pela velocidade).

**Por que as cores batem:** tanto o visualizador ao vivo quanto o de replay são o
**mesmo noVNC**, que negocia o mesmo pixel format preferido. Como os frames foram
gravados já no formato que o noVNC ao vivo pediu, o noVNC de replay os decodifica
corretamente. (Limitação: assets que ignoram o `SetPixelFormat` do cliente podem
ter fidelidade de cor reduzida no replay — documentado.)

## Configuração

- `RECORDINGS_DIR` (gateway): diretório de gravação; **vazio desliga a gravação**
  globalmente. No compose é o volume `recordings` montado em `/recordings`
  (backend monta o mesmo volume **somente-leitura** para servir).
- `record_sessions` por asset (default `true`): permite desligar por ativo.
- Migração de banco: `infra/postgres/init/002-recordings.sql` (aplicada em volume
  novo; para banco existente, rodar manualmente — é idempotente com `IF NOT EXISTS`).

## Verificação (Postgres real + servidor RFB simulado)

| Suíte | Cobre | Resultado |
|---|---|---|
| gateway unit (recorder, 4) | round-trip do `PAMREC01`, writes pós-close, truncamento, magic | ✅ |
| integração 5.1 (10) | sessão real gravada → arquivo válido (só S→C), `recording_path` no banco, **admin baixa (200+magic)**, **usuário comum 403**, sessão sem gravação 404, **visualização auditada**, `has_recording` na listagem | ✅ |

## Pendências / próximo

- Ensaio visual do replay com noVNC + asset real (precisa de `docker pull`).
- Retenção/expurgo de gravações; cifra das gravações em repouso.
- Próximos avançados: SSO/OIDC, MFA, aprovação de acesso, VeNCrypt.
