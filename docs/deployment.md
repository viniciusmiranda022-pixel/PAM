# Deploy local (estado da Fase 0)

## Pré-requisitos

- Docker + Docker Compose v2

## Subir a infraestrutura

```bash
cd infra
cp .env.example .env        # ajuste senhas locais
docker compose up -d
```

O que sobe hoje (Fase 0):

| Serviço | Rede | Descrição |
|---|---|---|
| `postgres` | `app_net` | PostgreSQL 16 com o schema de `postgres/init/` aplicado no primeiro boot |
| `lab-vnc` | `assets_net` (isolada) | Asset VNC de laboratório para as Fases 1–2 |

A rede `assets_net` é `internal: true`: **nenhuma porta do asset é publicada no
host** e somente containers dessa rede o alcançam. Isso modela, desde já, o
requisito HR-07 (usuário sem rota direta ao asset) — para conectar no lab-vnc
será obrigatório passar pelo gateway.

Os serviços de aplicação (`backend`, `gateway`, `frontend`, `nginx`, `vault`)
estão declarados sob o **profile `app`** e serão ativados conforme as fases:

```bash
docker compose --profile app up -d   # a partir da Fase 1
```

## Verificações

```bash
docker compose ps
docker compose exec postgres psql -U pam -d pam -c '\dt'   # tabelas criadas
docker compose exec postgres psql -U pam -d pam -c 'SELECT * FROM allowed_ports;'
```

## TLS

- Local: certificado autoassinado gerado por `scripts/` (Fase 1).
- Produção: ACME/Let's Encrypt ou PKI interna, terminado no Nginx. WSS obrigatório.

## Backup (Fase 4)

`pg_dump` agendado + retenção; documentação completa entra na Fase 4.
