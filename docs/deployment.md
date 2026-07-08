# Deploy local

## Pré-requisitos

- Docker + Docker Compose v2
- Node 22 (apenas para rodar os testes fora do container)

## 1. Configurar ambiente

```bash
cd infra
cp .env.example .env        # ajuste POSTGRES_PASSWORD, COOKIE_SECRET, etc.
../scripts/gen-certs.sh     # certificado TLS autoassinado para o Nginx (lab)
```

## 2. Subir a stack (Fase 1)

```bash
cd infra
docker compose --profile app up -d --build
```

Sobe: `postgres` (schema aplicado no 1º boot), `lab-vnc` (asset em rede
isolada, IP fixo 172.28.0.10), `backend`, `gateway`, `frontend` e `nginx`
(porta 443).

## 3. Semear o laboratório

```bash
cd infra
# exige SEED_USER_PASSWORD e SEED_ADMIN_PASSWORD no .env (sem default!)
docker compose --profile app run --rm backend node dist/seed.js
```

Cria os usuários `poc` e `admin` (senhas **obrigatórias** via
`SEED_USER_PASSWORD`/`SEED_ADMIN_PASSWORD` no `.env` — o seed falha sem elas e
não imprime senha), o grupo `vnc-ops`, o asset `lab-vnc` (172.28.0.10:5901) e a
permissão do grupo.

## 4. Usar

Abra `https://localhost` (aceite o certificado autoassinado), faça login com
`poc` e a senha definida em `SEED_USER_PASSWORD`, clique no ativo `lab-vnc` e a
sessão VNC abre no navegador.

## Isolamento de rede (HR-07)

A rede `assets_net` é `internal: true`: **nenhuma porta do asset é publicada no
host** e só o `gateway` participa dela (o `backend` não tem rota). Para provar:

```bash
cd infra
# o backend NAO alcanca o asset:
docker compose --profile app exec backend sh -c "nc -z -w2 172.28.0.10 5901; echo exit=$?"   # falha
# o gateway alcanca:
docker compose --profile app exec gateway sh -c "nc -z -w2 172.28.0.10 5901; echo exit=$?"    # ok
```

## Testes

Unitários (sem Docker):

```bash
cd gateway && npm ci && npm test      # RFB/DES + handshakes
cd backend && npm ci && npm test      # validacao estrita, KDF, trust-proxy, TOTP…
```

Integração + segurança (Postgres real; ver [`../tests/README.md`](../tests/README.md)):

```bash
(cd backend && npm run build) && (cd gateway && npm run build)   # a suite importa dist/
cd tests && npm ci
DATABASE_URL=... PAM_APP_URL=... PAM_APP_PASSWORD=... SCRYPT_N=16384 npm test
```

Tudo isso roda automaticamente no CI (`.github/workflows/ci.yml`) a cada push/PR,
com um Postgres de service container. O CI também roda os scans de segredo e de
dependência de proxy genérico e valida o `docker compose config`.

## TLS

- Local: certificado autoassinado (`scripts/gen-certs.sh`).
- Produção: ACME/Let's Encrypt ou PKI interna, terminado no Nginx. WSS obrigatório.

## Backup (Fase 4)

`pg_dump` agendado + retenção; documentação completa entra na Fase 4.
