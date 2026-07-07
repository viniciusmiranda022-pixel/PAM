import { Registry, collectDefaultMetrics, Counter } from "prom-client";

export const registry = new Registry();
collectDefaultMetrics({ register: registry });

const logins = new Counter({
  name: "pam_backend_logins_total",
  help: "Tentativas de login por resultado",
  labelNames: ["result"],
  registers: [registry],
});
const sessionsCreated = new Counter({
  name: "pam_backend_sessions_created_total",
  help: "Sessoes criadas",
  registers: [registry],
});
const rateLimited = new Counter({
  name: "pam_backend_rate_limited_total",
  help: "Requisicoes bloqueadas por rate limit, por rota",
  labelNames: ["route"],
  registers: [registry],
});

export const metrics = {
  login: (result: "ok" | "fail") => logins.inc({ result }),
  sessionCreated: () => sessionsCreated.inc(),
  rateLimited: (route: string) => rateLimited.inc({ route }),
};
