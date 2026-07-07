import { Registry, collectDefaultMetrics, Counter, Gauge } from "prom-client";
import { activeSessionCount } from "./registry.js";

export const registry = new Registry();
collectDefaultMetrics({ register: registry });

const started = new Counter({
  name: "pam_gateway_sessions_started_total",
  help: "Sessoes VNC iniciadas",
  registers: [registry],
});
const ended = new Counter({
  name: "pam_gateway_sessions_ended_total",
  help: "Sessoes VNC encerradas, por motivo",
  labelNames: ["reason"],
  registers: [registry],
});
new Gauge({
  name: "pam_gateway_active_sessions",
  help: "Sessoes VNC ativas neste gateway",
  registers: [registry],
  collect() {
    this.set(activeSessionCount());
  },
});

export const metrics = {
  sessionStarted: () => started.inc(),
  sessionEnded: (reason: string) => ended.inc({ reason }),
};
