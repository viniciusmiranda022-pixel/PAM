import type { Db } from "./db.js";
import { activeSessionIds, closeSession } from "./registry.js";

/**
 * Consulta periodicamente o banco: qualquer sessao ativa neste gateway que o
 * backend tenha marcado como nao-ativa (terminated pelo admin/usuario) tem seu
 * WebSocket e TCP derrubados na hora. Torna o "encerrar sessao" efetivo ao vivo.
 */
export function startTerminationWatchdog(db: Db, intervalMs: number): NodeJS.Timeout {
  const timer = setInterval(() => {
    const ids = activeSessionIds();
    if (ids.length === 0) return;
    db.findTerminatedAmong(ids)
      .then((stale) => {
        for (const id of stale) closeSession(id, "forced_disconnect");
      })
      .catch(() => {
        /* tenta de novo no proximo ciclo */
      });
  }, intervalMs);
  timer.unref?.();
  return timer;
}
