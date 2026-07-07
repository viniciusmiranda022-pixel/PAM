/**
 * Registro em memoria das sessoes VNC ativas nesta instancia do gateway.
 * Permite ao watchdog derrubar ao vivo uma sessao que o backend marcou como
 * encerrada (kill de admin / pedido do usuario) — docs/session-flow.md.
 */
type Closer = (reason: string) => void;

const active = new Map<string, Closer>();

export function registerSession(id: string, closer: Closer): void {
  active.set(id, closer);
}

export function unregisterSession(id: string): void {
  active.delete(id);
}

export function activeSessionIds(): string[] {
  return [...active.keys()];
}

export function activeSessionCount(): number {
  return active.size;
}

export function closeSession(id: string, reason: string): void {
  active.get(id)?.(reason);
}
