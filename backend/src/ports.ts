/**
 * Denylist IMUTAVEL de portas (em codigo, nunca no banco). Estas portas de
 * outros protocolos jamais podem entrar na allowlist de portas VNC — HR-04 /
 * docs/security-requirements.md secao 2.
 */
export const PORT_DENYLIST: ReadonlySet<number> = new Set([
  22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 465, 587, 636, 1433, 1521,
  3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017,
]);

/** Retorna o motivo da recusa, ou null se a porta pode entrar na allowlist. */
export function portRejectionReason(port: number): string | null {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    return "porta deve estar entre 1024 e 65535";
  }
  if (PORT_DENYLIST.has(port)) {
    return "porta pertence a protocolo nao-VNC (denylist imutavel)";
  }
  return null;
}
