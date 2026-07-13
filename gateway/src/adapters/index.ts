/**
 * Registry de adapters de protocolo (PR-16). O gateway resolve o adapter pelo
 * `protocol` do asset (vindo do banco). Protocolo sem adapter registrado e
 * RECUSADO — nunca ha fallback para proxy generico (HR-08/HR-09).
 *
 * Novos protocolos (RDP, SSH…) entram registrando um adapter aqui, um por PR.
 * Hoje ha exatamente um: VNC.
 */
import type { ProtocolAdapter } from "./types.js";
import { vncAdapter } from "./vnc/index.js";

const registry = new Map<string, ProtocolAdapter>();

function register(adapter: ProtocolAdapter): void {
  registry.set(adapter.protocol, adapter);
}

register(vncAdapter);

/** Adapter do protocolo, ou null se nao houver um registrado. */
export function getAdapter(protocol: string): ProtocolAdapter | null {
  return registry.get(protocol) ?? null;
}

/** Protocolos com adapter registrado (para o backend validar cadastro de asset). */
export function supportedProtocols(): string[] {
  return [...registry.keys()];
}

export type { ProtocolAdapter } from "./types.js";
