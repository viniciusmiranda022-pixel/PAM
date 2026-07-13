/**
 * Contrato de um adapter de protocolo (PR-16). Cada protocolo suportado pelo
 * gateway (hoje: VNC) implementa esta interface. A orquestracao de sessao
 * (session.ts) e agnostica: valida token, resolve destino/credencial do banco,
 * conecta o TCP e delega a TERMINACAO DO HANDSHAKE ao adapter — nunca ha proxy
 * TCP generico (HR-08/HR-09).
 *
 * Regras que todo adapter deve honrar:
 *  - terminar o handshake do protocolo DOS DOIS LADOS (asset e navegador);
 *  - nunca enviar a credencial ao navegador (HR-05);
 *  - validar que o destino realmente fala o protocolo esperado (HR-08);
 *  - lancar AdapterHandshakeError (com evento de auditoria e close code) em falha.
 */
import type net from "node:net";
import type tls from "node:tls";
import type { WebSocket } from "ws";
import type { ByteStreamReader } from "../byte-stream-types.js";

/**
 * Opcoes de TLS do cliente (gateway→asset), neutras de protocolo. O contrato
 * generico NAO importa nada de adapters/vnc/ — a dependencia vai sempre do
 * adapter para o contrato, nunca o contrario.
 */
export interface AdapterTlsOptions {
  rejectUnauthorized: boolean;
  ca?: Buffer;
  servername?: string;
}

/** Codigos de close do WebSocket usados na terminacao (docs/api-contract.md §4). */
export const ADAPTER_CLOSE = {
  CLIENT_INVALID: 4400,
  ASSET_FAIL: 4503,
  AUTH_FAIL: 4504,
} as const;

/** Falha de handshake mapeada para auditoria + close code, sem vazar segredo. */
export class AdapterHandshakeError extends Error {
  constructor(
    /** Motivo tecnico (vai para end_reason). */
    public readonly reason: string,
    /** Evento de auditoria correspondente (HR-10). */
    public readonly auditEvent: string,
    /** Codigo de close do WebSocket. */
    public readonly closeCode: number,
  ) {
    super(reason);
    this.name = "AdapterHandshakeError";
  }
}

/** Entrada da terminacao: sockets/streams dos dois lados + politica do asset. */
export interface AdapterConnectContext {
  /** TCP ja conectado ao destino resolvido pelo backend (ip:porta do banco). */
  assetSocket: net.Socket;
  /** Credencial resolvida do cofre — fica no gateway, nunca vai ao navegador. */
  credential: string;
  /** Exige TLS gateway→asset (VeNCrypt no VNC). */
  tlsRequired: boolean;
  /** Opcoes de TLS do cliente (CA/rejectUnauthorized). */
  tlsOptions: AdapterTlsOptions;
  /** WebSocket do navegador. */
  ws: WebSocket;
  /** Leitor sobre o WebSocket (para o handshake e o residual do splice). */
  wsStream: ByteStreamReader;
  /** Envia bytes ao navegador. */
  wsSend: (b: Buffer) => void;
  /** Timeout de cada etapa do handshake. */
  timeoutMs: number;
  /** Envolve uma etapa com timeout rotulado. */
  withTimeout: <T>(p: Promise<T>, ms: number, label: string) => Promise<T>;
}

/** Resultado da terminacao: o que o orquestrador precisa para splice/gravacao. */
export interface AdapterConnectResult {
  /** Socket efetivo do asset a ser usado no splice (o TLS quando houve VeNCrypt). */
  effectiveAssetSocket: net.Socket | tls.TLSSocket;
  /** Reader sobre o socket efetivo (para dar flush no residual bufferizado). */
  assetStream: ByteStreamReader;
  /** Preambulo p/ gravacao (ex.: ServerInit do RFB); null se o protocolo nao tiver. */
  recordingPreamble: Buffer | null;
  /** TLS estabelecido no trecho gateway→asset (para auditoria). */
  tlsEstablished: boolean;
}

export interface ProtocolAdapter {
  /** Identificador do protocolo (valor de assets.protocol). Ex.: "vnc". */
  readonly protocol: string;
  /** Portas padrao do protocolo (base da allowlist por protocolo — HR-04). */
  readonly defaultPorts: readonly number[];
  /** Termina o handshake dos dois lados. Lanca AdapterHandshakeError em falha. */
  connect(ctx: AdapterConnectContext): Promise<AdapterConnectResult>;
}
