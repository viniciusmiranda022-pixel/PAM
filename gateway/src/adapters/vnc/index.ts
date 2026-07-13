/**
 * Adapter VNC (RFB) — o primeiro adapter oficial (PR-16). Encapsula a
 * terminacao RFB dos dois lados que antes vivia solta em session.ts. O
 * comportamento e IDENTICO ao anterior; apenas foi isolado atras do contrato
 * ProtocolAdapter. Ver docs/protocols/vnc.md e docs/architecture.md §4.
 */
import {
  AdapterHandshakeError,
  ADAPTER_CLOSE,
  type AdapterConnectContext,
  type AdapterConnectResult,
  type ProtocolAdapter,
} from "../types.js";
import { assetHandshakeTls, browserHandshake } from "./handshake.js";
import { RfbError } from "./rfb.js";

class VncAdapter implements ProtocolAdapter {
  readonly protocol = "vnc";
  readonly defaultPorts = [5900, 5901, 5902] as const;

  async connect(ctx: AdapterConnectContext): Promise<AdapterConnectResult> {
    // Lado asset: banner RFB + auth (VNC Authentication), TLS via VeNCrypt se exigido.
    let hs;
    try {
      hs = await ctx.withTimeout(
        assetHandshakeTls(ctx.assetSocket, ctx.credential, ctx.tlsRequired, ctx.tlsOptions),
        ctx.timeoutMs,
        "asset-rfb",
      );
    } catch (err) {
      throw mapAssetError(err);
    }

    // Lado navegador: RFB 3.8 + None (nenhuma credencial trafega — HR-05).
    try {
      await ctx.withTimeout(
        browserHandshake(ctx.wsStream, ctx.wsSend, hs.serverInit),
        ctx.timeoutMs,
        "browser-rfb",
      );
    } catch {
      throw new AdapterHandshakeError(
        "client_handshake_failed",
        "gateway.client_handshake_failed",
        ADAPTER_CLOSE.CLIENT_INVALID,
      );
    }

    return {
      effectiveAssetSocket: hs.socket,
      assetStream: hs.stream,
      recordingPreamble: hs.serverInit, // PAMREC01 grava a partir do ServerInit
      tlsEstablished: ctx.tlsRequired,
    };
  }
}

/** Mapeia a falha do handshake RFB para o evento de auditoria + close code. */
function mapAssetError(err: unknown): AdapterHandshakeError {
  const isAuth = err instanceof RfbError && /autentica/.test(err.message);
  const isBanner = err instanceof RfbError && /banner|RFB/.test(err.message);
  const isTls = err instanceof RfbError && /VeNCrypt|tls_required/i.test(err.message);
  if (isBanner) return new AdapterHandshakeError("asset_handshake_failed", "gateway.banner_mismatch", ADAPTER_CLOSE.ASSET_FAIL);
  if (isTls) return new AdapterHandshakeError("asset_handshake_failed", "gateway.tls_required_failed", ADAPTER_CLOSE.ASSET_FAIL);
  if (isAuth) return new AdapterHandshakeError("vnc_auth_failed", "gateway.vnc_auth_failed", ADAPTER_CLOSE.AUTH_FAIL);
  return new AdapterHandshakeError("asset_handshake_failed", "gateway.asset_handshake_failed", ADAPTER_CLOSE.ASSET_FAIL);
}

export const vncAdapter: ProtocolAdapter = new VncAdapter();
