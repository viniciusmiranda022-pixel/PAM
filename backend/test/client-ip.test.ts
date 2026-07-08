import { describe, expect, it } from "vitest";
import type { FastifyRequest } from "fastify";
import { clientIp } from "../src/server.ts";

// HR-10: a origem auditada deve ser confiavel. O nginx sobrescreve X-Real-IP com
// o IP real do cliente, entao o backend NUNCA pode usar o X-Forwarded-For enviado
// pelo cliente (falsificavel). Estes testes negativos travam esse contrato.
function mkReq(headers: Record<string, string>, remoteAddress: string | undefined): FastifyRequest {
  return { headers, socket: { remoteAddress } } as unknown as FastifyRequest;
}

describe("clientIp — origem confiavel para auditoria (HR-10)", () => {
  it("IGNORA X-Forwarded-For forjado pelo cliente e usa o X-Real-IP do nginx", () => {
    const req = mkReq({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "10.0.0.9" }, "172.18.0.5");
    expect(clientIp(req)).toBe("10.0.0.9");
  });

  it("NAO aceita X-Forwarded-For sozinho; sem X-Real-IP cai no socket real", () => {
    const req = mkReq({ "x-forwarded-for": "9.9.9.9" }, "172.18.0.5");
    expect(clientIp(req)).toBe("172.18.0.5");
  });

  it("usa o remoteAddress do socket quando nao ha headers de proxy", () => {
    const req = mkReq({}, "203.0.113.7");
    expect(clientIp(req)).toBe("203.0.113.7");
  });

  it("nao confunde X-Real-IP com XFF: mesmo com XFF valido, prevalece X-Real-IP", () => {
    const req = mkReq({ "x-forwarded-for": "8.8.8.8, 172.18.0.5", "x-real-ip": "198.51.100.2" }, "172.18.0.5");
    expect(clientIp(req)).toBe("198.51.100.2");
  });
});
