import { describe, expect, it } from "vitest";
import { parseTrustProxy } from "../src/config.ts";

describe("parseTrustProxy (HR-10: fonte confiavel de IP)", () => {
  it("ausente/false => false (ignora X-Forwarded-For)", () => {
    expect(parseTrustProxy(undefined)).toBe(false);
    expect(parseTrustProxy("false")).toBe(false);
    expect(parseTrustProxy("")).toBe(false);
  });

  it("inteiro => numero de hops confiaveis", () => {
    expect(parseTrustProxy("1")).toBe(1);
    expect(parseTrustProxy("2")).toBe(2);
    expect(parseTrustProxy("0")).toBe(0);
  });

  it("true => confia em qualquer proxy", () => {
    expect(parseTrustProxy("true")).toBe(true);
  });

  it("valor nao-numerico => repassado (lista de IP/CIDR ao Fastify)", () => {
    expect(parseTrustProxy("10.0.0.0/8")).toBe("10.0.0.0/8");
  });
});
