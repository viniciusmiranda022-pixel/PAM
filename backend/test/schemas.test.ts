import { describe, expect, it } from "vitest";
import { createSessionSchema } from "../src/schemas.ts";

describe("createSessionSchema (HR-01/02: somente assetId)", () => {
  const assetId = "11111111-1111-4111-8111-111111111111";

  it("aceita apenas assetId", () => {
    const r = createSessionSchema.safeParse({ assetId });
    expect(r.success).toBe(true);
  });

  it("rejeita host", () => {
    const r = createSessionSchema.safeParse({ assetId, host: "10.0.0.1" });
    expect(r.success).toBe(false);
  });

  it("rejeita port", () => {
    const r = createSessionSchema.safeParse({ assetId, port: 5900 });
    expect(r.success).toBe(false);
  });

  it("rejeita hostname/ip arbitrarios", () => {
    expect(createSessionSchema.safeParse({ assetId, hostname: "x" }).success).toBe(false);
    expect(createSessionSchema.safeParse({ assetId, ip: "1.2.3.4" }).success).toBe(false);
  });

  it("rejeita assetId que nao e uuid", () => {
    expect(createSessionSchema.safeParse({ assetId: "not-a-uuid" }).success).toBe(false);
  });

  it("rejeita corpo sem assetId", () => {
    expect(createSessionSchema.safeParse({}).success).toBe(false);
  });
});
