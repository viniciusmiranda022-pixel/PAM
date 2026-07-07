import { describe, expect, it } from "vitest";
import { RateLimiter } from "../src/rate-limit.ts";

describe("RateLimiter (janela deslizante)", () => {
  it("libera ate o limite e bloqueia o excedente", () => {
    const rl = new RateLimiter(3, 60_000);
    const t = 1_000_000;
    expect(rl.check("ip", t)).toBe(true);
    expect(rl.check("ip", t + 1)).toBe(true);
    expect(rl.check("ip", t + 2)).toBe(true);
    expect(rl.check("ip", t + 3)).toBe(false); // 4a tentativa na janela
  });

  it("libera novamente apos a janela expirar", () => {
    const rl = new RateLimiter(2, 60_000);
    const t = 1_000_000;
    rl.check("ip", t);
    rl.check("ip", t + 1);
    expect(rl.check("ip", t + 2)).toBe(false);
    expect(rl.check("ip", t + 60_001)).toBe(true); // fora da janela
  });

  it("isola chaves diferentes", () => {
    const rl = new RateLimiter(1, 60_000);
    expect(rl.check("a")).toBe(true);
    expect(rl.check("b")).toBe(true);
    expect(rl.check("a")).toBe(false);
  });

  it("prune remove chaves expiradas", () => {
    const rl = new RateLimiter(1, 1_000);
    rl.check("a", 0);
    rl.prune(2_000);
    expect(rl.check("a", 2_001)).toBe(true);
  });
});
