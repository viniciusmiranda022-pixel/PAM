import { describe, expect, it } from "vitest";
import { portRejectionReason } from "../src/ports.ts";

describe("portRejectionReason (denylist imutavel HR-04)", () => {
  it("aceita portas VNC tipicas", () => {
    for (const p of [5900, 5901, 5902, 5905, 6000]) {
      expect(portRejectionReason(p)).toBeNull();
    }
  });

  it("rejeita portas de outros protocolos", () => {
    for (const p of [22, 23, 80, 443, 445, 3389, 1433, 3306, 5432, 5985, 6379, 8080, 27017]) {
      expect(portRejectionReason(p)).not.toBeNull();
    }
  });

  it("rejeita fora da faixa 1024-65535", () => {
    expect(portRejectionReason(0)).not.toBeNull();
    expect(portRejectionReason(80)).not.toBeNull();
    expect(portRejectionReason(70000)).not.toBeNull();
    expect(portRejectionReason(5900.5)).not.toBeNull();
  });
});
