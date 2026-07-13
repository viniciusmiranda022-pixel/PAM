import { describe, expect, it } from "vitest";
import { getAdapter, supportedProtocols } from "../src/adapters/index.ts";
import { vncAdapter } from "../src/adapters/vnc/index.ts";

describe("registry de adapters (PR-16)", () => {
  it("resolve o protocolo vnc", () => {
    expect(getAdapter("vnc")).toBe(vncAdapter);
    expect(vncAdapter.protocol).toBe("vnc");
  });

  it("recusa protocolo sem adapter (null, nunca fallback)", () => {
    expect(getAdapter("rdp")).toBeNull();
    expect(getAdapter("ssh")).toBeNull();
    expect(getAdapter("")).toBeNull();
  });

  it("lista apenas os protocolos com adapter oficial", () => {
    expect(supportedProtocols()).toEqual(["vnc"]);
  });

  it("o adapter VNC declara suas portas padrão (allowlist por protocolo)", () => {
    expect([...vncAdapter.defaultPorts]).toEqual([5900, 5901, 5902]);
  });
});
