import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SessionRecorder, parseRecording, RECORDING_MAGIC } from "../src/recorder.ts";

function tmpFile(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pamrec-")), "s.pamrec");
}

describe("SessionRecorder + parseRecording (round-trip)", () => {
  it("grava header com ServerInit e frames na ordem", async () => {
    const file = tmpFile();
    const serverInit = Buffer.from("SERVERINIT-BYTES");
    const rec = new SessionRecorder(file, serverInit);
    rec.write(Buffer.from("frame-um"));
    rec.write(Buffer.from("frame-dois"));
    rec.close();
    await new Promise((r) => setTimeout(r, 50)); // flush do stream

    const parsed = parseRecording(fs.readFileSync(file));
    expect(parsed.serverInit.equals(serverInit)).toBe(true);
    expect(parsed.frames.length).toBe(2);
    expect(parsed.frames[0].data.toString()).toBe("frame-um");
    expect(parsed.frames[1].data.toString()).toBe("frame-dois");
    expect(parsed.frames[0].direction).toBe(0);
    expect(parsed.frames[1].deltaMs).toBeGreaterThanOrEqual(parsed.frames[0].deltaMs);
  });

  it("ignora writes apos close e frames vazios", async () => {
    const file = tmpFile();
    const rec = new SessionRecorder(file, Buffer.alloc(4));
    rec.write(Buffer.alloc(0));
    rec.close();
    rec.write(Buffer.from("depois-do-close"));
    await new Promise((r) => setTimeout(r, 50));
    expect(parseRecording(fs.readFileSync(file)).frames.length).toBe(0);
  });

  it("tolera arquivo truncado (sessao interrompida)", async () => {
    const file = tmpFile();
    const rec = new SessionRecorder(file, Buffer.from("SI"));
    rec.write(Buffer.from("frame-completo"));
    rec.close();
    await new Promise((r) => setTimeout(r, 50));
    const whole = fs.readFileSync(file);
    const truncated = whole.subarray(0, whole.length - 5); // corta o ultimo frame
    const parsed = parseRecording(truncated);
    expect(parsed.frames.length).toBe(0); // frame truncado descartado, sem throw
  });

  it("rejeita arquivo sem magic", () => {
    expect(() => parseRecording(Buffer.from("NAO-E-GRAVACAO"))).toThrow();
    expect(RECORDING_MAGIC).toBe("PAMREC01");
  });
});
