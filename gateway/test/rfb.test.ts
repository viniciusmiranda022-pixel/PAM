import { describe, expect, it } from "vitest";
import {
  formatProtocolVersion,
  mirrorBits,
  negotiatedVersion,
  parseProtocolVersion,
  RfbError,
  vncDesKey,
  vncEncryptChallenge,
} from "../src/adapters/vnc/rfb.ts";
import { assetHandshake, browserHandshake } from "../src/adapters/vnc/handshake.ts";
import type { ByteStreamReader } from "../src/byte-stream-types.ts";

/** Reader roteirizado por um buffer fixo; captura tambem o residual. */
class FakeReader implements ByteStreamReader {
  private pos = 0;
  constructor(private data: Buffer) {}
  async read(n: number): Promise<Buffer> {
    const out = this.data.subarray(this.pos, this.pos + n);
    if (out.length < n) throw new Error("eof no fake reader");
    this.pos += n;
    return Buffer.from(out);
  }
  detach(): Buffer {
    return this.data.subarray(this.pos);
  }
}

describe("mirrorBits", () => {
  it("inverte a ordem dos bits", () => {
    expect(mirrorBits(0x01)).toBe(0x80);
    expect(mirrorBits(0x02)).toBe(0x40);
    expect(mirrorBits(0x0f)).toBe(0xf0);
    expect(mirrorBits(0xff)).toBe(0xff);
    expect(mirrorBits(0xa5)).toBe(0xa5); // palindromo binario
  });
});

describe("vncDesKey", () => {
  it("trunca em 8 bytes e espelha os bits", () => {
    const key = vncDesKey("labonly1");
    expect(key.length).toBe(8);
    expect(key[0]).toBe(mirrorBits("l".charCodeAt(0)));
  });
  it("senha vazia => chave toda zero", () => {
    expect(vncDesKey("").equals(Buffer.alloc(8, 0))).toBe(true);
  });
});

describe("vncEncryptChallenge", () => {
  // Vetor conhecido, nao-circular: senha vazia => chave DES toda zero; cada
  // bloco de 8 bytes do challenge zero => DES(0,0) = 8CA64DE9C1B123A7 (KAT
  // canonico do DES). Amarra o vetor canonico ao wrapper do VNC.
  it("bate com o KAT canonico do DES para senha vazia e challenge zero", () => {
    const out = vncEncryptChallenge("", Buffer.alloc(16, 0));
    const block = Buffer.from("8CA64DE9C1B123A7", "hex");
    expect(out.equals(Buffer.concat([block, block]))).toBe(true);
  });
  it("e deterministico e sensivel a senha", () => {
    const ch = Buffer.alloc(16, 0x42);
    expect(vncEncryptChallenge("senha1", ch).equals(vncEncryptChallenge("senha1", ch))).toBe(true);
    expect(vncEncryptChallenge("senha1", ch).equals(vncEncryptChallenge("senha2", ch))).toBe(false);
  });
  it("rejeita challenge com tamanho != 16", () => {
    expect(() => vncEncryptChallenge("x", Buffer.alloc(8))).toThrow(RfbError);
  });
});

describe("parseProtocolVersion", () => {
  it("aceita banner RFB valido", () => {
    expect(parseProtocolVersion(Buffer.from("RFB 003.008\n"))).toEqual({ major: 3, minor: 8 });
  });
  it("recusa banner nao-RFB (defesa HR-08)", () => {
    expect(() => parseProtocolVersion(Buffer.from("HTTP/1.1 200 \n"))).toThrow(RfbError);
    expect(() => parseProtocolVersion(Buffer.from("SSH-2.0-Open"))).toThrow(RfbError);
  });
  it("round-trip com formatProtocolVersion", () => {
    const b = formatProtocolVersion({ major: 3, minor: 8 });
    expect(b.toString("ascii")).toBe("RFB 003.008\n");
    expect(parseProtocolVersion(b)).toEqual({ major: 3, minor: 8 });
  });
});

describe("negotiatedVersion", () => {
  it("limita a 3.8 e preserva versoes menores", () => {
    expect(negotiatedVersion({ major: 3, minor: 8 })).toEqual({ major: 3, minor: 8 });
    expect(negotiatedVersion({ major: 3, minor: 889 })).toEqual({ major: 3, minor: 8 });
    expect(negotiatedVersion({ major: 3, minor: 3 })).toEqual({ major: 3, minor: 3 });
  });
  it("rejeita major diferente de 3", () => {
    expect(() => negotiatedVersion({ major: 4, minor: 0 })).toThrow(RfbError);
  });
});

describe("assetHandshake (gateway como cliente)", () => {
  it("negocia 3.8 + VNC Auth e retorna o ServerInit", async () => {
    const challenge = Buffer.alloc(16, 0x11);
    const serverInitHead = Buffer.alloc(24);
    serverInitHead.writeUInt32BE(4, 20); // name-length = 4
    const name = Buffer.from("labx");
    const script = Buffer.concat([
      Buffer.from("RFB 003.008\n"),
      Buffer.from([1, 2]), // 1 security type: VNC Auth
      challenge,
      Buffer.from([0, 0, 0, 0]), // SecurityResult OK
      serverInitHead,
      name,
    ]);
    const reader = new FakeReader(script);
    const sends: Buffer[] = [];
    const serverInit = await assetHandshake(reader, (b) => sends.push(Buffer.from(b)), "labonly1");

    expect(sends[0].toString("ascii")).toBe("RFB 003.008\n");
    expect(sends[1].equals(Buffer.from([2]))).toBe(true); // selecionou VNC Auth
    expect(sends[2].equals(vncEncryptChallenge("labonly1", challenge))).toBe(true);
    expect(sends[3].equals(Buffer.from([1]))).toBe(true); // ClientInit shared=1
    expect(serverInit.equals(Buffer.concat([serverInitHead, name]))).toBe(true);
  });

  it("recusa destino que nao fala RFB", async () => {
    const reader = new FakeReader(Buffer.from("HTTP/1.1 400 Ba"));
    await expect(assetHandshake(reader, () => {}, "x")).rejects.toThrow(RfbError);
  });

  it("propaga falha de autenticacao (SecurityResult != 0)", async () => {
    const script = Buffer.concat([
      Buffer.from("RFB 003.008\n"),
      Buffer.from([1, 2]),
      Buffer.alloc(16, 0),
      Buffer.from([0, 0, 0, 1]), // SecurityResult FAIL
      Buffer.from([0, 0, 0, 0]), // reason length 0
    ]);
    const reader = new FakeReader(script);
    await expect(assetHandshake(reader, () => {}, "x")).rejects.toThrow(/autentica/);
  });
});

describe("browserHandshake (gateway como servidor)", () => {
  it("forca 3.8 + None e repassa o ServerInit sem senha", async () => {
    const serverInit = Buffer.concat([Buffer.alloc(24), Buffer.from("x")]);
    // O byte de name-length precisa refletir 1 para o cliente, mas aqui apenas
    // repassamos o bloco ja pronto vindo do asset.
    const clientScript = Buffer.concat([
      Buffer.from("RFB 003.008\n"),
      Buffer.from([1]), // seleciona None
      Buffer.from([1]), // ClientInit shared
    ]);
    const reader = new FakeReader(clientScript);
    const sends: Buffer[] = [];
    await browserHandshake(reader, (b) => sends.push(Buffer.from(b)), serverInit);

    expect(sends[0].toString("ascii")).toBe("RFB 003.008\n");
    expect(sends[1].equals(Buffer.from([1, 1]))).toBe(true); // count=1, None
    expect(sends[2].equals(Buffer.from([0, 0, 0, 0]))).toBe(true); // SecurityResult OK
    expect(sends[3].equals(serverInit)).toBe(true);
  });

  it("rejeita cliente que nao escolhe None", async () => {
    const clientScript = Buffer.concat([Buffer.from("RFB 003.008\n"), Buffer.from([2])]);
    const reader = new FakeReader(clientScript);
    await expect(browserHandshake(reader, () => {}, Buffer.alloc(0))).rejects.toThrow(RfbError);
  });
});
