import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Cofre interino (Fases 2). A senha VNC e cifrada com AES-256-GCM e guardada
 * apenas como texto cifrado em `credential_ref` (`enc:v1:<nonce>:<ct+tag>`).
 * O texto claro nunca vai ao banco; a master key vive so em variavel de
 * ambiente (nunca no banco/log/commit) — docs/security-requirements.md secao 4.
 * Na Fase 3 este provider e substituido pelo HashiCorp Vault.
 */
export function masterKey(env = process.env): Buffer {
  const b64 = env.CREDENTIAL_MASTER_KEY;
  if (!b64) throw new Error("CREDENTIAL_MASTER_KEY nao definido");
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) {
    throw new Error("CREDENTIAL_MASTER_KEY deve ter 32 bytes (base64)");
  }
  return key;
}

export function encryptCredential(plaintext: string, env = process.env): string {
  const key = masterKey(env);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const blob = Buffer.concat([ct, cipher.getAuthTag()]);
  return `enc:v1:${nonce.toString("base64url")}:${blob.toString("base64url")}`;
}

/** Inverso de encryptCredential — usado p/ segredos internos (ex.: MFA). */
export function decryptCredential(ref: string, env = process.env): string {
  const parts = ref.split(":");
  if (parts.length !== 4 || parts[0] !== "enc" || parts[1] !== "v1") {
    throw new Error("ref cifrada malformada");
  }
  const nonce = Buffer.from(parts[2], "base64url");
  const blob = Buffer.from(parts[3], "base64url");
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(0, blob.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", masterKey(env), nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}
