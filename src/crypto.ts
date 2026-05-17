// Crypto helpers using Node.js builtin crypto (ed25519, sha256)
// JWS format: compact serialization (header.payload.signature)

import {
  createHash,
  generateKeyPairSync,
  KeyObject,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  thumbprint: string; // sha256 of SPKI, hex
}

const b64url = {
  encode(buf: Buffer): string {
    return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  },
  decode(s: string): Buffer {
    let pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  },
};

export function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function sha256Prefixed(data: Buffer | string): string {
  return "sha256:" + sha256(data);
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const thumbprint = sha256(spki);
  return { publicKey, privateKey, thumbprint };
}

export function signJWS(payload: object, privateKey: KeyObject): string {
  const header = { alg: "EdDSA", typ: "JWS" };
  const headerB64 = b64url.encode(Buffer.from(JSON.stringify(header)));
  const payloadB64 = b64url.encode(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = nodeSign(null, signingInput, privateKey);
  const signatureB64 = b64url.encode(signature);
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

export function verifyJWS<T = unknown>(jws: string, publicKey: KeyObject): T | null {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = b64url.decode(signatureB64);
  const valid = nodeVerify(null, signingInput, publicKey, signature);
  if (!valid) return null;
  try {
    return JSON.parse(b64url.decode(payloadB64).toString("utf-8")) as T;
  } catch {
    return null;
  }
}

export function nonce(): string {
  return b64url.encode(Buffer.from(Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))));
}

export function nowISO(): string {
  return new Date().toISOString();
}
