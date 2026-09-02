import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalize } from "./canon.js";

export interface LabKey {
  keyId: string;
  warning: string;
  alg: "Ed25519";
  publicKeyPem: string;
  privateKeyPem: string;
}

export function loadLabKey(jsonPath: string): LabKey {
  const parsed = JSON.parse(fs.readFileSync(jsonPath, "utf8")) as LabKey;
  if (parsed.alg !== "Ed25519") {
    throw new Error(`unsupported lab key alg: ${parsed.alg}`);
  }
  return parsed;
}

export function publicKeyPemFromFile(pemPath: string): string {
  return fs.readFileSync(pemPath, "utf8");
}

export function signCanonical(payload: unknown, key: LabKey): string {
  const message = Buffer.from(canonicalize(payload), "utf8");
  const signature = crypto.sign(null, message, key.privateKeyPem);
  return signature.toString("base64");
}

export function verifyCanonical(
  payload: unknown,
  publicKeyPem: string,
  signatureB64: string,
): boolean {
  const message = Buffer.from(canonicalize(payload), "utf8");
  const signature = Buffer.from(signatureB64, "base64");
  try {
    return crypto.verify(null, message, publicKeyPem, signature);
  } catch {
    return false;
  }
}

export function sha256Canonical(payload: unknown): string {
  return crypto
    .createHash("sha256")
    .update(canonicalize(payload), "utf8")
    .digest("hex");
}

/** Deterministic lab nonce / derived bytes. Not a KDF for production secrets. */
export function hmacHex(seed: string, label: string, bytes = 16): string {
  return crypto
    .createHmac("sha256", seed)
    .update(label)
    .digest("hex")
    .slice(0, bytes * 2);
}

export function pemFingerprints(publicKeyPem: string): string {
  const der = crypto.createPublicKey(publicKeyPem).export({
    type: "spki",
    format: "der",
  });
  return crypto.createHash("sha256").update(der).digest("hex");
}
