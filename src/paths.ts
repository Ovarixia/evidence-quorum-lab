import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Repo root whether we run from src/ (tsx) or dist/. */
export const repoRoot = path.resolve(here, "..");

export const fixturesDir = path.join(repoRoot, "fixtures");
export const tenantsDir = path.join(fixturesDir, "tenants");
export const demoKeyPath = path.join(fixturesDir, "keys", "demo-ed25519.json");
export const demoPublicPemPath = path.join(
  fixturesDir,
  "keys",
  "demo-ed25519.pub.pem",
);

export function defaultReceiptDir(): string {
  return path.join(repoRoot, "receipts");
}

export function readUtf8(filePath: string): string {
  return fs.readFileSync(filePath, "utf8");
}
