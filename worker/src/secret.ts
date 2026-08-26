// One Durable Object per secret id. DOs serialize execution per object, so
// the claim state machine is atomic: exactly one valid claim can ever win.
// Conforms to docs/SPEC.md.
import { DurableObject } from 'cloudflare:workers';

const MAX_ATTEMPTS = 5;

interface Rec {
  ct?: string;        // base64 blob (absent on tombstones)
  verifier?: string;  // lowercase hex sha256(K_auth)
  attempts?: number;
  gone?: 'claimed' | 'burned';
  expiresAt: number;  // ms epoch
}

export type CreateResult = { code: 201; expiresAt: number } | { code: 409 };
export type ClaimResult =
  | { code: 200; ct: string }
  | { code: 403; attemptsLeft: number }
  | { code: 410; reason: 'claimed' | 'burned' }
  | { code: 404 };

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export class Secret extends DurableObject {
  async create(ct: string, verifier: string, ttlSeconds: number): Promise<CreateResult> {
    const existing = await this.ctx.storage.get<Rec>('rec');
    if (existing) return { code: 409 };
    const expiresAt = Date.now() + ttlSeconds * 1000;
    await this.ctx.storage.put<Rec>('rec', { ct, verifier, attempts: 0, expiresAt });
    await this.ctx.storage.setAlarm(expiresAt);
    return { code: 201, expiresAt };
  }

  async claim(auth: string): Promise<ClaimResult> {
    const rec = await this.ctx.storage.get<Rec>('rec');
    if (!rec) return { code: 404 };
    if (rec.expiresAt <= Date.now()) {
      await this.ctx.storage.deleteAll();
      return { code: 404 };
    }
    if (rec.gone) return { code: 410, reason: rec.gone };

    const sum = hex(await crypto.subtle.digest('SHA-256', hexToBytes(auth)));
    if (!constantTimeEqualHex(sum, rec.verifier!)) {
      rec.attempts = (rec.attempts ?? 0) + 1;
      if (rec.attempts >= MAX_ATTEMPTS) {
        // Burn: keep only a tombstone until the original expiry.
        await this.ctx.storage.put<Rec>('rec', { gone: 'burned', expiresAt: rec.expiresAt });
        return { code: 410, reason: 'burned' };
      }
      await this.ctx.storage.put<Rec>('rec', rec);
      return { code: 403, attemptsLeft: MAX_ATTEMPTS - rec.attempts };
    }

    // Valid claim: destroy the ciphertext before responding.
    await this.ctx.storage.put<Rec>('rec', { gone: 'claimed', expiresAt: rec.expiresAt });
    return { code: 200, ct: rec.ct! };
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
