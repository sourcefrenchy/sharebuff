// One Durable Object per secret id. DOs serialize execution per object, so
// the claim state machine is atomic: exactly one valid claim can ever win.
// The interface is fetch()-based (not RPC): ciphertexts run to ~27 MB base64
// and RPC messages cap at 1 MiB. SQLite-backed DO storage caps values at
// 2 MB, so the base64 ciphertext is split across `ct:<n>` keys.
// Conforms to docs/SPEC.md.
import { DurableObject } from 'cloudflare:workers';

const MAX_ATTEMPTS = 10;
const COOLDOWN_MAX_S = 300;
const CHUNK = 1_500_000; // base64 chars per storage key (< 2 MB value limit)

// Cooldown after the n-th counted wrong attempt: min(2^n, 300) seconds.
const cooldownMs = (attempts: number) =>
  Math.min(2 ** attempts, COOLDOWN_MAX_S) * 1000;

interface Rec {
  verifier?: string;  // lowercase hex sha256(K_auth)
  chunks?: number;    // number of ct:<n> keys
  attempts?: number;
  nextAllowedAt?: number; // ms epoch
  gone?: 'claimed' | 'burned';
  expiresAt: number;  // ms epoch
}

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

function json(code: number, body: Record<string, unknown>, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status: code,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

export class Secret extends DurableObject {
  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === '/create') return this.create(request);
    if (path === '/claim') return this.claim(request);
    return json(404, { error: 'not found' });
  }

  private async create(request: Request): Promise<Response> {
    const { ct, verifier, ttl } = await request.json<{ ct: string; verifier: string; ttl: number }>();
    const existing = await this.ctx.storage.get<Rec>('rec');
    if (existing) return json(409, { error: 'id already exists' });
    const expiresAt = Date.now() + ttl * 1000;
    const chunks = Math.ceil(ct.length / CHUNK);
    const entries: Record<string, unknown> = {
      rec: { verifier, chunks, attempts: 0, expiresAt } satisfies Rec,
    };
    for (let i = 0; i < chunks; i++) entries[`ct:${i}`] = ct.slice(i * CHUNK, (i + 1) * CHUNK);
    await this.ctx.storage.put(entries);
    await this.ctx.storage.setAlarm(expiresAt);
    return json(201, { expires_at: Math.floor(expiresAt / 1000) });
  }

  private async claim(request: Request): Promise<Response> {
    const { auth } = await request.json<{ auth: string }>();
    const rec = await this.ctx.storage.get<Rec>('rec');
    if (!rec) return json(404, { error: 'not found' });
    if (rec.expiresAt <= Date.now()) {
      await this.ctx.storage.deleteAll();
      return json(404, { error: 'not found' });
    }
    if (rec.gone) return json(410, { reason: rec.gone });

    // Cooldown gate: rejected before the proof is examined and NOT counted —
    // hammering can neither brute-force the PIN nor burn the secret.
    if (rec.nextAllowedAt && Date.now() < rec.nextAllowedAt) {
      const retry = Math.ceil((rec.nextAllowedAt - Date.now()) / 1000);
      return json(429, { retry_after_seconds: retry }, { 'retry-after': String(retry) });
    }

    const sum = hex(await crypto.subtle.digest('SHA-256', hexToBytes(auth)));
    if (!constantTimeEqualHex(sum, rec.verifier!)) {
      rec.attempts = (rec.attempts ?? 0) + 1;
      rec.nextAllowedAt = Date.now() + cooldownMs(rec.attempts);
      if (rec.attempts >= MAX_ATTEMPTS) {
        // Burn: keep only a tombstone until the original expiry.
        await this.ctx.storage.deleteAll();
        await this.ctx.storage.put<Rec>('rec', { gone: 'burned', expiresAt: rec.expiresAt });
        await this.ctx.storage.setAlarm(rec.expiresAt);
        return json(410, { reason: 'burned' });
      }
      await this.ctx.storage.put<Rec>('rec', rec);
      return json(403, { attempts_left: MAX_ATTEMPTS - rec.attempts });
    }

    // Valid claim: reassemble, then destroy the ciphertext before responding.
    const keys = Array.from({ length: rec.chunks ?? 0 }, (_, i) => `ct:${i}`);
    const stored = await this.ctx.storage.get<string>(keys);
    const ct = keys.map((k) => stored.get(k) ?? '').join('');
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.put<Rec>('rec', { gone: 'claimed', expiresAt: rec.expiresAt });
    await this.ctx.storage.setAlarm(rec.expiresAt);
    return json(200, { ct });
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

// ---------------------------------------------------------------------------
// Exact per-IP rate limiting. One object per client IP (idFromName(ip)) keeps
// fixed windows in memory — no storage writes, and an evicted object simply
// starts a fresh window. Cloudflare's Rate Limiting binding is eventually
// consistent (per-machine caches), so it stays as a coarse outer layer while
// this object is the authoritative count. Checked before any Secret object is
// touched, so random-locator spam costs one object per attacker IP, not one
// per guessed locator.
export class IPLimiter extends DurableObject {
  private windows = new Map<string, { start: number; count: number }>();

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const bucket = url.searchParams.get('bucket') ?? 'default';
    const max = Number(url.searchParams.get('max') ?? '60');
    const period = Number(url.searchParams.get('period') ?? '60') * 1000;
    const now = Date.now();
    // Opportunistic cleanup keeps the map bounded.
    if (this.windows.size > 64) {
      for (const [k, w] of this.windows) if (now - w.start >= period) this.windows.delete(k);
    }
    const w = this.windows.get(bucket);
    if (!w || now - w.start >= period) {
      this.windows.set(bucket, { start: now, count: 1 });
      return json(200, { allowed: true });
    }
    if (w.count >= max) {
      return json(200, { allowed: false, retry_after_seconds: Math.ceil((w.start + period - now) / 1000) });
    }
    w.count++;
    return json(200, { allowed: true });
  }
}
