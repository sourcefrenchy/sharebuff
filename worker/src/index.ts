// Sharebuff Worker: routes the JSON API to per-secret Durable Objects and
// everything else to the static assets binding (../web). See docs/SPEC.md.
import { Secret } from './secret';
export { Secret };

interface Env {
  ASSETS: Fetcher;
  SECRET: DurableObjectNamespace<Secret>;
}

const ID_RE = /^[1-9A-HJ-NP-Za-km-z]{16,32}$/;
const HEX_RE = /^[0-9a-f]{64}$/;
const MAX_CT_B64 = Math.ceil((65536 + 28) / 3) * 4 + 8;
const DEFAULT_TTL = 604800;
const MIN_TTL = 60;
const MAX_TTL = 604800;

function json(code: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: code,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

const err = (code: number, error: string) => json(code, { error });

async function readJSON(request: Request, maxBytes: number): Promise<Record<string, unknown> | null> {
  const len = Number(request.headers.get('content-length') ?? '0');
  if (len > maxBytes) return null;
  try {
    const text = await request.text();
    if (text.length > maxBytes) return null;
    const v = JSON.parse(text);
    return typeof v === 'object' && v !== null ? v : null;
  } catch {
    return null;
  }
}

function validB64(s: string): boolean {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0;
}

async function handleCreate(request: Request, env: Env): Promise<Response> {
  const body = await readJSON(request, 128 * 1024);
  if (!body) return err(400, 'malformed body');
  const { id, ct, verifier } = body as { id?: string; ct?: string; verifier?: string };
  let ttl = (body.ttl_seconds as number | undefined) ?? 0;
  if (ttl === 0) ttl = DEFAULT_TTL;
  if (typeof id !== 'string' || !ID_RE.test(id)) return err(400, 'malformed id');
  if (typeof verifier !== 'string' || !HEX_RE.test(verifier)) return err(400, 'malformed verifier');
  if (typeof ct !== 'string' || !validB64(ct) || ct.length < 40) return err(400, 'malformed ciphertext');
  if (ct.length > MAX_CT_B64) return err(413, 'ciphertext too large');
  if (!Number.isInteger(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) return err(400, 'ttl out of range');

  const stub = env.SECRET.get(env.SECRET.idFromName(id));
  const res = await stub.create(ct, verifier, ttl);
  if (res.code === 409) return err(409, 'id already exists');
  return json(201, { expires_at: Math.floor(res.expiresAt / 1000) });
}

async function handleClaim(request: Request, env: Env, id: string): Promise<Response> {
  if (!ID_RE.test(id)) return err(400, 'malformed id');
  const body = await readJSON(request, 4096);
  const auth = body?.auth;
  if (typeof auth !== 'string' || !HEX_RE.test(auth)) return err(400, 'malformed auth');

  const stub = env.SECRET.get(env.SECRET.idFromName(id));
  const res = await stub.claim(auth);
  switch (res.code) {
    case 200: return json(200, { ct: res.ct });
    case 403: return json(403, { attempts_left: res.attemptsLeft });
    case 410: return json(410, { reason: res.reason });
    default: return err(404, 'not found');
  }
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    const claimMatch = /^\/api\/secrets\/([^/]+)\/claim$/.exec(url.pathname);
    if (url.pathname === '/api/secrets' && request.method === 'POST') {
      return handleCreate(request, env);
    }
    if (claimMatch && request.method === 'POST') {
      return handleClaim(request, env, claimMatch[1]);
    }
    if (url.pathname.startsWith('/api/')) {
      return err(404, 'not found');
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
