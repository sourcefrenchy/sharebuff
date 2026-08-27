// Sharebuff Worker: routes the JSON API to per-secret Durable Objects and
// everything else to the static assets binding (../web). See docs/SPEC.md.
// DO calls go over fetch() bodies, not RPC — ciphertexts can reach ~27 MB
// base64, far past the 1 MiB RPC message cap.
import { Secret } from './secret';
export { Secret };

interface RateLimiter { limit(opts: { key: string }): Promise<{ success: boolean }> }

interface Env {
  ASSETS: Fetcher;
  SECRET: DurableObjectNamespace;
  CREATE_LIMIT: RateLimiter; // per-IP creates per minute (wrangler.jsonc)
  CLAIM_LIMIT: RateLimiter;  // per-IP claims per minute
  // "enforce" (default): creation is refused on corporate signals; "advise": only reported via /api/env.
  SHARE_POLICY?: string;
  // Optional secret: POST JSON alert events here (ntfy, Slack, Discord…). Never payloads or IPs.
  ALERT_WEBHOOK?: string;
}

// alert writes a structured event to Workers Logs and, if configured, to the
// webhook. Fields are deliberately coarse: reasons, ASN org, country, locator.
function alert(env: Env, ctx: ExecutionContext, event: string, fields: Record<string, unknown>): void {
  const body = JSON.stringify({ event, ts: new Date().toISOString(), ...fields });
  console.warn(body);
  if (env.ALERT_WEBHOOK) {
    ctx.waitUntil(fetch(env.ALERT_WEBHOOK, { method: 'POST', headers: { 'content-type': 'application/json' }, body }).catch(() => {}));
  }
}

const clientIP = (request: Request) => request.headers.get('cf-connecting-ip') ?? 'unknown';

async function rateLimited(limiter: RateLimiter | undefined, request: Request): Promise<boolean> {
  if (!limiter) return false; // binding absent (e.g. local dev without support) → open
  try {
    const { success } = await limiter.limit({ key: clientIP(request) });
    return !success;
  } catch {
    return false;
  }
}

const tooMany = () => json(429, { error: 'too many requests', retry_after_seconds: 60 }, );

const ID_RE = /^[0-9A-HJKMNP-TV-Z]{5}$/; // a v4 locator
const HEX_RE = /^[0-9a-f]{64}$/;
const MAX_BLOB = 4 + 4096 + 20 * 1024 * 1024 + 12 + 16; // envelope + nonce + tag
const MAX_CT_B64 = Math.ceil(MAX_BLOB / 3) * 4 + 8;
const MAX_BODY = 32 * 1024 * 1024;
const DEFAULT_TTL = 604800;

// Corporate-environment signals (best effort; see docs/SECURITY.md). Any hit
// makes the page hide the Share tab so company data isn't posted by accident.
const SWG_VENDORS = ['ZSCALER', 'NETSKOPE', 'PALO ALTO', 'PRISMA', 'FORCEPOINT', 'IBOSS', 'MENLO',
  'SYMANTEC', 'BROADCOM', 'UMBRELLA', 'CATO NETWORKS', 'CHECK POINT', 'FORTINET', 'SKYHIGH', 'MCAFEE'];
const PROXY_HEADERS = ['via', 'x-bluecoat-via', 'x-zscaler-ip', 'x-zscaler-user', 'x-netskope-user', 'proxy-authorization'];

// A current browser reaches Cloudflare over HTTP/2 or HTTP/3; TLS-intercepting
// proxies usually re-originate as HTTP/1.1. A modern browser UA arriving over
// HTTP/1.1 is therefore a strong middlebox tell.
function modernBrowser(ua: string): boolean {
  const m = /(?:Chrome|CriOS|Chromium)\/(\d+)/.exec(ua);
  if (m) return Number(m[1]) >= 90;
  const f = /Firefox\/(\d+)/.exec(ua);
  if (f) return Number(f[1]) >= 90;
  const s = /Version\/(\d+)[\d.]* .*Safari\//.exec(ua);
  if (s) return Number(s[1]) >= 14;
  return false;
}

function environment(request: Request): { share: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const cf = request.cf as { asOrganization?: string; httpProtocol?: string } | undefined;
  const proto = cf?.httpProtocol ?? '';
  if (/^HTTP\/1\./.test(proto) && modernBrowser(request.headers.get('user-agent') ?? '')) {
    reasons.push(`modern browser arriving over ${proto} (TLS-intercepting proxy suspected)`);
  }
  const policy = (request.headers.get('x-sharebuff-policy') ?? '').toLowerCase();
  if (policy.includes('retrieve-only') || policy.includes('no-share')) reasons.push('organization policy header');
  for (const h of PROXY_HEADERS) if (request.headers.has(h)) reasons.push(`proxy header ${h}`);
  const xff = request.headers.get('x-forwarded-for') ?? '';
  if (xff.split(',').filter(Boolean).length > 1) reasons.push('forwarded through a proxy');
  const org = (cf?.asOrganization ?? '').toUpperCase();
  for (const v of SWG_VENDORS) if (org.includes(v)) { reasons.push(`secure web gateway (${org})`); break; }
  return { share: reasons.length === 0, reasons };
}
const MIN_TTL = 60;
const MAX_TTL = 604800;

function json(code: number, body: unknown): Response {
  const headers: Record<string, string> = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (code === 429) headers['retry-after'] = '60';
  return new Response(JSON.stringify(body), { status: code, headers });
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

function stubFor(env: Env, id: string): DurableObjectStub {
  return env.SECRET.get(env.SECRET.idFromName(id));
}

function withNoStore(resp: Response): Response {
  const out = new Response(resp.body, resp);
  out.headers.set('cache-control', 'no-store');
  return out;
}

async function handleCreate(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  // Server-side enforcement: a patched page or curl gets the same answer.
  if ((env.SHARE_POLICY ?? 'enforce') !== 'advise') {
    const e = environment(request);
    if (!e.share) {
      const cf = request.cf as { asOrganization?: string; country?: string } | undefined;
      alert(env, ctx, 'create_refused', { reasons: e.reasons, asn_org: cf?.asOrganization, country: cf?.country });
      return json(403, { error: 'sharing is disabled on this network', reasons: e.reasons });
    }
  }
  if (await rateLimited(env.CREATE_LIMIT, request)) {
    alert(env, ctx, 'rate_limited', { bucket: 'create' });
    return tooMany();
  }
  const body = await readJSON(request, MAX_BODY);
  if (!body) return err(400, 'malformed body');
  const { id, ct, verifier } = body as { id?: string; ct?: string; verifier?: string };
  let ttl = (body.ttl_seconds as number | undefined) ?? 0;
  if (ttl === 0) ttl = DEFAULT_TTL;
  if (typeof id !== 'string' || !ID_RE.test(id)) return err(400, 'malformed id');
  if (typeof verifier !== 'string' || !HEX_RE.test(verifier)) return err(400, 'malformed verifier');
  if (typeof ct !== 'string' || !validB64(ct) || ct.length < 40) return err(400, 'malformed ciphertext');
  if (ct.length > MAX_CT_B64) return err(413, 'ciphertext too large');
  if (!Number.isInteger(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) return err(400, 'ttl out of range');

  const resp = await stubFor(env, id).fetch('https://do/create', {
    method: 'POST',
    body: JSON.stringify({ ct, verifier, ttl }),
  });
  return withNoStore(resp);
}

async function handleClaim(request: Request, env: Env, ctx: ExecutionContext, id: string): Promise<Response> {
  if (!ID_RE.test(id)) return err(400, 'malformed id');
  // Rate-limit before touching a Durable Object: random-locator spam must not
  // instantiate objects (cost amplification) or burn secrets by volume.
  if (await rateLimited(env.CLAIM_LIMIT, request)) {
    alert(env, ctx, 'rate_limited', { bucket: 'claim' });
    return tooMany();
  }
  const body = await readJSON(request, 4096);
  const auth = body?.auth;
  if (typeof auth !== 'string' || !HEX_RE.test(auth)) return err(400, 'malformed auth');

  const resp = await stubFor(env, id).fetch('https://do/claim', {
    method: 'POST',
    body: JSON.stringify({ auth }),
  });
  if (resp.status === 410) {
    const peek = (await resp.clone().json().catch(() => ({}))) as { reason?: string };
    if (peek.reason === 'burned') alert(env, ctx, 'secret_burned', { locator: id });
  }
  return withNoStore(resp);
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    const claimMatch = /^\/api\/secrets\/([^/]+)\/claim$/.exec(url.pathname);
    if (url.pathname === '/api/secrets' && request.method === 'POST') {
      return handleCreate(request, env, ctx);
    }
    if (claimMatch && request.method === 'POST') {
      return handleClaim(request, env, ctx, claimMatch[1]);
    }
    if (url.pathname === '/api/env' && request.method === 'GET') {
      return json(200, environment(request));
    }
    if (url.pathname.startsWith('/api/')) {
      return err(404, 'not found');
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
