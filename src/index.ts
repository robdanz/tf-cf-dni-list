/**
 * Logpush endpoint: receives Zero Trust network sessions (CLIENT_TLS_ERROR)
 * and Gateway network logs (SessionID + SNI). Bidirectional correlation via KV:
 *
 * - POST /         — zero_trust_network_sessions
 *   If sni:{SessionID} exists (Gateway arrived first) → add SNI to list, delete sni key
 *   Otherwise → create pending:{SessionID}
 *
 * - POST /gateway  — gateway_network
 *   If pending:{SessionID} exists (Zero Trust arrived first) → add SNI to list, delete pending
 *   Otherwise → create sni:{SessionID} with the hostname
 *
 * Both key types expire after 5 minutes. Order of arrival doesn't matter.
 */

const CLIENT_TLS_ERROR = "CLIENT_TLS_ERROR";
// Pending keys expire quickly; zero_trust and gateway_network batches are close in time. Orphans clear without listing.
const PENDING_TTL_SECONDS = 300; // 5 minutes

// Zero Trust network session log (dataset: zero_trust_network_sessions)
interface ZeroTrustSessionLog {
  ConnectionCloseReason?: string;
  SessionID?: string;
}

// Gateway network log (dataset: gateway_network)
interface GatewayNetworkLog {
  SessionID?: string;
  SNI?: string;
}

interface Env {
  API_TOKEN: string;
  LIST_ID: string;
  ACCOUNT_ID: string;
  SESSION_CACHE: KVNamespace;
  LOGPUSH_SECRET: string;
}

/** Validate the X-Logpush-Secret header matches the configured secret. */
function validateSecret(request: Request, env: Env): Response | null {
  const secret = request.headers.get("X-Logpush-Secret");
  if (!secret || secret !== env.LOGPUSH_SECRET) {
    return new Response("Unauthorized", { status: 401 });
  }
  return null;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        "cf-dni-list Logpush endpoint\n  POST / = zero_trust_network_sessions\n  POST /gateway = gateway_network\n",
        { headers: { "Content-Type": "text/plain" } }
      );
    }

    if (url.pathname === "/" && request.method === "POST") {
      const authError = validateSecret(request, env);
      if (authError) return authError;
      try {
        return await handleZeroTrustSessions(request, env);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const stack = e instanceof Error ? e.stack : undefined;
        console.error("handleZeroTrustSessions threw", msg, stack);
        return new Response(
          JSON.stringify({ ok: false, error: msg }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    if (url.pathname === "/gateway" && request.method === "POST") {
      const authError = validateSecret(request, env);
      if (authError) return authError;

      try {
        return await handleGatewayNetwork(request, env);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const stack = e instanceof Error ? e.stack : undefined;
        console.error("handleGatewayNetwork threw", msg, stack);
        return new Response(
          JSON.stringify({ ok: false, error: msg }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};

/** Gzip magic bytes (1f 8b) at start of buffer. */
const GZIP_MAGIC = new Uint8Array([0x1f, 0x8b]);

function isGzipBuffer(buf: ArrayBuffer): boolean {
  if (buf.byteLength < 2) return false;
  const u = new Uint8Array(buf);
  return u[0] === GZIP_MAGIC[0] && u[1] === GZIP_MAGIC[1];
}

async function readBody(request: Request): Promise<string> {
  const body = await request.arrayBuffer();
  const ce = request.headers.get("Content-Encoding")?.toLowerCase().trim();
  const isGzip =
    ce === "gzip" || ce === "x-gzip" || isGzipBuffer(body);
  if (isGzip) {
    const ds = new DecompressionStream("gzip");
    return await new Response(
      new Blob([body]).stream().pipeThrough(ds)
    ).text();
  }
  return new TextDecoder("utf-8").decode(body);
}

function parseNDJSON(body: string): Record<string, unknown>[] {
  const lines = body.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const out: Record<string, unknown>[] = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line) as Record<string, unknown>);
    } catch {
      // skip bad lines
    }
  }
  return out;
}

/**
 * Zero Trust: CLIENT_TLS_ERROR → SessionID. We don't have SNI here (ResolvedFQDN is usually blank).
 * Check if gateway_network already stored an SNI for this SessionID; if so, add to list immediately.
 * Otherwise write pending:SessionID so /gateway can resolve when it sees that SessionID + SNI.
 */
async function handleZeroTrustSessions(
  request: Request,
  env: Env
): Promise<Response> {
  if (!env.SESSION_CACHE) {
    throw new Error("SESSION_CACHE KV binding is missing");
  }

  let body: string;
  try {
    body = await readBody(request);
  } catch (e) {
    console.error("read body failed", e);
    return new Response("Bad Request", { status: 400 });
  }

  const records = parseNDJSON(body) as ZeroTrustSessionLog[];
  const sessionIds: string[] = [];

  for (const record of records) {
    if (record.ConnectionCloseReason !== CLIENT_TLS_ERROR) continue;
    const sid = record.SessionID?.trim();
    if (sid) sessionIds.push(sid);
  }

  const uniqueSessionIds = [...new Set(sessionIds)];
  const pending: string[] = [];
  const matched: string[] = [];
  const added: string[] = [];
  const skipped: string[] = [];
  const errors: string[] = [];

  // Fetch existing hostnames once if we might need to add to list
  let existing: Set<string> | null = null;

  try {
    for (const sessionId of uniqueSessionIds) {
      // Check if Gateway already stored an SNI for this session
      const storedSni = await env.SESSION_CACHE.get(sniKey(sessionId));

      if (storedSni) {
        // Gateway arrived first - add SNI to list now
        matched.push(sessionId);
        await env.SESSION_CACHE.delete(sniKey(sessionId));

        if (!isValidHostname(storedSni)) {
          errors.push(`${sessionId}: invalid hostname ${storedSni}`);
          continue;
        }

        // Lazy-load existing hostnames
        if (existing === null) {
          existing = await getListHostnames(env);
        }

        if (existing.has(storedSni)) {
          skipped.push(storedSni);
          continue;
        }

        try {
          await appendToList(env, storedSni);
          added.push(storedSni);
          existing.add(storedSni);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          errors.push(`${sessionId} (${storedSni}): ${msg}`);
        }
      } else {
        // Gateway hasn't arrived yet - store pending marker
        await env.SESSION_CACHE.put(pendingKey(sessionId), "1", {
          expirationTtl: PENDING_TTL_SECONDS,
        });
        pending.push(sessionId);
      }
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("KV or API operation failed", msg);
    return new Response(
      JSON.stringify({
        ok: false,
        error: msg,
        pending_session_ids: pending.length,
        matched_session_ids: matched.length,
        added_hostnames: added,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  const status = errors.length === 0 ? 200 : 207;
  return new Response(
    JSON.stringify({
      ok: errors.length === 0,
      pending_session_ids: pending.length,
      matched_session_ids: matched.length,
      added_hostnames: added,
      skipped_existing: skipped.length,
      errors: errors.length ? errors : undefined,
    }),
    { status, headers: { "Content-Type": "application/json" } }
  );
}

/**
 * Gateway network: if SessionID is pending (CLIENT_TLS_ERROR was seen), add SNI to list.
 * If not pending, store SNI in KV so Zero Trust handler can add it later.
 */
async function handleGatewayNetwork(
  request: Request,
  env: Env
): Promise<Response> {
  if (!env.SESSION_CACHE) {
    throw new Error("SESSION_CACHE KV binding is missing");
  }

  let body: string;
  try {
    body = await readBody(request);
  } catch (e) {
    console.error("read body failed", e);
    return new Response("Bad Request", { status: 400 });
  }

  const records = parseNDJSON(body) as GatewayNetworkLog[];
  const toAdd: Array<{ sessionId: string; sni: string }> = [];
  const storedForLater: string[] = [];

  for (const record of records) {
    const sessionId = record.SessionID?.trim();
    const sni = record.SNI?.trim();
    if (!sessionId || !sni) continue;
    if (!isValidHostname(sni)) continue;

    const wasPending = await env.SESSION_CACHE.get(pendingKey(sessionId));

    if (wasPending) {
      // Zero Trust arrived first - add to list now
      toAdd.push({ sessionId, sni });
      await env.SESSION_CACHE.delete(pendingKey(sessionId));
    } else {
      // Zero Trust hasn't arrived yet - store SNI for later
      await env.SESSION_CACHE.put(sniKey(sessionId), sni, {
        expirationTtl: PENDING_TTL_SECONDS,
      });
      storedForLater.push(sessionId);
    }
  }

  // No pending sessions matched — return 200 without calling Gateway API
  if (toAdd.length === 0) {
    return new Response(
      JSON.stringify({
        ok: true,
        added: 0,
        added_hostnames: [],
        skipped_existing: 0,
        stored_for_later: storedForLater.length,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  let existing: Set<string>;
  try {
    existing = await getListHostnames(env);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("getListHostnames failed", msg);
    return new Response(
      JSON.stringify({
        ok: false,
        error: msg,
        added: 0,
        added_hostnames: [],
        stored_for_later: storedForLater.length,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  const added: string[] = [];
  const errors: string[] = [];
  const skipped: string[] = [];

  for (const { sessionId, sni } of toAdd) {
    if (existing.has(sni)) {
      skipped.push(sni);
      continue;
    }
    try {
      await appendToList(env, sni);
      added.push(sni);
      existing.add(sni);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      errors.push(`${sessionId} (${sni}): ${msg}`);
    }
  }

  const status = errors.length === 0 ? 200 : 207;
  return new Response(
    JSON.stringify({
      ok: errors.length === 0,
      added: added.length,
      added_hostnames: added,
      skipped_existing: skipped.length,
      stored_for_later: storedForLater.length,
      errors: errors.length ? errors : undefined,
    }),
    { status, headers: { "Content-Type": "application/json" } }
  );
}

function pendingKey(sessionId: string): string {
  return `pending:${sessionId}`;
}

function sniKey(sessionId: string): string {
  return `sni:${sessionId}`;
}

function isValidHostname(s: string): boolean {
  if (s.length > 253) return false;
  const part =
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$/i;
  return part.test(s) && !s.startsWith("-") && !s.endsWith(".");
}

/** GET list items and return set of current hostname values (normalized). */
async function getListHostnames(env: Env): Promise<Set<string>> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/gateway/lists/${env.LIST_ID}/items`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${env.API_TOKEN}`,
    },
  });

  if (!res.ok) {
    const err = (await res.json()) as { errors?: Array<{ message?: string }> };
    const msg = err?.errors?.[0]?.message ?? res.statusText;
    throw new Error(`List items: ${msg}`);
  }

  const data = (await res.json()) as {
    result?: Array<{ value?: string }>;
  };
  const items = data?.result ?? [];
  const set = new Set<string>();
  for (const item of items) {
    const v = item.value?.trim();
    if (v) set.add(v);
  }
  return set;
}

async function appendToList(env: Env, hostname: string): Promise<void> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/gateway/lists/${env.LIST_ID}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${env.API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      append: [{ value: hostname, description: "CLIENT_TLS_ERROR" }],
    }),
  });

  if (!res.ok) {
    const err = (await res.json()) as { errors?: Array<{ message?: string }> };
    const msg = err?.errors?.[0]?.message ?? res.statusText;
    throw new Error(msg);
  }
}
