/**
 * Logpush endpoint: receives Zero Trust network sessions (CLIENT_TLS_ERROR)
 * and adds the SNI directly to the Gateway list. The SNI field is now included
 * in the zero_trust_network_sessions dataset, so no KV correlation is needed.
 *
 * - POST / — zero_trust_network_sessions (fields: SessionID, ConnectionCloseReason, SNI)
 * - GET /  — health check
 */

const CLIENT_TLS_ERROR = "CLIENT_TLS_ERROR";

// Zero Trust network session log (dataset: zero_trust_network_sessions)
interface ZeroTrustSessionLog {
  ConnectionCloseReason?: string;
  SessionID?: string;
  SNI?: string;
}

interface Env {
  API_TOKEN: string;
  LIST_ID: string;
  ACCOUNT_ID: string;
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
    if (request.method === "GET") {
      return new Response(
        "cf-dni-list Logpush endpoint\n  POST / = zero_trust_network_sessions\n",
        { headers: { "Content-Type": "text/plain" } }
      );
    }

    if (request.method === "POST") {
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
 * Zero Trust: CLIENT_TLS_ERROR records now include SNI directly.
 * Add each valid SNI to the Gateway list immediately.
 */
async function handleZeroTrustSessions(
  request: Request,
  env: Env
): Promise<Response> {
  let body: string;
  try {
    body = await readBody(request);
  } catch (e) {
    console.error("read body failed", e);
    return new Response("Bad Request", { status: 400 });
  }

  const records = parseNDJSON(body) as ZeroTrustSessionLog[];
  const toAdd: string[] = [];

  for (const record of records) {
    if (record.ConnectionCloseReason !== CLIENT_TLS_ERROR) continue;
    const sni = record.SNI?.trim();
    if (!sni || !isValidHostname(sni)) continue;
    toAdd.push(sni);
  }

  const unique = [...new Set(toAdd)];

  if (unique.length === 0) {
    return new Response(
      JSON.stringify({ ok: true, added_hostnames: [], skipped_existing: 0 }),
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
      JSON.stringify({ ok: false, error: msg }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  const added: string[] = [];
  const skipped: string[] = [];
  const errors: string[] = [];

  for (const sni of unique) {
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
      errors.push(`${sni}: ${msg}`);
    }
  }

  const status = errors.length === 0 ? 200 : 207;
  return new Response(
    JSON.stringify({
      ok: errors.length === 0,
      added_hostnames: added,
      skipped_existing: skipped.length,
      errors: errors.length ? errors : undefined,
    }),
    { status, headers: { "Content-Type": "application/json" } }
  );
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
