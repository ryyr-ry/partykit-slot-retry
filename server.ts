import type * as Party from "partykit/server";

const ROOM_ID = "mcp-bridge";
const REQUEST_TIMEOUT_MS = 30000;
const RELAY_RETRY_COUNT = 3;
const AUTH_CODE_TTL_SEC = 120;
const ACCESS_TOKEN_TTL_SEC = 86400;
const TUNNEL_TOKEN_TTL_SEC = 3600;
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_TOKEN_MAX = 5;
const RATE_LIMIT_AUTHORIZE_MAX = 10;

interface PendingRequest {
  resolve: (msg: any) => void;
  reject: (err: any) => void;
  timer: ReturnType<typeof setTimeout>;
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacVerify(data: string, sig: string, secret: string): Promise<boolean> {
  const expected = await hmacSign(data, secret);
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return diff === 0;
}

function b64urlEncode(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): string {
  return atob(s.replace(/-/g, "+").replace(/_/g, "/"));
}

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeToken(secret: string, ttlSec: number, extra: Record<string, any> = {}): Promise<string> {
  const payload = JSON.stringify({ iat: Date.now(), exp: Date.now() + ttlSec * 1000, ...extra });
  const b64 = b64urlEncode(payload);
  const sig = await hmacSign(b64, secret);
  return `${b64}.${sig}`;
}

interface TokenPayload {
  iat: number;
  exp: number;
  type?: string;
  client_id?: string;
  scope?: string;
  challenge?: string;
  resource?: string;
}

async function verifyToken(token: string, secret: string, expectedType?: string): Promise<TokenPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  if (!(await hmacVerify(b64, sig, secret))) return null;
  try {
    const payload = JSON.parse(b64urlDecode(b64)) as TokenPayload;
    if (Date.now() >= payload.exp) return null;
    if (expectedType && payload.type !== expectedType) return null;
    return payload;
  } catch { return null; }
}

function isRedirectUriAllowed(redirectUri: string): boolean {
  try {
    const u = new URL(redirectUri);
    return u.protocol === "https:" || u.hostname === "localhost" || u.hostname === "127.0.0.1";
  } catch { return false; }
}

function getClientIp(req: Party.Request): string {
  return req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}

export default class TunnelServer implements Party.Server {
  pending = new Map<string, PendingRequest>();

  constructor(readonly room: Party.Room) {}

  onConnect(connection: Party.Connection) {
    const url = new URL(connection.uri);
    const tunnelToken = url.searchParams.get("tunnel_token") ?? "";
    const tunnelSecret = this.room.env.TUNNEL_TOKEN_SECRET as string;

    verifyToken(tunnelToken, tunnelSecret, "tunnel").then((payload) => {
      if (!payload) {
        connection.close(4001, "unauthorized");
        return;
      }
      connection.setState({ role: "tunnel" });
      connection.send(JSON.stringify({ type: "connected" }));
    });
  }

  onMessage(message: string | ArrayBuffer | ArrayBufferView) {
    if (typeof message !== "string") return;
    let msg: any;
    try { msg = JSON.parse(message); } catch { return; }

    if (msg.type === "heartbeat") {
      for (const conn of this.room.getConnections()) {
        if ((conn.state as any)?.role === "tunnel")
          conn.send(JSON.stringify({ type: "heartbeat-ack" }));
      }
      return;
    }

    if (msg.type === "response" && msg.id) {
      const p = this.pending.get(msg.id);
      if (p) {
        this.pending.delete(msg.id);
        clearTimeout(p.timer);
        p.resolve(msg);
      }
    }
  }

  onClose(connection: Party.Connection) {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error("tunnel disconnected"));
      this.pending.delete(id);
    }
  }

  onError(connection: Party.Connection, error: Error) {}

  getTunnel(): Party.Connection | undefined {
    const conns = [...this.room.getConnections()];
    return conns.find(c => (c.state as any)?.role === "tunnel");
  }

  async onRequest(req: Party.Request): Promise<Response> {
    const url = new URL(req.url);
    const roomPrefix = `/parties/main/${this.room.id}`;
    const cleanPath = url.pathname.startsWith(roomPrefix)
      ? url.pathname.slice(roomPrefix.length) || "/"
      : url.pathname;

    if (cleanPath === "/__ratecheck" && req.method === "GET") {
      const key = url.searchParams.get("key") ?? "";
      const now = Number(url.searchParams.get("now") ?? Date.now());
      const max = Number(url.searchParams.get("max") ?? 5);
      const storageKey = `rate:${key}`;
      const last = (await this.room.storage.get<number[]>(storageKey)) ?? [];
      const recent = last.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
      if (recent.length >= max) {
        await this.room.storage.put(storageKey, recent);
        return new Response("denied", { status: 429 });
      }
      recent.push(now);
      await this.room.storage.put(storageKey, recent);
      return new Response("ok", { status: 200 });
    }

    const tunnel = this.getTunnel();
    if (!tunnel) {
      return new Response(
        JSON.stringify({ error: "tunnel not connected" }),
        { status: 503, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "null" } }
      );
    }

    const id = crypto.randomUUID();
    let path = cleanPath;
    let relayPath = path;
    if (url.search) relayPath += url.search;

    const body = req.method !== "GET" && req.method !== "HEAD" ? await req.text() : undefined;
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => { headers[k] = v; });

    tunnel.send(JSON.stringify({ type: "request", id, method: req.method, path: relayPath, headers, body }));

    return new Promise<Response>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error("timeout")); }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, {
        resolve: (msg: any) => {
          const h = new Headers(msg.headers ?? {});
          h.set("Access-Control-Allow-Origin", "null");
          h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
          h.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
          resolve(new Response(msg.body ?? null, { status: msg.status ?? 200, headers: h }));
        },
        reject,
        timer,
      });
    });
  }

  static async onFetch(req: Party.Request, lobby: Party.FetchLobby): Promise<Response | null> {
    if (req.headers.get("upgrade") === "websocket") return null;

    const oauthCorsHeaders: Record<string, string> = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    };

    const mcpCorsHeaders: Record<string, string> = {
      "Access-Control-Allow-Origin": "null",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    };

    if (req.method === "OPTIONS") {
      const url = new URL(req.url);
      const corsHeaders = url.pathname === "/mcp" || url.pathname.startsWith("/mcp") ? mcpCorsHeaders : oauthCorsHeaders;
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(req.url);
    const path = url.pathname;
    const base = `https://${url.host}`;
    const clientId = lobby.env.OAUTH_CLIENT_ID as string;
    const clientSecret = lobby.env.OAUTH_CLIENT_SECRET as string;
    const signingSecret = lobby.env.TOKEN_SIGNING_SECRET as string;
    const tunnelSecret = lobby.env.TUNNEL_TOKEN_SECRET as string;

    async function checkRateLimit(stub: Party.Stub, key: string, max: number): Promise<boolean> {
      const now = Date.now();
      const res = await stub.fetch(`/__ratecheck?key=${encodeURIComponent(key)}&now=${now}&max=${max}`, { method: "GET" });
      return res.status === 200;
    }

    // --- Health ---
    if (path === "/health") {
      return new Response(
        JSON.stringify({ status: "ok" }),
        { status: 200, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } }
      );
    }

    // --- OAuth Authorization Server Metadata (RFC 8414) ---
    if (path === "/.well-known/oauth-authorization-server") {
      return new Response(JSON.stringify({
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        scopes_supported: ["mcp"],
      }), { status: 200, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
    }

    // --- OAuth Protected Resource Metadata (RFC 9728) ---
    if (path === "/.well-known/oauth-protected-resource") {
      return new Response(JSON.stringify({
        resource: base,
        authorization_servers: [base],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp"],
      }), { status: 200, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
    }

    // --- Authorize (auto-approve, stateless, PKCE optional but verified) ---
    if (path === "/authorize" && req.method === "GET") {
      const qp = url.searchParams;
      const redirectUri = qp.get("redirect_uri");
      const state = qp.get("state") ?? "";
      const reqClientId = qp.get("client_id") ?? "";
      const codeChallenge = qp.get("code_challenge") ?? "";
      const codeChallengeMethod = qp.get("code_challenge_method") ?? "";
      const resourceParam = qp.get("resource") ?? base;
      let resource = base;
      try { resource = new URL(resourceParam).origin; } catch {}

      if (!redirectUri) {
        return new Response(JSON.stringify({ error: "invalid_request" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }
      if (reqClientId !== clientId) {
        return new Response(JSON.stringify({ error: "invalid_client" }), { status: 401, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }
      if (!isRedirectUriAllowed(redirectUri)) {
        return new Response(JSON.stringify({ error: "invalid_request", error_description: "redirect_uri not allowed" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      const stub = lobby.parties["main"].get(ROOM_ID);
      const ip = getClientIp(req);
      const allowed = await checkRateLimit(stub, `auth:${ip}`, RATE_LIMIT_AUTHORIZE_MAX);
      if (!allowed) {
        return new Response(JSON.stringify({ error: "too_many_requests" }), { status: 429, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      const codeExtra: Record<string, any> = { type: "code", client_id: reqClientId, resource };
      if (codeChallenge && codeChallengeMethod === "S256") {
        codeExtra.challenge = codeChallenge;
      }

      const code = await makeToken(signingSecret, AUTH_CODE_TTL_SEC, codeExtra);
      const callbackUrl = `${redirectUri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
      return Response.redirect(callbackUrl, 302);
    }

    // --- Token endpoint (stateless, with client authentication + PKCE required) ---
    if (path === "/token" && req.method === "POST") {
      const stub = lobby.parties["main"].get(ROOM_ID);
      const ip = getClientIp(req);
      const allowed = await checkRateLimit(stub, `token:${ip}`, RATE_LIMIT_TOKEN_MAX);
      if (!allowed) {
        return new Response(JSON.stringify({ error: "too_many_requests" }), { status: 429, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      const body = await req.text();
      const params = new URLSearchParams(body);
      const grantType = params.get("grant_type") ?? "";

      let authenticated = false;

      const authHeader = req.headers.get("authorization") ?? "";
      if (authHeader.startsWith("Basic ")) {
        try {
          const decoded = atob(authHeader.slice(6));
          const colonIdx = decoded.indexOf(":");
          const u = decoded.slice(0, colonIdx);
          const p = decoded.slice(colonIdx + 1);
          if (u === clientId && p === clientSecret) authenticated = true;
        } catch {}
      } else {
        const postCid = params.get("client_id") ?? "";
        const postCsec = params.get("client_secret") ?? "";
        if (postCid === clientId && postCsec === clientSecret) authenticated = true;
      }

      if (!authenticated) {
        return new Response(JSON.stringify({ error: "invalid_client" }), { status: 401, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      if (grantType === "authorization_code") {
        const code = params.get("code") ?? "";
        const codeVerifier = params.get("code_verifier") ?? "";
        const codePayload = await verifyToken(code, signingSecret, "code");
        if (!codePayload) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
        }

        if (codePayload.challenge && codeVerifier) {
          const computed = await sha256(codeVerifier);
          if (computed !== codePayload.challenge) {
            return new Response(JSON.stringify({ error: "invalid_grant", error_description: "PKCE verification failed" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
          }
        }

        const token = await makeToken(signingSecret, ACCESS_TOKEN_TTL_SEC, { type: "access", client_id: codePayload.client_id, scope: "mcp", resource: codePayload.resource });
        const refreshToken = await makeToken(signingSecret, ACCESS_TOKEN_TTL_SEC, { type: "refresh", client_id: codePayload.client_id, scope: "mcp", resource: codePayload.resource });
        return new Response(JSON.stringify({
          access_token: token,
          token_type: "Bearer",
          expires_in: ACCESS_TOKEN_TTL_SEC,
          refresh_token: refreshToken,
          scope: "mcp",
        }), { status: 200, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      if (grantType === "refresh_token") {
        const refreshToken = params.get("refresh_token") ?? "";
        const refreshPayload = await verifyToken(refreshToken, signingSecret, "refresh");
        if (!refreshPayload) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
        }
        const token = await makeToken(signingSecret, ACCESS_TOKEN_TTL_SEC, { type: "access", client_id: refreshPayload.client_id, scope: "mcp", resource: refreshPayload.resource });
        return new Response(JSON.stringify({
          access_token: token,
          token_type: "Bearer",
          expires_in: ACCESS_TOKEN_TTL_SEC,
          scope: "mcp",
        }), { status: 200, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
      }

      return new Response(JSON.stringify({ error: "unsupported_grant_type" }), { status: 400, headers: { "Content-Type": "application/json", ...oauthCorsHeaders } });
    }

    // --- All other paths: require Bearer token then relay ---
    const resourceMetadataUrl = `${base}/.well-known/oauth-protected-resource`;
    const wwwAuth = `Bearer resource_metadata="${resourceMetadataUrl}", scope="mcp"`;

    const auth = req.headers.get("Authorization") ?? "";
    if (!auth.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": wwwAuth,
          ...mcpCorsHeaders,
        },
      });
    }
    const token = auth.slice(7);
    const payload = await verifyToken(token, signingSecret, "access");
    if (!payload) {
      return new Response(JSON.stringify({ error: "invalid_token" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": wwwAuth,
          ...mcpCorsHeaders,
        },
      });
    }

    if (payload.resource) {
      let resourceOrigin = base;
      try { resourceOrigin = new URL(payload.resource).origin; } catch {}
      if (resourceOrigin !== base) {
        return new Response(JSON.stringify({ error: "invalid_token", error_description: "resource mismatch" }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": wwwAuth,
            ...mcpCorsHeaders,
          },
        });
      }
    }

    const reqBody = req.method !== "GET" && req.method !== "HEAD" ? await req.text() : undefined;
    const reqHeaders = Object.fromEntries(req.headers);
    const fullPath = path + url.search;

    for (let attempt = 0; attempt < RELAY_RETRY_COUNT; attempt++) {
      try {
        const stub = lobby.parties["main"].get(ROOM_ID);
        const res = await stub.fetch(fullPath, { method: req.method, headers: reqHeaders, body: reqBody });
        if (res.status !== 503) return res;
        await res.text();
        if (attempt < RELAY_RETRY_COUNT - 1) await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      } catch {
        if (attempt < RELAY_RETRY_COUNT - 1) await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      }
    }

    return new Response(
      JSON.stringify({ error: "tunnel unavailable" }),
      { status: 503, headers: { "Content-Type": "application/json", ...mcpCorsHeaders } }
    );
  }
}

TunnelServer satisfies Party.Worker;
