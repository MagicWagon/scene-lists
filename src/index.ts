import { SignJWT, importPKCS8 } from "jose";

type Env = {
  GITHUB_APP_ID: string;
  GITHUB_INSTALLATION_ID: string;
  GITHUB_PRIVATE_KEY_PEM: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  CHALLENGES: any;
};

const OWNER = "MagicWagon";
const REPO = "scene-lists";
const CHALLENGE_TTL_SECONDS = 10 * 60;
const RATE_LIMIT_WINDOW_SECONDS = 60 * 60;
const RATE_LIMIT_CHALLENGE_STARTS_PER_WINDOW = 10;
const RATE_LIMIT_SUBMITS_PER_WINDOW = 3;
const MAX_SUBMIT_BYTES = 900_000;
const MAX_SUBMIT_SCENES = 2500;

type StoredChallengeSession = {
  ip_hash: string;
  created_at_ms: number;
  expires_at_ms: number;
  verified: boolean;
  verified_at_ms?: number;
};

function jsonError(status: number, code: string, message: string, details?: unknown) {
  return Response.json(
    { ok: false, error: { code, message, details: details ?? null } },
    { status, headers: { "Content-Type": "application/json" } },
  );
}

function jsonOk(data: Record<string, unknown>, init?: ResponseInit) {
  const status = init?.status ?? 200;
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify({ ok: true, ...data }), { ...init, status, headers });
}

function base64EncodeBytes(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64DecodeToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64encodeUtf8(input: string): string {
  return base64EncodeBytes(new TextEncoder().encode(input));
}

function base64decodeUtf8(b64: string): string {
  return new TextDecoder().decode(base64DecodeToBytes(b64));
}

function normalizeWorkerPath(pathname: string) {
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

function getRequestIp(request: Request): string {
  const cfIp = request.headers.get("CF-Connecting-IP");
  if (cfIp) return cfIp.trim();
  const xff = request.headers.get("X-Forwarded-For");
  if (xff) return xff.split(",")[0]?.trim() || "unknown";
  return "unknown";
}

function base64UrlEncode(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64Url(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlEncode(digest);
}

async function readJsonWithLimit(request: Request, maxBytes: number): Promise<any> {
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new Error("payload_too_large");
  const text = new TextDecoder().decode(buf);
  return text ? JSON.parse(text) : null;
}

function sanitizeScenePath(scenePath: string): string | null {
  const p = (scenePath || "").trim();
  if (!p) return null;
  if (p.startsWith("/") || p.includes("\\") || p.includes("..")) return null;
  if (!(p.startsWith("scenejsons/") || p.startsWith("shows/"))) return null;
  if (!p.endsWith(".json")) return null;
  if (p.length > 220) return null;
  return p;
}

export class Challenges {
  constructor(
    private readonly state: any,
    private readonly env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = normalizeWorkerPath(url.pathname);

    if (request.method === "POST" && path === "/rate/consume") {
      let body: any;
      try {
        body = await readJsonWithLimit(request, 10_000);
      } catch (e: any) {
        if (String(e?.message || e) === "payload_too_large") return jsonError(413, "payload_too_large", "Payload too large.");
        return jsonError(400, "bad_json", "Body must be valid JSON.");
      }

      const kind = String(body?.kind || "");
      const limit = Number(body?.limit || 0) || 0;
      const windowSeconds = Number(body?.window_seconds || 0) || 0;
      if (!kind || !Number.isFinite(limit) || limit <= 0 || !Number.isFinite(windowSeconds) || windowSeconds <= 0) {
        return jsonError(400, "bad_request", "Missing or invalid rate limit parameters.");
      }

      const nowMs = Date.now();
      const windowMs = windowSeconds * 1000;
      const bucket = Math.floor(nowMs / windowMs);
      const key = `${kind}:${bucket}`;
      const current = Number((await this.state.storage.get<number>(key)) || 0) || 0;
      const next = current + 1;
      await this.state.storage.put(key, next, { expirationTtl: windowSeconds * 2 });

      if (next > limit) {
        const bucketEndMs = (bucket + 1) * windowMs;
        const retryAfterSeconds = Math.max(1, Math.ceil((bucketEndMs - nowMs) / 1000));
        return new Response(
          JSON.stringify({
            ok: false,
            error: { code: "rate_limited", message: "Too many requests.", details: { retry_after_seconds: retryAfterSeconds } },
          }),
          { status: 429, headers: { "Content-Type": "application/json", "Retry-After": String(retryAfterSeconds) } },
        );
      }

      return jsonOk({});
    }

    if (request.method === "POST" && path === "/session/init") {
      let body: any;
      try {
        body = await readJsonWithLimit(request, 10_000);
      } catch (e: any) {
        if (String(e?.message || e) === "payload_too_large") return jsonError(413, "payload_too_large", "Payload too large.");
        return jsonError(400, "bad_json", "Body must be valid JSON.");
      }

      const ipHash = String(body?.ip_hash || "").trim();
      const ttlSeconds = Number(body?.ttl_seconds || 0) || 0;
      if (!ipHash || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
        return jsonError(400, "bad_request", "Missing or invalid session parameters.");
      }

      const nowMs = Date.now();
      const session: StoredChallengeSession = {
        ip_hash: ipHash,
        created_at_ms: nowMs,
        expires_at_ms: nowMs + ttlSeconds * 1000,
        verified: false,
      };

      await this.state.storage.put("session", session, { expirationTtl: ttlSeconds });
      return jsonOk({});
    }

    if (request.method === "GET" && path === "/session/get") {
      const session = (await this.state.storage.get<StoredChallengeSession>("session")) || null;
      if (!session) return jsonOk({ session: null });
      if (Date.now() > session.expires_at_ms) {
        await this.state.storage.delete("session");
        return jsonOk({ session: null });
      }
      return jsonOk({ session });
    }

    if (request.method === "POST" && path === "/session/verify") {
      const session = (await this.state.storage.get<StoredChallengeSession>("session")) || null;
      if (!session) return jsonError(404, "not_found", "Session not found.");
      if (Date.now() > session.expires_at_ms) {
        await this.state.storage.delete("session");
        return jsonError(404, "not_found", "Session not found.");
      }

      session.verified = true;
      session.verified_at_ms = Date.now();
      const remainingSeconds = Math.max(1, Math.ceil((session.expires_at_ms - Date.now()) / 1000));
      await this.state.storage.put("session", session, { expirationTtl: remainingSeconds });
      return jsonOk({});
    }

    return new Response("not found", { status: 404 });
  }
}

async function consumeRateLimit(env: Env, ipHash: string, kind: "start" | "submit"): Promise<Response | null> {
  const id = env.CHALLENGES.idFromName(`ip:${ipHash}`);
  const stub = env.CHALLENGES.get(id);
  const resp = await stub.fetch("https://do/rate/consume", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      kind,
      limit: kind === "start" ? RATE_LIMIT_CHALLENGE_STARTS_PER_WINDOW : RATE_LIMIT_SUBMITS_PER_WINDOW,
      window_seconds: RATE_LIMIT_WINDOW_SECONDS,
    }),
  });
  return resp.ok ? null : resp;
}

async function initChallengeSession(env: Env, sessionId: string, ipHash: string): Promise<void> {
  const id = env.CHALLENGES.idFromName(`sess:${sessionId}`);
  const stub = env.CHALLENGES.get(id);
  const resp = await stub.fetch("https://do/session/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip_hash: ipHash, ttl_seconds: CHALLENGE_TTL_SECONDS }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to init session (${resp.status}): ${text}`);
  }
}

async function getChallengeSession(env: Env, sessionId: string): Promise<StoredChallengeSession | null> {
  const id = env.CHALLENGES.idFromName(`sess:${sessionId}`);
  const stub = env.CHALLENGES.get(id);
  const resp = await stub.fetch("https://do/session/get");
  if (!resp.ok) return null;
  const data: any = await resp.json().catch(() => null);
  const session = data?.session || null;
  if (!session) return null;
  return session as StoredChallengeSession;
}

async function markChallengeVerified(env: Env, sessionId: string): Promise<void> {
  const id = env.CHALLENGES.idFromName(`sess:${sessionId}`);
  const stub = env.CHALLENGES.get(id);
  const resp = await stub.fetch("https://do/session/verify", { method: "POST" });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to verify session (${resp.status}): ${text}`);
  }
}

function captchaRequiredResponse(): Response {
  return new Response(
    JSON.stringify({ ok: false, error: { code: "captcha_required", message: "Please complete verification." } }),
    { status: 403, headers: { "Content-Type": "application/json" } },
  );
}

async function githubFetch(token: string, url: string, init?: RequestInit) {
  const resp = await fetch(url, {
    ...init,
    headers: {
      "User-Agent": "Bleepr-Worker/1.0",
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      ...(init?.headers || {}),
    },
  });
  const text = await resp.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!resp.ok) {
    throw new Error(`GitHub API failed (${resp.status}): ${typeof data === "string" ? data : JSON.stringify(data)}`);
  }
  return data;
}

async function mintAppJwt(env: Env): Promise<string> {
  const appId = String(env.GITHUB_APP_ID || "").trim();
  const pem = String(env.GITHUB_PRIVATE_KEY_PEM || "").trim();
  if (!appId || !pem) throw new Error("Missing GitHub App credentials.");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };

  const key = await importPKCS8(pem, "RS256");

  return await new SignJWT({})
    .setProtectedHeader(header)
    .setIssuer(appId)
    .setIssuedAt(now)
    .setExpirationTime(now + 9 * 60)
    .sign(key);
}

async function mintInstallationToken(env: Env): Promise<string> {
  const installationId = String(env.GITHUB_INSTALLATION_ID || "").trim();
  if (!installationId) throw new Error("Missing GITHUB_INSTALLATION_ID.");

  const jwt = await mintAppJwt(env);

  const resp = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      "User-Agent": "Bleepr-Worker/1.0",
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${jwt}`,
    },
  });

  const data = await resp.json().catch(() => null);
  if (!resp.ok) throw new Error(`Installation token mint failed (${resp.status}): ${JSON.stringify(data)}`);

  const token = String(data?.token || "").trim();
  if (!token) throw new Error("Installation token response missing token.");
  return token;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = normalizeWorkerPath(url.pathname);

    if (request.method === "POST" && path === "/challenge/start") {
      const ipHash = await sha256Base64Url(getRequestIp(request));
      const limited = await consumeRateLimit(env, ipHash, "start");
      if (limited) return limited;

      const sessionId = crypto.randomUUID();
      try {
        await initChallengeSession(env, sessionId, ipHash);
      } catch (e: any) {
        return jsonError(500, "session_error", "Failed to create challenge session.", String(e?.message || e));
      }

      return jsonOk({ session_id: sessionId, verify_url: `${url.origin}/challenge/${sessionId}` });
    }

    const challengeMatch = path.match(/^\/challenge\/([a-zA-Z0-9-]+)$/);
    if (request.method === "GET" && challengeMatch) {
      const sessionId = challengeMatch[1]!;
      const siteKey = String(env.TURNSTILE_SITE_KEY || "").trim();
      if (!siteKey) return jsonError(500, "config_error", "Missing TURNSTILE_SITE_KEY.");

      const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Bleepr Verification</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 32px; line-height: 1.4; }
      .card { max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #e5e7eb; border-radius: 14px; }
      h1 { font-size: 18px; margin: 0 0 12px; }
      p { margin: 0 0 16px; color: #374151; }
      .status { margin-top: 14px; font-size: 14px; color: #111827; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Verify you’re human</h1>
      <p>Complete the challenge, then return to the Bleepr app.</p>
      <div class="cf-turnstile" data-sitekey="${siteKey}" data-callback="onTurnstile" data-error-callback="onTurnstileError"></div>
      <div class="status" id="status"></div>
      <p style="margin-top: 16px; font-size: 12px; color: #6b7280;">
        Session: <code>${sessionId}</code>
      </p>
    </div>
    <script>
      const sessionId = ${JSON.stringify(sessionId)};
      function onTurnstileError(code) {
        const el = document.getElementById("status");
        const c = String(code || "");
        if (c === "110200") {
          el.textContent = "Turnstile is not configured for this domain. Add " + location.hostname + " to the widget's allowed hostnames.";
          return;
        }
        el.textContent = "Turnstile error: " + (c || "unknown");
      }
      async function onTurnstile(token) {
        const el = document.getElementById("status");
        el.textContent = "Verifying…";
        try {
          const resp = await fetch("/challenge/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sessionId, token })
          });
          const data = await resp.json().catch(() => null);
          if (resp.ok && data && data.ok) {
            el.textContent = "Verified. You can close this tab.";
          } else {
            el.textContent = (data && data.error && data.error.message) ? data.error.message : "Verification failed.";
          }
        } catch (e) {
          el.textContent = "Verification failed.";
        }
      }
    </script>
  </body>
</html>`;
      return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    if (request.method === "POST" && path === "/challenge/complete") {
      let body: any;
      try {
        body = await readJsonWithLimit(request, 30_000);
      } catch (e: any) {
        if (String(e?.message || e) === "payload_too_large") return jsonError(413, "payload_too_large", "Payload too large.");
        return jsonError(400, "bad_json", "Body must be valid JSON.");
      }

      const sessionId = String(body?.session_id || "").trim();
      const token = String(body?.token || "").trim();
      if (!sessionId || !token) return jsonError(400, "bad_request", "Missing session_id or token.");

      const ipHash = await sha256Base64Url(getRequestIp(request));
      const session = await getChallengeSession(env, sessionId);
      if (!session || session.ip_hash !== ipHash) return captchaRequiredResponse();

      const secret = String(env.TURNSTILE_SECRET_KEY || "").trim();
      if (!secret) return jsonError(500, "config_error", "Missing TURNSTILE_SECRET_KEY.");

      const form = new URLSearchParams();
      form.set("secret", secret);
      form.set("response", token);
      const ip = getRequestIp(request);
      if (ip && ip !== "unknown") form.set("remoteip", ip);

      let verifyResp: Response;
      try {
        verifyResp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: form.toString(),
        });
      } catch (e: any) {
        return jsonError(502, "turnstile_unreachable", "Failed to reach Turnstile verification.", String(e?.message || e));
      }

      const verifyData: any = await verifyResp.json().catch(() => null);
      if (!verifyResp.ok) {
        return jsonError(502, "turnstile_error", "Turnstile verification failed.", verifyData);
      }
      if (!verifyData?.success) {
        return jsonError(403, "turnstile_invalid", "Invalid verification token.", verifyData);
      }

      try {
        await markChallengeVerified(env, sessionId);
      } catch (e: any) {
        return jsonError(500, "session_error", "Failed to mark session verified.", String(e?.message || e));
      }

      return jsonOk({ verified: true });
    }

    if (request.method === "POST" && path === "/challenge/status") {
      let body: any;
      try {
        body = await readJsonWithLimit(request, 10_000);
      } catch (e: any) {
        if (String(e?.message || e) === "payload_too_large") return jsonError(413, "payload_too_large", "Payload too large.");
        return jsonError(400, "bad_json", "Body must be valid JSON.");
      }

      const sessionId = String(body?.session_id || "").trim();
      if (!sessionId) return jsonError(400, "bad_request", "Missing session_id.");

      const ipHash = await sha256Base64Url(getRequestIp(request));
      const session = await getChallengeSession(env, sessionId);
      const verified = Boolean(session && session.ip_hash === ipHash && session.verified);
      return jsonOk({ verified });
    }

    if (request.method !== "POST" || path !== "/submit-scene") {
      return new Response("not found", { status: 404 });
    }

    const sessionId = String(request.headers.get("X-Bleepr-Challenge") || "").trim();
    if (!sessionId) return captchaRequiredResponse();

    const ipHash = await sha256Base64Url(getRequestIp(request));
    const session = await getChallengeSession(env, sessionId);
    if (!session || session.ip_hash !== ipHash || !session.verified) return captchaRequiredResponse();

    const limited = await consumeRateLimit(env, ipHash, "submit");
    if (limited) return limited;

    let body: any;
    let rawBytes = 0;
    try {
      const buf = await request.arrayBuffer();
      rawBytes = buf.byteLength;
      if (rawBytes > MAX_SUBMIT_BYTES) return jsonError(413, "payload_too_large", "Payload too large.");
      const text = new TextDecoder().decode(buf);
      body = text ? JSON.parse(text) : null;
    } catch {
      return jsonError(400, "bad_json", "Body must be valid JSON.");
    }

    const sceneList = body?.scene_list;
    const scenePathRaw = body?.scene_path;

    if (!sceneList || typeof sceneList !== "object") {
      return jsonError(400, "bad_request", "Missing scene_list object.");
    }

    const schemaVersion = Number(sceneList.schema_version || 0);
    if (schemaVersion !== 3) {
      return jsonError(400, "bad_schema", "scene_list.schema_version must be 3.");
    }

    const contentType = String(sceneList.content_type || "").trim().toLowerCase();
    if (contentType !== "movie" && contentType !== "episode") {
      return jsonError(400, "bad_content_type", "scene_list.content_type must be movie or episode.");
    }

    const ids = sceneList.ids;
    if (!ids || typeof ids !== "object") {
      return jsonError(400, "bad_ids", "scene_list.ids must be an object.");
    }
    const tmdb = (ids as any).tmdb;
    if (!tmdb || typeof tmdb !== "object") {
      return jsonError(400, "bad_tmdb", "scene_list.ids.tmdb must be an object.");
    }
    const tmdbType = String((tmdb as any).type || "").trim().toLowerCase();
    const tmdbId = Number((tmdb as any).id || 0) || 0;
    if (!Number.isFinite(tmdbId) || tmdbId <= 0 || (tmdbType !== "movie" && tmdbType !== "tv")) {
      return jsonError(400, "bad_tmdb", "scene_list.ids.tmdb.type must be movie|tv and id must be a positive integer.");
    }
    if (contentType === "movie" && tmdbType !== "movie") {
      return jsonError(400, "bad_tmdb", "Movie submissions must use ids.tmdb.type = movie.");
    }
    if (contentType === "episode" && tmdbType !== "tv") {
      return jsonError(400, "bad_tmdb", "Episode submissions must use ids.tmdb.type = tv.");
    }

    const imdbIdRaw = String((ids as any).imdb || "").trim();
    const imdbId = imdbIdRaw ? imdbIdRaw.toLowerCase() : "";
    if (imdbId && !/^tt\d{7,9}$/.test(imdbId)) {
      return jsonError(400, "bad_imdb_id", "scene_list.ids.imdb must look like tt1234567 (or be omitted).");
    }

    let seasonNumber = 0;
    let episodeNumber = 0;
    if (contentType === "episode") {
      const episode = sceneList.episode;
      if (!episode || typeof episode !== "object") {
        return jsonError(400, "bad_episode", "scene_list.episode must be an object for episode submissions.");
      }
      seasonNumber = Number((episode as any).season_number || 0) || 0;
      episodeNumber = Number((episode as any).episode_number || 0) || 0;
      if (!Number.isFinite(seasonNumber) || !Number.isFinite(episodeNumber) || seasonNumber <= 0 || episodeNumber <= 0) {
        return jsonError(400, "bad_episode", "scene_list.episode.season_number and episode_number must be positive integers.");
      }
    }

    const scenes = sceneList.scenes;
    if (!Array.isArray(scenes) || scenes.length === 0) {
      return jsonError(400, "no_scenes", "scene_list.scenes must be a non-empty array.");
    }
    if (scenes.length > MAX_SUBMIT_SCENES) {
      return jsonError(400, "too_many_scenes", "scene_list.scenes is too large.");
    }

    const scenePath = sanitizeScenePath(String(scenePathRaw || ""));
    if (!scenePath) {
      return jsonError(400, "bad_scene_path", "scene_path must be under scenejsons/ or shows/ and end with .json.");
    }

    if (rawBytes > MAX_SUBMIT_BYTES) return jsonError(413, "payload_too_large", "Payload too large.");

    let installationToken: string;
    try {
      installationToken = await mintInstallationToken(env);
    } catch (e: any) {
      return jsonError(500, "auth_failed", "Failed to mint GitHub installation token.", String(e?.message || e));
    }

    try {
      const repoInfo = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}`,
      );
      const baseBranch = String(repoInfo?.default_branch || "main");

      const refInfo = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}/git/ref/heads/${encodeURIComponent(baseBranch)}`,
      );
      const baseSha = String(refInfo?.object?.sha || "");
      if (!baseSha) throw new Error("Missing base SHA.");

      const branchKey = contentType === "episode" ? `tmdb_${tmdbType}_${tmdbId}_s${String(seasonNumber).padStart(2, '0')}e${String(episodeNumber).padStart(2, '0')}` : `tmdb_${tmdbType}_${tmdbId}`;

      const branch = `bleepr/upload/${branchKey}/${Date.now()}`;

      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/git/refs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: baseSha }),
      });

      // Upload scene file
      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/contents/${scenePath}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: `Add scene list for ${sceneList.title || branchKey} (tmdb:${tmdbType}:${tmdbId}${imdbId ? ` imdb:${imdbId}` : ""})`,
          content: base64encodeUtf8(JSON.stringify(sceneList, null, 2)),
          branch,
        }),
      });

      // Update index.json
      const indexResp = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}/contents/index.json?ref=${encodeURIComponent(branch)}`,
      );
      const indexSha = String(indexResp?.sha || "");
      const indexContentB64 = String(indexResp?.content || "");
      const indexText = indexContentB64 ? base64decodeUtf8(indexContentB64.replace(/\n/g, "")) : "{}";

      let indexJson: any = {};
      try {
        indexJson = JSON.parse(indexText);
      } catch {
        indexJson = {};
      }
      if (!indexJson || typeof indexJson !== "object") indexJson = {};
      if (!Array.isArray(indexJson.movies)) indexJson.movies = [];
      if (!Array.isArray(indexJson.episodes)) indexJson.episodes = [];
      if (!indexJson.schema_version) indexJson.schema_version = 2;

      const title = String(sceneList.title || "").trim();
      const createdAt = String(sceneList.created_at || "").trim();
      const durationMs = Number(sceneList.video_duration_ms || 0) || 0;
      const label = String(sceneList.label || "").trim();

      if (contentType === "movie") {
        indexJson.movies.push({
          imdb_id: imdbId || `tmdb_movie_${tmdbId}`,
          tmdb: { type: tmdbType, id: tmdbId },
          title,
          year: Number(sceneList.year || 0) || 0,
          path: scenePath,
          created_at: createdAt,
          video_duration_ms: durationMs,
          label,
        });
      } else {
        const seriesTitle = String(sceneList.series?.title || "").trim();
        const episodeTitle = String(sceneList.episode?.title || "").trim();
        indexJson.episodes.push({
          tmdb: { type: tmdbType, id: tmdbId },
          imdb_id: imdbId || "",
          series_title: seriesTitle,
          season_number: seasonNumber,
          episode_number: episodeNumber,
          episode_title: episodeTitle,
          title,
          year: Number(sceneList.year || 0) || 0,
          path: scenePath,
          created_at: createdAt,
          video_duration_ms: durationMs,
          label,
        });
      }

      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/contents/index.json`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: `Update index for ${sceneList.title || branchKey} (tmdb:${tmdbType}:${tmdbId})`,
          content: base64encodeUtf8(JSON.stringify(indexJson, null, 2)),
          sha: indexSha,
          branch,
        }),
      });

      const pr = await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/pulls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: `Add scene list: ${sceneList.title || branchKey} (tmdb:${tmdbType}:${tmdbId})`,
          head: `${OWNER}:${branch}`,
          base: baseBranch,
          body: `TMDb: ${tmdbType}:${tmdbId}\nIMDb: ${imdbId || "(none)"}\nType: ${contentType}${contentType === "episode" ? `\nSeason: ${seasonNumber}\nEpisode: ${episodeNumber}` : ""}\nPath: ${scenePath}\nCreated: ${sceneList.created_at || ""}\n`,
        }),
      });

      const prUrl = String(pr?.html_url || "").trim();
      if (!prUrl) throw new Error("PR created but missing html_url.");

      return jsonOk({ pr_url: prUrl });
    } catch (e: any) {
      return jsonError(500, "github_error", "Failed to create pull request.", String(e?.message || e));
    }
  },
};
