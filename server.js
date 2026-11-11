"use strict";

/*
  TEDxAASTMT ticketing server
  ---------------------------
  Serves index.html (tickets) and checkin.html (organizers), and relays
  requests to the Google Apps Script web app, which is the source of truth.

  Required env:
    APPS_SCRIPT_URL   The web app URL ending in /exec (no extra path!)

  Optional env:
    PORT                 default 5000
    EVENT_DATE           default "Tuesday, 15 December 2026"
    EVENT_TIME           default "2:30 PM"
    EVENT_PLACE          default "AASTMT AbuQir"
    EVENT_VENUE          default "Pharmacy · Romanian Stadium"
    REGISTRATION_CLOSED  set to "1" to close registration
    TRUST_PROXY          set to "1" when behind a proxy (Render, Railway, Nginx...)

  Optional file:
    data/students.json   JSON array of valid 9-digit registration numbers.
                         If present, only these numbers can register.
*/

const http = require("node:http");
const fsp = require("node:fs/promises");
const path = require("node:path");

/* ============ CONFIG ============ */
const PORT = Number(process.env.PORT) || 5000;
const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL || "";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";

const EVENT = {
  eventDate: process.env.EVENT_DATE || "Tuesday, 15 December 2026",
  eventTime: process.env.EVENT_TIME || "2:30 PM",
  eventPlace: process.env.EVENT_PLACE || "AASTMT AbuQir",
  eventVenue: process.env.EVENT_VENUE || "Pharmacy · Romanian Stadium",
  // ISO start time (Cairo is UTC+2 in December). Used for the add-to-calendar file.
  eventStart: process.env.EVENT_START || "2026-12-15T14:30:00+02:00",
  branches: ["AbuQir", "Miami", "Alamein"]
};

const ROOT = __dirname;
const STUDENTS_FILE = path.join(ROOT, "data", "students.json");
const MAX_BODY = 8 * 1024;
const UPSTREAM_TIMEOUT_MS = 20000;

// Only these files can ever be served. Nothing else in the folder is public.
const PAGES = {
  "/": "index.html",
  "/index.html": "index.html",
  "/checkin": "checkin.html",
  "/checkin.html": "checkin.html",
  "/organizer": "checkin.html"
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "media-src 'self' blob:",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'"
  ].join("; ")
};

/* ============ SMALL HELPERS ============ */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, data, extra = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...SECURITY_HEADERS,
    ...extra
  });
  res.end(body);
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const fwd = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (fwd) return fwd;
  }
  return req.socket.remoteAddress || "unknown";
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    let done = false;

    req.on("data", (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_BODY) {
        done = true;
        reject(new HttpError(413, "Request too large."));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("not an object");
        }
        resolve(parsed);
      } catch {
        reject(new HttpError(400, "Invalid request."));
      }
    });
    req.on("error", () => {
      if (!done) {
        done = true;
        reject(new HttpError(400, "Invalid request."));
      }
    });
  });
}

/* ============ RATE LIMITING (in memory) ============ */
const buckets = new Map();

function rateLimited(key, max, windowMs) {
  const now = Date.now();
  const entry = buckets.get(key);
  if (!entry || entry.reset <= now) {
    buckets.set(key, { count: 1, reset: now + windowMs });
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}

// Organizer-code guessing: lock an IP out after repeated wrong codes.
const authFails = new Map();
const AUTH_MAX_FAILS = 8;
const AUTH_LOCK_MS = 10 * 60 * 1000;

function authLocked(ip) {
  const e = authFails.get(ip);
  return Boolean(e && e.until > Date.now());
}

function noteAuthResult(ip, ok) {
  if (ok) {
    authFails.delete(ip);
    return;
  }
  const e = authFails.get(ip) || { count: 0, until: 0 };
  e.count += 1;
  if (e.count >= AUTH_MAX_FAILS) {
    e.until = Date.now() + AUTH_LOCK_MS;
    e.count = 0;
  }
  authFails.set(ip, e);
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.reset <= now) buckets.delete(k);
  for (const [k, v] of authFails) if (v.until <= now && v.count === 0) authFails.delete(k);
}, 60 * 1000).unref();

/* ============ APPS SCRIPT RELAY ============ */
// Apps Script web apps have ONE url and no path routing, so every call goes
// to the same /exec url with an { action } field in the body.
async function callScript(payload) {
  if (!APPS_SCRIPT_URL) {
    throw new HttpError(503, "The ticketing service is not configured yet.");
  }

  let response;
  try {
    response = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      // text/plain avoids a CORS preflight; Apps Script reads the raw body.
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify(payload),
      redirect: "follow",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
    });
  } catch (err) {
    console.error("Apps Script request failed:", err.message);
    throw new HttpError(502, "The ticketing service could not be reached. Please try again.");
  }

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    console.error("Apps Script returned non-JSON (status " + response.status + "):", text.slice(0, 200));
    throw new HttpError(
      502,
      "The ticketing service returned an unexpected reply. Check the Apps Script deployment settings."
    );
  }
}

/* ============ STUDENT ALLOWLIST (optional) ============ */
let validStudents = null;

async function loadStudents() {
  try {
    const list = JSON.parse(await fsp.readFile(STUDENTS_FILE, "utf8"));
    if (Array.isArray(list)) {
      validStudents = new Set(list.map((n) => String(n).trim()));
      console.log(`Student allowlist loaded: ${validStudents.size} registration numbers.`);
    }
  } catch (err) {
    if (err.code !== "ENOENT") console.warn("Could not read students.json:", err.message);
    console.log("No student allowlist found: any 9-digit registration number is accepted.");
  }
}

/* ============ ROUTE HANDLERS ============ */
async function handleRegister(req, res) {
  if (process.env.REGISTRATION_CLOSED === "1") {
    return sendJson(res, 403, { ok: false, message: "Registration is closed." });
  }

  const ip = clientIp(req);
  if (rateLimited("register:" + ip, 10, 60 * 1000)) {
    return sendJson(res, 429, { ok: false, message: "Too many attempts. Please wait a minute and try again." });
  }

  const body = await readJson(req);
  const regno = String(body.registration_number || "").trim();

  if (validStudents && !validStudents.has(regno)) {
    return sendJson(res, 403, {
      ok: false,
      message: "This registration number is not on the AASTMT student list. Check it, or contact the organizers."
    });
  }

  const result = await callScript({
    action: "register",
    name: body.name,
    registration_number: body.registration_number,
    email: body.email,
    branch: body.branch
  });

  // Apps Script always answers HTTP 200, so turn failures into real 400s.
  if (!result.ok) {
    return sendJson(res, 400, { ok: false, message: result.message || "Registration failed." });
  }
  sendJson(res, 200, result);
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (authLocked(ip)) {
    return sendJson(res, 429, { ok: false, result: "locked", message: "Too many wrong codes. Try again in a few minutes." });
  }
  if (rateLimited("auth:" + ip, 30, 60 * 1000)) {
    return sendJson(res, 429, { ok: false, message: "Too many requests. Slow down." });
  }

  const code = String(req.headers["x-checkin-pin"] || "").trim();
  if (!code) {
    return sendJson(res, 401, { ok: false, result: "unauthorized", message: "Enter your organizer code." });
  }

  const result = await callScript({ action: "login", code });
  noteAuthResult(ip, result.ok === true);
  sendJson(res, result.ok ? 200 : 401, result);
}

async function handleCheckIn(req, res) {
  const ip = clientIp(req);
  if (authLocked(ip)) {
    return sendJson(res, 429, { ok: false, result: "locked", message: "Too many wrong codes. Try again in a few minutes." });
  }
  if (rateLimited("scan:" + ip, 120, 60 * 1000)) {
    return sendJson(res, 429, { ok: false, message: "Too many requests. Slow down." });
  }

  const code = String(req.headers["x-checkin-pin"] || "").trim();
  if (!code) {
    return sendJson(res, 401, { ok: false, result: "unauthorized", message: "Enter your organizer code." });
  }

  const body = await readJson(req);
  const token = String(body.ticketToken || body.token || "").trim();
  if (!token) {
    return sendJson(res, 400, { ok: false, message: "No ticket was provided." });
  }

  const result = await callScript({ action: "scan", code, token });
  noteAuthResult(ip, result.result !== "unauthorized");
  sendJson(res, result.result === "unauthorized" ? 401 : 200, result);
}

async function servePage(res, file) {
  try {
    const content = await fsp.readFile(path.join(ROOT, file));
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      ...SECURITY_HEADERS,
      ...(file === "checkin.html" ? { "X-Robots-Tag": "noindex, nofollow" } : {})
    });
    res.end(content);
  } catch {
    sendJson(res, 404, { ok: false, message: "Not found." });
  }
}

/* ============ SERVER ============ */
const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, "http://localhost");

    if (req.method === "GET" || req.method === "HEAD") {
      if (PAGES[pathname]) return await servePage(res, PAGES[pathname]);

      if (pathname === "/event-status") {
        return sendJson(res, 200, {
          ...EVENT,
          registrationOpen: process.env.REGISTRATION_CLOSED !== "1"
        });
      }
      if (pathname === "/robots.txt") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("User-agent: *\nDisallow: /checkin\nDisallow: /checkin.html\nDisallow: /organizer\n");
      }
      return sendJson(res, 404, { ok: false, message: "Not found." });
    }

    if (req.method === "POST") {
      if (pathname === "/register") return await handleRegister(req, res);
      if (pathname === "/login") return await handleLogin(req, res);
      if (pathname === "/checkin") return await handleCheckIn(req, res);
      return sendJson(res, 404, { ok: false, message: "Not found." });
    }

    sendJson(res, 405, { ok: false, message: "Method not allowed." });
  } catch (err) {
    if (err instanceof HttpError) {
      return sendJson(res, err.status, { ok: false, message: err.message });
    }
    console.error("Unhandled error:", err);
    if (!res.headersSent) {
      sendJson(res, 500, { ok: false, message: "Something went wrong on our side. Please try again." });
    } else {
      res.end();
    }
  }
});

// Last-resort guards so one bad request can never kill the process.
process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));
process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));

async function start() {
  if (!APPS_SCRIPT_URL) {
    console.warn("WARNING: APPS_SCRIPT_URL is not set. Registration and check-in will not work.");
  }
  await loadStudents();
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

start();
