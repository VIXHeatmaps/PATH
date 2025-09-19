// /api/chat.js  — server proxy for your bots
// - Verifies your Discord session cookie
// - Pulls reference files (text only, size-limited) from R2
// - Sends refs + your message to OpenAI and returns the reply
//
// POST JSON:
// { "bot": "any-label", "message": "prompt", "keys": ["<userId>/path/to/file.txt", ...] }
//
// Env vars: OPENAI_API_KEY (required), OPENAI_MODEL (optional, default gpt-4o-mini)
// Also uses: R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, SESSION_SECRET

const aws4 = require("aws4");
const crypto = require("crypto");
const { URL } = require("url");

// -------- session helpers (same as other endpoints) --------
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const p of parts) if (p.startsWith(name + "=")) return decodeURIComponent(p.slice(name.length + 1));
  return null;
}
function b64uToStr(b) {
  const base64 = b.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64").toString("utf8");
}
function verifySession(token, secret) {
  if (!token) return null;
  const [bodyB64u, sig] = token.split(".");
  if (!bodyB64u || !sig) return null;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(bodyB64u)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  if (sig !== expected) return null;
  let payload;
  try { payload = JSON.parse(b64uToStr(bodyB64u)); } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) return null;
  return payload; // { sub, name, iat, exp }
}

// -------- R2 text fetcher (guarded) --------
const TEXT_EXT = /\.(txt|md|markdown|csv|tsv|json|log|html|js|ts|css|py|java|rb|go|rs|c|cpp|h|cs)$/i;
const MAX_BYTES = parseInt(process.env.REF_MAX_BYTES || "400000", 10); // ~400 KB per file

async function getR2Text(key) {
  if (!TEXT_EXT.test(key)) {
    return { key, text: null, note: "skipped (non-text file type)" };
  }
  const endpoint = process.env.R2_ENDPOINT;
  const bucket = process.env.R2_BUCKET;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  const host = new URL(endpoint).host;
  const path = `/${bucket}/${key}`;

  const opts = {
    host,
    path,
    service: "s3",
    region: "auto",
    method: "GET",
    headers: {}
  };
  aws4.sign(opts, { accessKeyId, secretAccessKey });

  const resp = await fetch(`https://${host}${path}`, { headers: opts.headers });
  if (!resp.ok) {
    const t = await resp.text();
    return { key, text: null, note: `fetch failed: ${resp.status} ${t.slice(0,200)}` };
  }

  const buf = Buffer.from(await resp.arrayBuffer());
  const limit = Math.min(buf.length, MAX_BYTES);
  const slice = buf.slice(0, limit).toString("utf8");
  const truncated = buf.length > limit ? "\n\n[...truncated...]" : "";
  return { key, text: slice + truncated, note: null };
}

// -------- OpenAI call --------
async function openaiChat(messages) {
  const apiKey = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
  if (!apiKey) throw new Error("OPENAI_API_KEY missing");

  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
    body: JSON.stringify({ model, temperature: 0.2, messages })
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`OpenAI error ${r.status}: ${t}`);
  }
  const j = await r.json();
  return j.choices?.[0]?.message?.content || "";
}

// -------- handler --------
module.exports = async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).send("Method not allowed");

    const secret = process.env.SESSION_SECRET || "dev-secret-change-me";
    const session = verifySession(getCookie(req, "session"), secret);
    if (!session) return res.status(401).send("Unauthorized");

    const body = await readJson(req);
    const bot = String(body.bot || "default");
    const userMsg = String(body.message || "").trim();
    const keys = Array.isArray(body.keys) ? body.keys.map(String) : [];
    if (!userMsg) return res.status(400).send("message required");

    // enforce per-user keys
    const prefix = session.sub + "/";
    for (const k of keys) {
      if (!k.startsWith(prefix)) {
        return res.status(403).send(`Forbidden key: ${k} (must start with ${prefix})`);
      }
    }

    // fetch references
    const refs = [];
    for (const k of keys) {
      const r = await getR2Text(k);
      if (r.text) refs.push(r);
    }

    // build prompt
    const messages = [];
    messages.push({
      role: "system",
      content:
        `You are the "${bot}" bot. Use the provided reference files when relevant. ` +
        `If something isn't covered, say you don't know rather than guessing. ` +
        `When you use a reference, cite the filename.`
    });
    for (const r of refs) {
      messages.push({ role: "system", content: `Reference (${r.key}):\n${r.text}` });
    }
    messages.push({ role: "user", content: userMsg });

    const reply = await openaiChat(messages);
    res.status(200).json({ reply, used: refs.map(r => r.key) });
  } catch (err) {
    res.status(500).send("Chat error: " + (err?.message || String(err)));
  }
};

// read JSON body helper (Vercel Node)
function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("Invalid JSON")); } });
    req.on("error", reject);
  });
}
