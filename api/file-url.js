// Secure presigned GET for Cloudflare R2 (S3-compatible)
// Requires a valid HttpOnly "session" cookie (set by /api/auth/discord/callback)
// Query:  /api/file-url?key=<object-key>
// Returns: { url }  // short-lived GET URL to download the object

const aws4 = require("aws4");
const crypto = require("crypto");
const { URL } = require("url");

// --- tiny helpers (same scheme as upload-url) ---
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

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET") return res.status(405).send("Method not allowed");

    // auth gate
    const secret = process.env.SESSION_SECRET || "dev-secret-change-me";
    const sessionToken = getCookie(req, "session");
    const session = verifySession(sessionToken, secret);
    if (!session) return res.status(401).send("Unauthorized");

    // input
    const key = String(req.query.key || "").trim();
    if (!key) return res.status(400).send("key required");

    // enforce user folder: only allow keys under "<userId>/"
    const prefix = session.sub + "/";
    if (!key.startsWith(prefix)) {
      return res.status(403).send("Forbidden: key must start with your user folder");
    }

    // env
    const endpoint = process.env.R2_ENDPOINT;
    const bucket = process.env.R2_BUCKET;
    const accessKeyId = process.env.R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
      return res.status(500).send("R2 environment variables missing");
    }

    // build pre-signed GET
    const host = new URL(endpoint).host;
    const path = `/${bucket}/${key}`;
    const opts = {
      host,
      path,
      service: "s3",
      region: "auto",
      method: "GET",
      signQuery: true,
      expires: 300 // 5 minutes
    };

    aws4.sign(opts, { accessKeyId, secretAccessKey });
    const url = `https://${host}${opts.path}`;
    res.status(200).json({ url });
  } catch (err) {
    res.status(500).send("Presign GET error: " + (err?.message || String(err)));
  }
};
