// Secure presigned PUT for Cloudflare R2 (S3-compatible)
// Requires a valid HttpOnly "session" cookie set by /api/auth/discord/callback
const aws4 = require("aws4");
const crypto = require("crypto");
const { URL } = require("url");

// --- tiny helpers ---
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const p of parts) if (p.startsWith(name + "=")) return decodeURIComponent(p.slice(name.length + 1));
  return null;
}
function b64uToStr(b) {
  // base64url -> base64
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
  try {
    payload = JSON.parse(b64uToStr(bodyB64u));
  } catch {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) return null;
  return payload; // { sub, name, iat, exp }
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET") return res.status(405).send("Method not allowed");

    // --- auth gate ---
    const secret = process.env.SESSION_SECRET || "dev-secret-change-me";
    const sessionToken = getCookie(req, "session");
    const session = verifySession(sessionToken, secret);
    if (!session) return res.status(401).send("Unauthorized");

    const filename = String(req.query.filename || "").trim();
    const contentType = String(req.query.contentType || "application/octet-stream");
    if (!filename) return res.status(400).send("filename required");

    const endpoint = process.env.R2_ENDPOINT;
    const bucket = process.env.R2_BUCKET;
    const accessKeyId = process.env.R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
      return res.status(500).send("R2 environment variables missing");
    }

    // user-scoped key so uploads are cleanly namespaced
    const host = new URL(endpoint).host;
    const key = `${session.sub}/${Date.now()}-${filename}`;
    const path = `/${bucket}/${key}`;

    const opts = {
      host,
      path,
      service: "s3",
      region: "auto",
      method: "PUT",
      headers: { "content-type": contentType },
      signQuery: true,
      expires: 300 // 5 minutes
    };

    aws4.sign(opts, { accessKeyId, secretAccessKey });
    const url = `https://${host}${opts.path}`;
    res.status(200).json({ url, key, user: session.sub });
  } catch (err) {
    res.status(500).send("Presign error: " + (err?.message || String(err)));
  }
};
