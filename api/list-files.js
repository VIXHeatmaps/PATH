// List objects in your user folder on Cloudflare R2 (S3-compatible)
// GET /api/list-files            -> first page (max 50)
// GET /api/list-files?cursor=... -> next page
// Returns: { items: [{key, size, lastModified}], isTruncated, cursor }
const aws4 = require("aws4");
const crypto = require("crypto");
const { URL } = require("url");

// --- session helpers (same as other endpoints) ---
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

// --- tiny XML parser for S3 ListObjectsV2 output ---
function parseListXml(xml) {
  const items = [];
  const contentsRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  let m;
  while ((m = contentsRe.exec(xml))) {
    const block = m[1];
    const key = (block.match(/<Key>([^<]+)<\/Key>/) || [])[1];
    const size = parseInt((block.match(/<Size>([^<]+)<\/Size>/) || [])[1] || "0", 10);
    const lastModified = (block.match(/<LastModified>([^<]+)<\/LastModified>/) || [])[1];
    if (key) items.push({ key, size, lastModified });
  }
  const isTruncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  const nextToken = (xml.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/) || [])[1] || null;
  return { items, isTruncated, cursor: nextToken };
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET") return res.status(405).send("Method not allowed");

    // auth gate
    const secret = process.env.SESSION_SECRET || "dev-secret-change-me";
    const sessionToken = getCookie(req, "session");
    const session = verifySession(sessionToken, secret);
    if (!session) return res.status(401).send("Unauthorized");

    // env
    const endpoint = process.env.R2_ENDPOINT;
    const bucket = process.env.R2_BUCKET;
    const accessKeyId = process.env.R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
      return res.status(500).send("R2 environment variables missing");
    }

    // build ListObjectsV2 request for this user's folder
    const host = new URL(endpoint).host;
    const params = new URLSearchParams({
      "list-type": "2",
      "prefix": `${session.sub}/`,
      "max-keys": "50"
    });
    const cursor = String(req.query.cursor || "").trim();
    if (cursor) params.set("continuation-token", cursor);

    const path = `/${bucket}?${params.toString()}`;
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
      return res.status(resp.status).send(`List error: ${t}`);
    }
    const xml = await resp.text();
    const data = parseListXml(xml);
    res.status(200).json(data);
  } catch (err) {
    res.status(500).send("List error: " + (err?.message || String(err)));
  }
};
