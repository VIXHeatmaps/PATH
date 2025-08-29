// Issues a pre-signed PUT URL for Cloudflare R2 (S3-compatible) using aws4
// Query params: ?filename=<name>&contentType=<mime>
// Returns: { url, key }
const aws4 = require("aws4");
const { URL } = require("url");

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET") return res.status(405).send("Method not allowed");

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

    // Build path-style S3 URL: https://<account>.r2.cloudflarestorage.com/<bucket>/<key>
    const host = new URL(endpoint).host;
    const key = `${Date.now()}-${filename}`;
    const path = `/${bucket}/${key}`;

    // Sign a querystring (pre-signed) PUT
    const opts = {
      host,
      path,
      service: "s3",
      region: "auto",           // R2 uses 'auto'
      method: "PUT",
      headers: { "content-type": contentType },
      signQuery: true,
      expires: 300              // URL valid for 5 minutes
    };

    aws4.sign(opts, { accessKeyId, secretAccessKey });

    const url = `https://${host}${opts.path}`;
    res.status(200).json({ url, key });
  } catch (err) {
    res.status(500).send("Presign error: " + (err?.message || String(err)));
  }
};
