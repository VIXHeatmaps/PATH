// CommonJS + sets an HttpOnly "session" cookie after allowlist passes,
// then REDIRECTS back to "/" so you see index.html.

const crypto = require("crypto");

function b64u(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signPayload(payloadObj, secret) {
  const body = b64u(JSON.stringify(payloadObj));
  const sig = crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `${body}.${sig}`;
}

module.exports = async function handler(req, res) {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("Missing ?code");

    const client_id = process.env.DISCORD_CLIENT_ID;
    const client_secret = process.env.DISCORD_CLIENT_SECRET;
    const redirect_uri = process.env.DISCORD_REDIRECT_URI;

    // 1) Exchange code for token
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id,
        client_secret,
        grant_type: "authorization_code",
        code,
        redirect_uri
      })
    });
    if (!tokenResp.ok) {
      const t = await tokenResp.text();
      return res.status(401).send("Token exchange failed: " + t);
    }
    const tokenJson = await tokenResp.json(); // { access_token, token_type, ... }

    // 2) Fetch the user
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `${tokenJson.token_type} ${tokenJson.access_token}` }
    });
    if (!userResp.ok) {
      const t = await userResp.text();
      return res.status(401).send("User fetch failed: " + t);
    }
    const user = await userResp.json(); // { id, username, ... }

    // 3) Allowlist check
    const allow = (process.env.ALLOWLIST || "")
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);
    if (!allow.includes(user.id)) {
      return res.status(403).send(
        `Access denied. Your Discord ID (${user.id}) is not on the allowlist.`
      );
    }

    // 4) Set HttpOnly session cookie (valid ~8 hours)
    const secret = process.env.SESSION_SECRET || "dev-secret-change-me";
    const now = Math.floor(Date.now() / 1000);
    const payload = { sub: user.id, name: user.username, iat: now, exp: now + 8 * 3600 };
    const token = signPayload(payload, secret);
    res.setHeader("Set-Cookie", [
      `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${8 * 3600}`
    ]);

    // 5) Redirect back to the UI
    res.writeHead(302, { Location: "/" }).end();
  } catch (err) {
    res.status(500).send("Callback error: " + (err?.message || String(err)));
  }
};
