// CommonJS version (no `export default` anywhere)
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

    // 3) ALLOWLIST check
    const allow = (process.env.ALLOWLIST || "")
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);

    if (!allow.includes(user.id)) {
      return res.status(403).send(
        `Access denied. Your Discord ID (${user.id}) is not on the allowlist.`
      );
    }

    // 4) Success page
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(200).send(
      `<h1>Logged in ✔</h1>
       <p>User: <strong>${user.username || "(no name)"} (${user.id})</strong></p>
       <p>Allowlist check passed.</p>`
    );
  } catch (err) {
    res.status(500).send("Callback error: " + (err?.message || String(err)));
  }
};
