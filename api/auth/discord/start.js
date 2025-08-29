export default function handler(req, res) {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = encodeURIComponent(process.env.DISCORD_REDIRECT_URI);
  const state = Math.random().toString(36).slice(2); // simple CSRF token

  const url =
    `https://discord.com/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${clientId}` +
    `&scope=identify` +
    `&redirect_uri=${redirectUri}` +
    `&state=${state}`;

  res.writeHead(302, { Location: url }).end();
}
