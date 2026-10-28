const crypto = require("crypto");
const { sign } = require("../lib/relay");

module.exports = (req, res) => {
  const site = (process.env.SITE_URL || "").replace(/\/+$/, "");
  const guild = String((req.query && req.query.guild) || "");
  if (!/^\d{5,25}$/.test(guild)) return res.redirect(302, `${site}/result?error=${encodeURIComponent("Invalid verification link.")}`);
  const nonce = crypto.randomBytes(12).toString("hex");
  const exp = Date.now() + 10 * 60 * 1000;
  const body = `${guild}.${exp}.${nonce}`;
  const state = `${body}.${sign(process.env.PULL_RELAY_KEY, body)}`;
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", process.env.DISCORD_CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", `${site}/api/callback`);
  url.searchParams.set("scope", "identify guilds.join");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "consent");
  res.setHeader("Set-Cookie", `zv_nonce=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);
  res.redirect(302, url.toString());
};
