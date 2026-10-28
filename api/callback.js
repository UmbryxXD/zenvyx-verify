const crypto = require("crypto");
const { seal, sign } = require("../lib/relay");

module.exports = async (req, res) => {
  const site = (process.env.SITE_URL || "").replace(/\/+$/, "");
  const fail = (m) => res.redirect(302, `${site}/result?error=${encodeURIComponent(m)}`);
  try {
    const q = req.query || {};
    if (q.error) return fail("You cancelled the verification.");
    const state = String(q.state || "");
    const parts = state.split(".");
    if (parts.length !== 4) return fail("Your session expired. Please click Verify again.");
    const [guild, exp, nonce, sig] = parts;
    const body = `${guild}.${exp}.${nonce}`;
    const good = sign(process.env.PULL_RELAY_KEY, body);
    const cookieNonce = ((req.headers.cookie || "").match(/zv_nonce=([a-f0-9]+)/) || [])[1];
    if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) ||
        Date.now() > Number(exp) || cookieNonce !== nonce || !q.code) return fail("Your session expired. Please click Verify again.");

    const tokRes = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code", code: String(q.code), redirect_uri: `${site}/api/callback`,
      }),
    });
    if (!tokRes.ok) return fail("Discord refused the login. (Owner: check the client secret and redirect URL.)");
    const tok = await tokRes.json();
    const meRes = await fetch("https://discord.com/api/v10/users/@me", { headers: { Authorization: `Bearer ${tok.access_token}` } });
    if (!meRes.ok) return fail("Couldn't read your Discord account.");
    const me = await meRes.json();

    const blob = seal(process.env.PULL_RELAY_KEY, {
      g: guild, u: me.id, n: me.global_name || me.username, at: tok.access_token, rt: tok.refresh_token, ex: tok.expires_in, t: Date.now(),
    });
    const hook = await fetch(`${process.env.PULL_RELAY_WEBHOOK}?wait=true`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: `ZVP1:${blob}`, username: "Zenvyx Verify", allowed_mentions: { parse: [] } }),
    });
    if (!hook.ok) return fail("Couldn't reach the bot. Please try again in a minute.");
    res.setHeader("Set-Cookie", "zv_nonce=; Path=/; Max-Age=0");
    res.redirect(302, `${site}/result?ok=1`);
  } catch (e) {
    fail("Something went wrong. Please try again.");
  }
};
