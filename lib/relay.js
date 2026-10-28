// Encrypt-then-MAC with HMAC-SHA256 only (stdlib on both sides: Node here, Python in the bot).
const crypto = require("crypto");

const hmac = (key, data) => crypto.createHmac("sha256", key).update(data).digest();
const keys = (secret) => {
  const master = crypto.createHash("sha256").update(secret).digest();
  return { enc: hmac(master, "zenvyx-enc"), mac: hmac(master, "zenvyx-mac") };
};
function keystream(kEnc, nonce, length) {
  const blocks = [];
  for (let i = 0; blocks.length * 32 < length; i++) {
    const ctr = Buffer.alloc(4); ctr.writeUInt32BE(i);
    blocks.push(hmac(kEnc, Buffer.concat([nonce, ctr])));
  }
  return Buffer.concat(blocks).subarray(0, length);
}
exports.seal = (secret, obj) => {
  const k = keys(secret);
  const nonce = crypto.randomBytes(16);
  const plain = Buffer.from(JSON.stringify(obj), "utf8");
  const ks = keystream(k.enc, nonce, plain.length);
  const ct = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) ct[i] = plain[i] ^ ks[i];
  const tag = hmac(k.mac, Buffer.concat([nonce, ct]));
  return Buffer.concat([nonce, ct, tag]).toString("base64url");
};
exports.open = (secret, text) => {
  const k = keys(secret);
  const raw = Buffer.from(text, "base64url");
  const nonce = raw.subarray(0, 16), tag = raw.subarray(raw.length - 32), ct = raw.subarray(16, raw.length - 32);
  if (!crypto.timingSafeEqual(tag, hmac(k.mac, Buffer.concat([nonce, ct])))) throw new Error("bad tag");
  const ks = keystream(k.enc, nonce, ct.length);
  const plain = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i++) plain[i] = ct[i] ^ ks[i];
  return JSON.parse(plain.toString("utf8"));
};
exports.sign = (secret, text) => hmac(secret, text).toString("base64url");
