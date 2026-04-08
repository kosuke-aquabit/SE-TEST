const crypto = require("crypto");

const hs =
  "MDEyMzQ1Njc4OWFiY2RlZmJJTVVvdnRwMmxMLzZFT1N2SmJiZERiRldFbFgwQnFIUDZzMWhGZ0wvQ21URUdjZGQwbHZ6OTE5RGFhc1RScmh6QXNnVGdlUk5zVUkySitjdXRWUEk5cHlWMnY4aXh5ZFJIK0Z3aG10MGFxTTBUWUZpTGdVUjZzVHp5M0dhbk51S0diVHVuQlR4T2xrazAwejdYNExFMUFaMXdwTGFvdW9DMTE1Qmh5N0dDWnQ5aEJKaVhicmNJYjlpSUZmVDViMFMvakx6QnZHMU5EdmpaU252RzJXM0E9PQ..";
const pass = "smartplate-test-key-2026";

const expected =
  '{"pi":"SE.10015.0000001","cid":32132,"ut":"700116ae3eab661ac1f94b5ad21182c881322c573e00355aa2b5f19c854ead58","readtime":1512126959,"id":322405,"atp":"N"}';

function urlsafeDecode(val) {
  return val.replace(/_/g, "+").replace(/-/g, "/").replace(/\./g, "=");
}

function deriveKeyAndIv(passphrase, salt) {
  const data00 = Buffer.concat([Buffer.from(passphrase, "utf8"), salt]);
  const hash = [];
  hash[0] = crypto.createHash("sha256").update(data00).digest();
  for (let i = 1; i < 3; i += 1) {
    hash[i] = crypto
      .createHash("sha256")
      .update(Buffer.concat([hash[i - 1], data00]))
      .digest();
  }
  const derived = Buffer.concat(hash);
  return { key: derived.subarray(0, 32), iv: derived.subarray(32, 48) };
}

function decryptSmartPlateParams(hsParam, passphrase) {
  const base64Str = urlsafeDecode(hsParam);
  const rawData = Buffer.from(base64Str, "base64");
  const salt = rawData.subarray(0, 16);
  const ctBase64 = rawData.subarray(16).toString("ascii");
  const cipherBytes = Buffer.from(ctBase64, "base64");
  const { key, iv } = deriveKeyAndIv(passphrase, salt);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(cipherBytes, undefined, "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

const actual = JSON.stringify(decryptSmartPlateParams(hs, pass));
if (actual !== expected) {
  console.error("NG");
  console.error("actual  :", actual);
  console.error("expected:", expected);
  process.exit(1);
}
console.log("OK: テストベクタ一致");
