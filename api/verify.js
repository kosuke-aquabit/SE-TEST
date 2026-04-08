const crypto = require("crypto");

const COOKIE_NAME = "sp_ut";
const TIME_WINDOW_SECONDS = {
  N: 300,
  Q: 180,
  L: 60,
};

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    out[key] = decodeURIComponent(val);
  });
  return out;
}

function urlsafeDecode(val) {
  return String(val).replace(/_/g, "+").replace(/-/g, "/").replace(/\./g, "=");
}

function deriveKeyAndIv(pass, salt) {
  const data00 = Buffer.concat([Buffer.from(pass, "utf8"), salt]);
  const hash = [];
  hash[0] = crypto.createHash("sha256").update(data00).digest();
  for (let i = 1; i < 3; i += 1) {
    hash[i] = crypto
      .createHash("sha256")
      .update(Buffer.concat([hash[i - 1], data00]))
      .digest();
  }
  const derived = Buffer.concat(hash);
  return {
    key: derived.subarray(0, 32),
    iv: derived.subarray(32, 48),
  };
}

function decryptSmartPlateParams(hs, pass) {
  try {
    const base64Str = urlsafeDecode(hs);
    const rawData = Buffer.from(base64Str, "base64");
    if (rawData.length < 17) return null;

    const salt = rawData.subarray(0, 16);
    const ctBase64 = rawData.subarray(16).toString("ascii");
    const cipherBytes = Buffer.from(ctBase64, "base64");
    const { key, iv } = deriveKeyAndIv(pass, salt);

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(cipherBytes, undefined, "utf8");
    decrypted += decipher.final("utf8");

    const parsed = JSON.parse(decrypted);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}

function validate(params, sessionUserToken) {
  if (!params || typeof params !== "object") {
    return { ok: false, code: "DECRYPT_FAILED", status: 400 };
  }
  if (!params.ut || typeof params.ut !== "string") {
    return { ok: false, code: "INVALID_UT", status: 400 };
  }
  if (!Number.isInteger(params.readtime)) {
    return { ok: false, code: "INVALID_READTIME", status: 400 };
  }
  if (!params.atp || typeof params.atp !== "string") {
    return { ok: false, code: "INVALID_ATP", status: 400 };
  }

  const now = Math.floor(Date.now() / 1000);
  const elapsed = now - params.readtime;
  const maxWindow = TIME_WINDOW_SECONDS[params.atp] ?? 300;
  if (elapsed < 0 || elapsed > maxWindow) {
    return { ok: false, code: "EXPIRED", status: 410, elapsed, maxWindow };
  }

  if (sessionUserToken && sessionUserToken !== params.ut) {
    return { ok: false, code: "USER_MISMATCH", status: 403 };
  }

  return { ok: true };
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "METHOD_NOT_ALLOWED" });
  }

  const decryptKey = process.env.SP_DECRYPT_KEY;
  if (!decryptKey) {
    return res.status(500).json({
      ok: false,
      error: "MISSING_ENV",
      message: "SP_DECRYPT_KEY が未設定です。",
    });
  }

  const hs = req.body && typeof req.body.hs === "string" ? req.body.hs : "";
  if (!hs) {
    return res.status(400).json({ ok: false, error: "MISSING_HS" });
  }

  const params = decryptSmartPlateParams(hs, decryptKey);
  const cookies = parseCookies(req.headers.cookie || "");
  const sessionUt = cookies[COOKIE_NAME];
  const validation = validate(params, sessionUt);

  if (!validation.ok) {
    return res.status(validation.status).json({
      ok: false,
      error: validation.code,
      detail: {
        elapsed: validation.elapsed,
        maxWindow: validation.maxWindow,
      },
      params,
    });
  }

  if (!sessionUt) {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${encodeURIComponent(params.ut)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=86400`
    );
  }

  return res.status(200).json({
    ok: true,
    message: "ACCESS_ALLOWED",
    sessionBound: !sessionUt,
    params,
  });
};
