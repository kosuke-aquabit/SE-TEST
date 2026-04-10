const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

// Upstash Redis クライアント（環境変数 KV_REST_API_URL / KV_REST_API_TOKEN を使用）
const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

// 使用済み id の TTL（秒）: 十分長く保持して再利用を防ぐ（7日間）
const USED_ID_TTL_SECONDS = 60 * 60 * 24 * 7;

// atp 別の readtime 許容ウィンドウ（秒）
const TIME_WINDOW_SECONDS = {
  N: 300, // NFC: 5分
  Q: 180, // QR: 3分
  L: 60,  // Link: 1分
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

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "METHOD_NOT_ALLOWED" });
  }

  // --- 環境変数チェック ---
  const decryptKey = process.env.SP_DECRYPT_KEY;
  if (!decryptKey) {
    return res.status(500).json({
      ok: false,
      error: "MISSING_ENV",
      message: "SP_DECRYPT_KEY が未設定です。",
    });
  }
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    return res.status(500).json({
      ok: false,
      error: "MISSING_ENV",
      message: "KV_REST_API_URL または KV_REST_API_TOKEN が未設定です。",
    });
  }

  // --- hs パラメータ取得 ---
  const hs = req.body && typeof req.body.hs === "string" ? req.body.hs : "";
  if (!hs) {
    return res.status(400).json({ ok: false, error: "MISSING_HS" });
  }

  // --- 復号 ---
  const params = decryptSmartPlateParams(hs, decryptKey);
  if (!params || typeof params !== "object") {
    return res.status(400).json({ ok: false, error: "DECRYPT_FAILED" });
  }

  // --- 基本パラメータ検証 ---
  if (!params.ut || typeof params.ut !== "string") {
    return res.status(400).json({ ok: false, error: "INVALID_UT", params });
  }
  if (!Number.isInteger(params.readtime)) {
    return res.status(400).json({ ok: false, error: "INVALID_READTIME", params });
  }
  if (!params.atp || typeof params.atp !== "string") {
    return res.status(400).json({ ok: false, error: "INVALID_ATP", params });
  }
  if (!Number.isInteger(params.id)) {
    return res.status(400).json({ ok: false, error: "INVALID_ID", params });
  }

  // --- NFC 限定チェック ---
  if (params.atp !== "N") {
    return res.status(403).json({ ok: false, error: "NON_NFC_ACCESS", params });
  }

  // --- readtime 有効期限チェック ---
  const now = Math.floor(Date.now() / 1000);
  const elapsed = now - params.readtime;
  const maxWindow = TIME_WINDOW_SECONDS[params.atp] ?? 300;
  if (elapsed < 0 || elapsed > maxWindow) {
    return res.status(410).json({
      ok: false,
      error: "EXPIRED",
      detail: { elapsed, maxWindow },
      params,
    });
  }

  // --- 厳格パターン: id ワンタイムチェック ---
  const redisKey = `sp:used_id:${params.id}`;
  try {
    // SET NX（存在しない場合のみセット）でアトミックに使用済み登録
    const set = await redis.set(redisKey, "1", {
      nx: true,          // 存在しない場合のみ書き込む
      ex: USED_ID_TTL_SECONDS,
    });

    if (set === null) {
      // すでに使用済み → 拒否
      return res.status(409).json({
        ok: false,
        error: "ID_ALREADY_USED",
        message: "このアクセスIDはすでに使用済みです。NFCタグを再度タップしてください。",
        params,
      });
    }
  } catch (err) {
    // Redis 接続エラーはフェイルセーフ（拒否）
    console.error("Redis error:", err);
    return res.status(500).json({
      ok: false,
      error: "STORAGE_ERROR",
      message: "アクセス検証中にエラーが発生しました。",
    });
  }

  // --- 全検証通過 → アクセス許可 ---
  return res.status(200).json({
    ok: true,
    message: "ACCESS_ALLOWED",
    params,
  });
};
