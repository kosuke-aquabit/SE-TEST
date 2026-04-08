module.exports = async function handler(req, res) {
  if (req.method !== "DELETE") {
    res.setHeader("Allow", "DELETE");
    return res.status(405).json({ ok: false, error: "METHOD_NOT_ALLOWED" });
  }

  res.setHeader(
    "Set-Cookie",
    "sp_ut=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0"
  );
  return res.status(200).json({
    ok: true,
    message: "SESSION_CLEARED",
  });
};
