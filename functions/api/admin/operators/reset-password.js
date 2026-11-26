
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const item = cookie.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : null;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  let binary = "";
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return toBase64(new Uint8Array(bits));
}

export async function onRequestPost({ request, env }) {
  try {
    const origin = request.headers.get("Origin");

    if (origin && origin !== new URL(request.url).origin) {
      return json({
        success: false,
        message: "Invalid request origin."
      }, 403);
    }

    if (!env.DB) {
      return json({
        success: false,
        message: "Database binding नहीं मिला।"
      }, 500);
    }

    // Main Admin का Login Session जाँचें
    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया Login करें।"
      }, 401);
    }

    const tokenHash = await sha256(token);

    const admin = await env.DB.prepare(`
      SELECT
        s.user_id,
        s.expires_at,
        u.is_admin,
        u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (
      !admin ||
      !admin.expires_at ||
      new Date(admin.expires_at).getTime() <= Date.now() ||
      admin.status !== "active"
    ) {
      return json({
        success: false,
        message: "Login समाप्त हो गया है।"
      }, 401);
    }

    if (Number(admin.is_admin) !== 1) {
      return json({
        success: false,
        message: "केवल Main Admin पासवर्ड बदल सकता है।"
      }, 403);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Invalid JSON."
      }, 400);
    }

    const userId = String(body.userId || "").trim();
    const newPassword = String(body.newPassword || "");
    const confirmPassword = String(body.confirmPassword || "");

    if (!userId) {
      return json({
        success: false,
        message: "Operator की जानकारी नहीं मिली।"
      }, 400);
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return json({
        success: false,
        message: "पासवर्ड 8 से 128 अक्षरों के बीच होना चाहिए।"
      }, 400);
    }

    if (newPassword !== confirmPassword) {
      return json({
        success: false,
        message: "दोनों पासवर्ड एक जैसे नहीं हैं।"
      }, 400);
    }

    // Main Admin का पासवर्ड इस API से नहीं बदलेगा
    if (userId === admin.user_id) {
      return json({
        success: false,
        message: "Main Admin का पासवर्ड यहाँ से नहीं बदला जा सकता।"
      }, 403);
    }

    const target = await env.DB.prepare(`
      SELECT id, is_admin
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(userId).first();

    if (!target) {
      return json({
        success: false,
        message: "Operator अकाउंट नहीं मिला।"
      }, 404);
    }

    if (Number(target.is_admin) === 1) {
      return json({
        success: false,
        message: "Main Admin का पासवर्ड यहाँ से नहीं बदला जा सकता।"
      }, 403);
    }

    // नया Random Salt और PBKDF2 Hash
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordSalt = toBase64(salt);
    const passwordHash = await hashPassword(newPassword, salt);

    // पासवर्ड अपडेट और पुराने Sessions हटाना
    await env.DB.batch([
      env.DB.prepare(`
        UPDATE users
        SET password_hash = ?, password_salt = ?
        WHERE id = ? AND COALESCE(is_admin, 0) != 1
      `).bind(passwordHash, passwordSalt, userId),

      env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
      `).bind(userId)
    ]);

    return json({
      success: true,
      message: "Operator का पासवर्ड सफलतापूर्वक बदल गया है। पुराने Login Sessions समाप्त कर दिए गए हैं।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "पासवर्ड बदलने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
