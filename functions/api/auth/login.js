const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function normalizeMobile(value) {
  let mobile = String(value || "").replace(/\D/g, "");
  if (mobile.startsWith("91") && mobile.length === 12) {
    mobile = mobile.slice(2);
  }
  return mobile;
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

  let binary = "";
  for (const byte of new Uint8Array(bits)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
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

export async function onRequestPost({ request, env }) {
  try {
    const origin = request.headers.get("Origin");

    if (origin && origin !== new URL(request.url).origin) {
      return json({ success: false, message: "Invalid request origin." }, 403);
    }

    if (!env.DB) {
      return json({ success: false, message: "Database binding missing." }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, message: "Invalid JSON." }, 400);
    }

    const mobile = normalizeMobile(body.mobile);
    const password = String(body.password || "");

    if (!/^[6-9]\d{9}$/.test(mobile)) {
      return json({ success: false, message: "सही मोबाइल नंबर डालें।" }, 400);
    }

    if (!password || password.length > 128) {
      return json({ success: false, message: "पासवर्ड डालें।" }, 400);
    }

    const user = await env.DB.prepare(`
      SELECT id, name, mobile, password_hash, password_salt, status
      FROM users
      WHERE mobile = ?
      LIMIT 1
    `).bind(mobile).first();

    // Generic message to avoid revealing whether a number is registered.
    if (!user || user.status !== "active") {
      return json({ success: false, message: "मोबाइल नंबर या पासवर्ड गलत है।" }, 401);
    }

    const salt = fromBase64(user.password_salt);
    const calculatedHash = await hashPassword(password, salt);

    if (calculatedHash !== user.password_hash) {
      return json({ success: false, message: "मोबाइल नंबर या पासवर्ड गलत है।" }, 401);
    }

    // Generate random session token; store only its hash in DB.
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    let tokenBinary = "";
    for (const byte of tokenBytes) {
      tokenBinary += String.fromCharCode(byte);
    }
    const sessionToken = btoa(tokenBinary);

    const tokenHash = await sha256(sessionToken);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    await env.DB.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(sessionId, user.id, tokenHash, expiresAt).run();

    const cookie = [
      `session=${sessionToken}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Path=/",
      "Max-Age=604800"
    ].join("; ");

    return new Response(JSON.stringify({
      success: true,
      message: "Login सफल।",
      user: {
        id: user.id,
        name: user.name,
        mobile: user.mobile
      },
      expiresAt
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie": cookie
      }
    });

  } catch (error) {
    return json({
      success: false,
      message: "Login में समस्या हुई। कृपया बाद में प्रयास करें।"
    }, 500);
  }
}
