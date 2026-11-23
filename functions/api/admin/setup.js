

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });

function normalizeMobile(value) {
  let mobile = String(value || "").replace(/\D/g, "");
  if (mobile.startsWith("91") && mobile.length === 12) {
    mobile = mobile.slice(2);
  }
  return mobile;
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
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
      iterations: 150000,
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

    if (!origin || origin !== new URL(request.url).origin) {
      return json({ success: false, message: "Invalid request origin." }, 403);
    }

    if (!env.DB || !env.ADMIN_SETUP_SECRET) {
      return json({ success: false, message: "Server configuration missing." }, 500);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({ success: false, message: "Invalid JSON." }, 400);
    }

    const setupSecret = String(body.setupSecret || "");
    const name = String(body.name || "").trim();
    const mobile = normalizeMobile(body.mobile);
    const password = String(body.password || "");

    if (setupSecret !== env.ADMIN_SETUP_SECRET) {
      return json({ success: false, message: "Setup Secret गलत है।" }, 403);
    }

    if (name.length < 2 || name.length > 80) {
      return json({ success: false, message: "नाम सही डालें।" }, 400);
    }

    if (!/^[6-9]\d{9}$/.test(mobile)) {
      return json({ success: false, message: "सही 10 अंकों का मोबाइल नंबर डालें।" }, 400);
    }

    if (password.length < 12 || password.length > 128) {
      return json({ success: false, message: "Admin Password कम से कम 12 अक्षरों का होना चाहिए।" }, 400);
    }

    // Only allow the first Admin to be created.
    const existingAdmin = await env.DB.prepare(`
      SELECT id FROM users WHERE is_admin = 1 LIMIT 1
    `).first();

    if (existingAdmin) {
      return json({ success: false, message: "Admin पहले से बना हुआ है।" }, 409);
    }

    const existingUser = await env.DB.prepare(`
      SELECT id FROM users WHERE mobile = ? LIMIT 1
    `).bind(mobile).first();

    if (existingUser) {
      return json({ success: false, message: "यह मोबाइल नंबर पहले से Registered है।" }, 409);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const userId = crypto.randomUUID();

    await env.DB.prepare(`
      INSERT INTO users
        (id, name, mobile, password_hash, password_salt, status, is_admin)
      VALUES (?, ?, ?, ?, ?, 'active', 1)
    `).bind(
      userId,
      name,
      mobile,
      passwordHash,
      toBase64(salt)
    ).run();

    return json({
      success: true,
      message: "पहला Admin अकाउंट सफलतापूर्वक बन गया। अब इस Setup API को बंद कर दें।"
    }, 201);

  } catch (error) {
    return json({
      success: false,
      message: "Admin Setup में समस्या हुई।"
    }, 500);
  }
}
