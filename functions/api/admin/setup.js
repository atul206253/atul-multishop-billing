
const json = (data, status = 200, headers = {}) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
};

function normalizeMobile(value) {
  let mobile = String(value || "").replace(/\D/g, "");

  if (mobile.startsWith("91") && mobile.length === 12) {
    mobile = mobile.slice(2);
  }

  return mobile;
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
      salt: salt,
      iterations: 150000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return toBase64(new Uint8Array(bits));
}

function safeSecretMatch(input, actual) {
  const encoder = new TextEncoder();
  const a = encoder.encode(input);
  const b = encoder.encode(actual);

  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    // Check request origin
    const origin = request.headers.get("Origin");

    if (!origin || origin !== new URL(request.url).origin) {
      return json({
        success: false,
        message: "Invalid request origin."
      }, 403);
    }

    // Check database
    if (!env.DB) {
      console.error("ADMIN SETUP: DB binding missing");

      return json({
        success: false,
        message: "Database connection नहीं मिला।"
      }, 500);
    }

    // Check secret
    if (!env.ADMIN_SETUP_SECRET) {
      console.error("ADMIN SETUP: Secret missing");

      return json({
        success: false,
        message: "ADMIN_SETUP_SECRET उपलब्ध नहीं है।"
      }, 500);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Invalid JSON data."
      }, 400);
    }

    const setupSecret = String(body.setupSecret || "");
    const name = String(body.name || "").trim();
    const mobile = normalizeMobile(body.mobile);
    const password = String(body.password || "");

    // Verify setup secret
    if (!safeSecretMatch(setupSecret, env.ADMIN_SETUP_SECRET)) {
      return json({
        success: false,
        message: "Setup Secret गलत है।"
      }, 403);
    }

    // Validate name
    if (name.length < 2 || name.length > 80) {
      return json({
        success: false,
        message: "नाम 2 से 80 अक्षरों का होना चाहिए।"
      }, 400);
    }

    // Validate mobile
    if (!/^[6-9]\d{9}$/.test(mobile)) {
      return json({
        success: false,
        message: "सही 10 अंकों का मोबाइल नंबर डालें।"
      }, 400);
    }

    // Validate password
    if (password.length < 12 || password.length > 128) {
      return json({
        success: false,
        message: "Admin Password 12 से 128 अक्षरों का होना चाहिए।"
      }, 400);
    }

    // Check whether an Admin already exists
    const existingAdmin = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE is_admin = 1
      LIMIT 1
    `).first();

    if (existingAdmin) {
      return json({
        success: false,
        message: "Admin अकाउंट पहले से बना हुआ है।"
      }, 409);
    }

    // Check whether mobile is already registered
    const existingUser = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE mobile = ?
      LIMIT 1
    `).bind(mobile).first();

    if (existingUser) {
      return json({
        success: false,
        message: "यह मोबाइल नंबर पहले से Registered है।"
      }, 409);
    }

    // Generate secure password hash
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const passwordHash = await hashPassword(password, salt);

    const userId = crypto.randomUUID();
    const saltBase64 = toBase64(salt);

    // Create first Admin
    const result = await env.DB.prepare(`
      INSERT INTO users
        (
          id,
          name,
          mobile,
          password_hash,
          password_salt,
          status,
          is_admin
        )
      VALUES (?, ?, ?, ?, ?, 'active', 1)
    `).bind(
      userId,
      name,
      mobile,
      passwordHash,
      saltBase64
    ).run();

    if (!result.success) {
      throw new Error("Admin database insert failed");
    }

    console.log("ADMIN SETUP: First admin created successfully");

    return json({
      success: true,
      message: "पहला Admin अकाउंट सफलतापूर्वक बन गया।",
      admin: {
        name: name,
        mobile: mobile
      }
    }, 201);

  } catch (error) {
    // Detailed error only in Cloudflare Logs
    console.error("ADMIN SETUP ERROR:", error);

    return json({
      success: false,
      message: "Admin Setup में समस्या हुई। Cloudflare Logs चेक करें।"
    }, 500);
  }
}
