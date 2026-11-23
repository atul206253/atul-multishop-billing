
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function randomId() {
  return crypto.randomUUID();
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function safeSecretMatch(a, b) {
  const encoder = new TextEncoder();
  const aa = encoder.encode(String(a || ""));
  const bb = encoder.encode(String(b || ""));

  let difference = aa.length ^ bb.length;
  const maxLength = Math.max(aa.length, bb.length);

  for (let i = 0; i < maxLength; i++) {
    difference |= (aa[i] || 0) ^ (bb[i] || 0);
  }

  return difference === 0;
}

async function hashPassword(password, saltBytes) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return toBase64(new Uint8Array(bits));
}

export async function onRequestPost(context) {
  try {
    const { request, env } = context;

    // केवल same-origin request स्वीकार करें
    const origin = request.headers.get("Origin");
    const requestOrigin = new URL(request.url).origin;

    if (!origin || origin !== requestOrigin) {
      return json({
        success: false,
        message: "अनुमति नहीं है।"
      }, 403);
    }

    // Database binding जाँचें
    if (!env.DB) {
      console.error("ADMIN SETUP ERROR: DB binding missing");
      return json({
        success: false,
        message: "Database connection उपलब्ध नहीं है।"
      }, 500);
    }

    // Setup secret जाँचें
    if (!env.ADMIN_SETUP_SECRET) {
      console.error("ADMIN SETUP ERROR: ADMIN_SETUP_SECRET missing");
      return json({
        success: false,
        message: "Cloudflare में ADMIN_SETUP_SECRET सेट नहीं है।"
      }, 500);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "गलत JSON डेटा भेजा गया है।"
      }, 400);
    }

    const name = String(body.name || "").trim();
    const mobile = String(body.mobile || "").replace(/\D/g, "");
    const password = String(body.password || "");
    const setupSecret = String(body.setupSecret || "");

    if (!safeSecretMatch(setupSecret, env.ADMIN_SETUP_SECRET)) {
      return json({
        success: false,
        message: "Setup Secret गलत है।"
      }, 401);
    }

    if (name.length < 2 || name.length > 80) {
      return json({
        success: false,
        message: "नाम सही तरीके से भरें।"
      }, 400);
    }

    if (!/^[6-9]\d{9}$/.test(mobile)) {
      return json({
        success: false,
        message: "10 अंकों का सही मोबाइल नंबर भरें।"
      }, 400);
    }

    if (password.length < 8 || password.length > 128) {
      return json({
        success: false,
        message: "Admin Password कम से कम 8 और अधिकतम 128 अक्षरों का होना चाहिए।"
      }, 400);
    }

    // पहले से Admin मौजूद है या नहीं
    const existingAdmin = await env.DB
      .prepare("SELECT id FROM users WHERE is_admin = 1 LIMIT 1")
      .first();

    if (existingAdmin) {
      return json({
        success: false,
        message: "Admin Account पहले से बना हुआ है।"
      }, 409);
    }

    // मोबाइल नंबर पहले से मौजूद है या नहीं
    const existingUser = await env.DB
      .prepare("SELECT id FROM users WHERE mobile = ? LIMIT 1")
      .bind(mobile)
      .first();

    if (existingUser) {
      return json({
        success: false,
        message: "यह मोबाइल नंबर पहले से रजिस्टर है।"
      }, 409);
    }

    // Atul Jan Seva Kendra workspace मौजूद है या नहीं
    const workspace = await env.DB
      .prepare(
        "SELECT id FROM workspaces WHERE id = ? LIMIT 1"
      )
      .bind("atul-default-workspace")
      .first();

    if (!workspace) {
      console.error("ADMIN SETUP ERROR: Atul workspace not found");
      return json({
        success: false,
        message: "Atul Jan Seva Kendra Workspace नहीं मिला।"
      }, 500);
    }

    // Password hash तैयार करें
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const passwordSalt = toBase64(saltBytes);
    const passwordHash = await hashPassword(password, saltBytes);

    const userId = randomId();
    const membershipId = randomId();

    // Admin User और Workspace Membership एक batch में बनाएं
    const results = await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO users
          (id, name, mobile, password_hash, password_salt, status, is_admin)
        VALUES
          (?, ?, ?, ?, ?, 'active', 1)
      `).bind(
        userId,
        name,
        mobile,
        passwordHash,
        passwordSalt
      ),

      env.DB.prepare(`
        INSERT INTO workspace_memberships
          (id, workspace_id, user_id, role, status, created_at)
        VALUES
          (?, ?, ?, 'owner', 'active', CURRENT_TIMESTAMP)
      `).bind(
        membershipId,
        "atul-default-workspace",
        userId
      ),

      env.DB.prepare(`
        UPDATE workspaces
        SET owner_user_id = ?
        WHERE id = ?
          AND owner_user_id IS NULL
      `).bind(
        userId,
        "atul-default-workspace"
      )
    ]);

    console.log("ADMIN SETUP SUCCESS:", userId);

    return json({
      success: true,
      message: "Admin Account सफलतापूर्वक बन गया है। अब Login कर सकते हैं।"
    });

  } catch (error) {
    console.error("ADMIN SETUP ERROR:", error);

    return json({
      success: false,
      message: "ADMIN SETUP ERROR: " + String(error?.message || error)
    }, 500);
  }
}
