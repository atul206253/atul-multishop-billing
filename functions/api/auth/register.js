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

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function hashPassword(password, salt) {
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
    // Basic same-origin protection
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
      return json({ success: false, message: "Invalid JSON data." }, 400);
    }

    const name = String(body.name || "").trim();
    const mobile = normalizeMobile(body.mobile);
    const password = String(body.password || "");
    const shopMode = String(body.shopMode || "");

    if (name.length < 2 || name.length > 80) {
      return json({ success: false, message: "Name 2 से 80 अक्षर का होना चाहिए।" }, 400);
    }

    if (!/^[6-9]\d{9}$/.test(mobile)) {
      return json({ success: false, message: "सही 10 अंकों का भारतीय मोबाइल नंबर डालें।" }, 400);
    }

    if (password.length < 8 || password.length > 128) {
      return json({ success: false, message: "Password कम से कम 8 अक्षरों का होना चाहिए।" }, 400);
    }

    if (!["new", "join"].includes(shopMode)) {
      return json({ success: false, message: "Registration option सही नहीं है।" }, 400);
    }

    const shopName = String(body.shopName || "").trim();
    const address = String(body.address || "").trim();
    const shopPhone = normalizeMobile(body.shopPhone || mobile);

    if (shopMode === "new" && (shopName.length < 2 || shopName.length > 100)) {
      return json({ success: false, message: "दुकान का नाम 2 से 100 अक्षरों में डालें।" }, 400);
    }

    if (shopPhone && !/^[6-9]\d{9}$/.test(shopPhone)) {
      return json({ success: false, message: "दुकान का मोबाइल नंबर सही नहीं है।" }, 400);
    }

    // Secure password hashing
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);

    const userId = crypto.randomUUID();
    const saltBase64 = toBase64(salt);

    const userInsert = env.DB.prepare(`
      INSERT INTO users (id, name, mobile, password_hash, password_salt, status)
      VALUES (?, ?, ?, ?, ?, 'active')
    `).bind(userId, name, mobile, passwordHash, saltBase64);

    if (shopMode === "join") {
      const workspaceId = "atul-default-workspace";

      const workspace = await env.DB.prepare(`
        SELECT id FROM workspaces
        WHERE id = ? AND status = 'active'
      `).bind(workspaceId).first();

      if (!workspace) {
        return json({ success: false, message: "Atul workspace नहीं मिला।" }, 500);
      }

      const membershipId = crypto.randomUUID();
      const joinRequestId = crypto.randomUUID();

      await env.DB.batch([
        userInsert,
        env.DB.prepare(`
          INSERT INTO workspace_memberships
            (id, workspace_id, user_id, role, status)
          VALUES (?, ?, ?, 'operator', 'pending')
        `).bind(membershipId, workspaceId, userId),
        env.DB.prepare(`
          INSERT INTO join_requests
            (id, user_id, workspace_id, status)
          VALUES (?, ?, ?, 'pending')
        `).bind(joinRequestId, userId, workspaceId)
      ]);

      return json({
        success: true,
        message: "Registration सफल! Atul Jan Seva Kendra में जुड़ने की Request Admin Approval के लिए भेज दी गई है।",
        status: "pending_approval"
      }, 201);
    }

    // Create a new independent shop/workspace
    const workspaceId = crypto.randomUUID();
    const membershipId = crypto.randomUUID();

    const slugBase = shopName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 40) || "shop";

    const slug = `${slugBase}-${crypto.randomUUID().slice(0, 8)}`;

    await env.DB.batch([
      userInsert,
      env.DB.prepare(`
        INSERT INTO workspaces
          (id, name, slug, owner_user_id, status)
        VALUES (?, ?, ?, ?, 'active')
      `).bind(workspaceId, shopName, slug, userId),
      env.DB.prepare(`
        INSERT INTO workspace_memberships
          (id, workspace_id, user_id, role, status)
        VALUES (?, ?, ?, 'owner', 'active')
      `).bind(membershipId, workspaceId, userId),
      env.DB.prepare(`
        INSERT INTO shop_settings
          (workspace_id, business_name, owner_name, address, phone, logo_key, services_json)
        VALUES (?, ?, ?, ?, ?, NULL, '[]')
      `).bind(workspaceId, shopName, name, address, shopPhone)
    ]);

    return json({
      success: true,
      message: "Registration सफल! आपकी नई दुकान बन गई है।",
      status: "active"
    }, 201);

  } catch (error) {
    if (error && error.message && error.message.includes("UNIQUE constraint failed")) {
      return json({
        success: false,
        message: "यह मोबाइल नंबर पहले से Registered है।"
      }, 409);
    }

    return json({
      success: false,
      message: "Registration में समस्या हुई। कृपया दोबारा कोशिश करें।"
    }, 500);
  }
}
