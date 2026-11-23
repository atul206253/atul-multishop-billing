
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

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return json({ success: false, message: "Database binding नहीं मिला।" }, 500);
    }

    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json({ success: false, message: "अनुमति नहीं है।" }, 403);
    }

    const token = getCookie(request, "session");
    if (!token) {
      return json({ success: false, message: "कृपया Login करें।" }, 401);
    }

    const tokenHash = await sha256(token);

    const admin = await env.DB.prepare(`
      SELECT s.user_id, s.expires_at, u.is_admin, u.status
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
      return json({ success: false, message: "Login समाप्त हो गया है।" }, 401);
    }

    if (Number(admin.is_admin) !== 1) {
      return json({ success: false, message: "केवल Main Admin को अनुमति है।" }, 403);
    }

    const body = await request.json();
    const userId = String(body.userId || "").trim();
    const newStatus = String(body.status || "").trim();

    if (!userId) {
      return json({ success: false, message: "User ID जरूरी है।" }, 400);
    }

    if (!["active", "suspended", "deleted"].includes(newStatus)) {
      return json({ success: false, message: "गलत Status दिया गया है।" }, 400);
    }

    if (userId === admin.user_id) {
      return json({ success: false, message: "आप अपना Admin अकाउंट बंद नहीं कर सकते।" }, 400);
    }

    const target = await env.DB.prepare(`
      SELECT id, name, mobile, status, is_admin
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(userId).first();

    if (!target) {
      return json({ success: false, message: "User नहीं मिला।" }, 404);
    }

    if (Number(target.is_admin) === 1) {
      return json({ success: false, message: "दूसरे Admin का Status नहीं बदल सकते।" }, 403);
    }

    if (target.status === newStatus) {
      return json({ success: true, message: "यह Status पहले से लागू है।" });
    }

    const details = JSON.stringify({
      target_user_id: target.id,
      target_name: target.name,
      target_mobile: target.mobile,
      old_status: target.status,
      new_status: newStatus
    });

    await env.DB.batch([
      env.DB.prepare(`
        UPDATE users
        SET status = ?
        WHERE id = ? AND is_admin = 0
      `).bind(newStatus, userId),

      env.DB.prepare(`
        INSERT INTO audit_logs
          (user_id, workspace_id, action, details, created_at)
        VALUES (?, NULL, ?, ?, datetime('now'))
      `).bind(
        admin.user_id,
        "operator_status_changed",
        details
      )
    ]);

    return json({
      success: true,
      message: "Operator का Status सफलतापूर्वक बदल गया।",
      user: {
        id: target.id,
        name: target.name,
        status: newStatus
      }
    });

  } catch (error) {
    return json({
      success: false,
      message: "Operator Status बदलने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
