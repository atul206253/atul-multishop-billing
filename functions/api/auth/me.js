const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const item of cookieHeader.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
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

const clearCookie = "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({ success: false, message: "Database binding missing." }, 500);
    }

    const token = getCookie(request, "session");

    if (!token) {
      return json({ success: false, authenticated: false }, 401);
    }

    const tokenHash = await sha256(token);

    const session = await env.DB.prepare(`
      SELECT id, user_id, expires_at
      FROM sessions
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (!session) {
      return json(
        { success: false, authenticated: false },
        401,
        { "Set-Cookie": clearCookie }
      );
    }

    // Check expiration in JavaScript to avoid SQLite date-format issues.
    if (Date.parse(session.expires_at) <= Date.now()) {
      await env.DB.prepare(`
        DELETE FROM sessions WHERE id = ?
      `).bind(session.id).run();

      return json(
        { success: false, authenticated: false, message: "Session expired." },
        401,
        { "Set-Cookie": clearCookie }
      );
    }

    const user = await env.DB.prepare(`
      SELECT id, name, mobile, status
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(session.user_id).first();

    if (!user || user.status !== "active") {
      await env.DB.prepare(`
        DELETE FROM sessions WHERE id = ?
      `).bind(session.id).run();

      return json(
        { success: false, authenticated: false },
        401,
        { "Set-Cookie": clearCookie }
      );
    }

    const workspaces = await env.DB.prepare(`
      SELECT
        w.id AS workspace_id,
        w.name AS workspace_name,
        w.slug,
        m.role,
        m.status AS membership_status,
        s.business_name,
        s.owner_name,
        s.address,
        s.phone,
        s.logo_key
      FROM workspace_memberships m
      JOIN workspaces w ON w.id = m.workspace_id
      LEFT JOIN shop_settings s ON s.workspace_id = w.id
      WHERE m.user_id = ?
        AND m.status = 'active'
        AND w.status = 'active'
    `).bind(user.id).all();

    const pending = await env.DB.prepare(`
      SELECT
        jr.id,
        jr.status,
        jr.requested_at,
        w.name AS workspace_name
      FROM join_requests jr
      JOIN workspaces w ON w.id = jr.workspace_id
      WHERE jr.user_id = ?
        AND jr.status = 'pending'
    `).bind(user.id).all();

    return json({
      success: true,
      authenticated: true,
      user: {
        id: user.id,
        name: user.name,
        mobile: user.mobile
      },
      workspaces: workspaces.results || [],
      pendingRequests: pending.results || []
    });

  } catch (error) {
    return json({
      success: false,
      message: "Session जाँच में समस्या हुई।"
    }, 500);
  }
}
