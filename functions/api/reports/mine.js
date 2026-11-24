
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");
    if (index === -1) continue;

    const key = cookie.slice(0, index).trim();
    const value = cookie.slice(index + 1).trim();

    if (key === name) return decodeURIComponent(value);
  }

  return null;
}

async function sha256Base64(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);

  let binary = "";
  for (const byte of new Uint8Array(hash)) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({ success: false, message: "Database binding नहीं मिला।" }, 500);
    }

    const token = getCookie(request, "session");

    if (!token) {
      return json({ success: false, message: "कृपया पहले Login करें।" }, 401);
    }

    const tokenHash = await sha256Base64(token);

    const session = await env.DB.prepare(`
      SELECT s.user_id, u.name, u.mobile
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND s.expires_at > datetime('now')
        AND u.status = 'active'
      LIMIT 1
    `).bind(tokenHash).first();

    if (!session) {
      return json({ success: false, message: "Session समाप्त हो गया है।" }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        r.id,
        r.workspace_id,
        r.bill_id,
        r.reason,
        r.details,
        r.status,
        r.admin_note,
        r.created_at,
        r.reviewed_at,
        w.name AS workspace_name,
        admin.name AS admin_name
      FROM operator_reports r
      LEFT JOIN workspaces w ON w.id = r.workspace_id
      LEFT JOIN users admin ON admin.id = r.reviewed_by
      WHERE r.reported_user_id = ?
      ORDER BY r.created_at DESC
    `).bind(session.user_id).all();

    return json({
      success: true,
      reports: result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      message: "Reports लोड करने में समस्या हुई।",
      error: error.message
    }, 500);
  }
}
