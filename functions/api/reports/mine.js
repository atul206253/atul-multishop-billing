
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

async function sha256Base64(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);

  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const [key, ...value] = part.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

export async function onRequestGet({ request, env }) {
  try {
    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "Login required"
      }, 401);
    }

    const tokenHash = await sha256Base64(token);

    const session = await env.DB.prepare(`
      SELECT s.user_id
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND datetime(s.expires_at) > datetime('now')
        AND u.status = 'active'
      LIMIT 1
    `).bind(tokenHash).first();

    if (!session) {
      return json({
        success: false,
        message: "Invalid session"
      }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        r.id,
        r.workspace_id,
        r.bill_id,
        b.bill_number AS linked_bill_number,
        r.reason,
        r.details,
        r.status,
        r.admin_note,
        r.created_at,
        r.reviewed_at,
        w.name AS workspace_name
      FROM operator_reports r
      LEFT JOIN workspaces w
        ON w.id = r.workspace_id
      LEFT JOIN bills b
        ON b.id = r.bill_id
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
      message: "Reports load failed",
      error: error.message
    }, 500);
  }
}
