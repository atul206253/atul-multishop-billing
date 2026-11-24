
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

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

export async function onRequestPost({ request, env }) {
  try {
    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया पहले Login करें।"
      }, 401);
    }

    const tokenHash = await hashToken(token);

    const admin = await env.DB.prepare(`
      SELECT u.id, u.is_admin
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND datetime(s.expires_at) > datetime('now')
        AND u.status = 'active'
      LIMIT 1
    `).bind(tokenHash).first();

    if (!admin) {
      return json({
        success: false,
        message: "आपका Login Session समाप्त हो गया है।"
      }, 401);
    }

    if (Number(admin.is_admin) !== 1) {
      return json({
        success: false,
        message: "केवल Main Admin Report Delete कर सकता है।"
      }, 403);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Request Data सही नहीं है।"
      }, 400);
    }

    const reportId = String(body.reportId || "").trim();

    if (!reportId) {
      return json({
        success: false,
        message: "Report ID नहीं मिली।"
      }, 400);
    }

    const report = await env.DB.prepare(`
      SELECT id
      FROM operator_reports
      WHERE id = ?
      LIMIT 1
    `).bind(reportId).first();

    if (!report) {
      return json({
        success: false,
        message: "यह Report पहले से मौजूद नहीं है।"
      }, 404);
    }

    await env.DB.prepare(`
      DELETE FROM operator_reports
      WHERE id = ?
    `).bind(reportId).run();

    return json({
      success: true,
      message: "Report सफलतापूर्वक Delete हो गई।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Report Delete करने में Server समस्या हुई।",
      error: error.message
    }, 500);
  }
}
