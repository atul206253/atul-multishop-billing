
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
      return json({
        success: false,
        message: "Database binding नहीं मिला।"
      }, 500);
    }

    const origin = request.headers.get("Origin");

    if (origin && origin !== new URL(request.url).origin) {
      return json({
        success: false,
        message: "Invalid request origin."
      }, 403);
    }

    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया Login करें।"
      }, 401);
    }

    const admin = await env.DB.prepare(`
      SELECT s.user_id, s.expires_at, u.is_admin, u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(await sha256(token)).first();

    if (
      !admin ||
      admin.status !== "active" ||
      !admin.expires_at ||
      new Date(admin.expires_at).getTime() <= Date.now()
    ) {
      return json({
        success: false,
        message: "Login समाप्त हो गया है।"
      }, 401);
    }

    if (Number(admin.is_admin) !== 1) {
      return json({
        success: false,
        message: "केवल Main Admin को अनुमति है।"
      }, 403);
    }

    const body = await request.json();

    const reportId = String(body.reportId || "").trim();
    const status = String(body.status || "").trim();
    const adminNote = String(body.adminNote || "").trim();

    const allowedStatuses = [
      "open",
      "reviewing",
      "resolved",
      "rejected"
    ];

    if (!reportId || !allowedStatuses.includes(status)) {
      return json({
        success: false,
        message: "Report ID या Status सही नहीं है।"
      }, 400);
    }

    if (adminNote.length > 2000) {
      return json({
        success: false,
        message: "Admin Note अधिकतम 2000 अक्षर का हो सकता है।"
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
        message: "Report नहीं मिली।"
      }, 404);
    }

    await env.DB.prepare(`
      UPDATE operator_reports
      SET status = ?,
          admin_note = ?,
          reviewed_at = CURRENT_TIMESTAMP,
          reviewed_by = ?
      WHERE id = ?
    `).bind(
      status,
      adminNote,
      admin.user_id,
      reportId
    ).run();

    return json({
      success: true,
      message: "Report का Status सफलतापूर्वक अपडेट हो गया।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Report अपडेट नहीं हो सकी।",
      error: String(error.message || error)
    }, 500);
  }
}
