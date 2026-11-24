
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

    const user = await env.DB.prepare(`
      SELECT s.user_id, s.expires_at, u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(await sha256(token)).first();

    if (
      !user ||
      user.status !== "active" ||
      !user.expires_at ||
      new Date(user.expires_at).getTime() <= Date.now()
    ) {
      return json({
        success: false,
        message: "Login समाप्त हो गया है। कृपया दोबारा Login करें।"
      }, 401);
    }

    const body = await request.json();

    const workspaceId = String(body.workspaceId || "").trim();
    const bill = body.bill || {};
    const reason = String(body.reason || "").trim();
    const message = String(body.details || "").trim();

    if (!workspaceId) {
      return json({
        success: false,
        message: "Workspace की जानकारी नहीं मिली।"
      }, 400);
    }

    if (!reason || reason.length > 150) {
      return json({
        success: false,
        message: "Report का कारण लिखें (अधिकतम 150 अक्षर)।"
      }, 400);
    }

    if (!message || message.length > 2000) {
      return json({
        success: false,
        message: "Report का विवरण लिखें (अधिकतम 2000 अक्षर)।"
      }, 400);
    }

    const billId = String(bill.id || "").trim();
    const customerName = String(bill.name || "").trim();

    if (!billId || !customerName) {
      return json({
        success: false,
        message: "बिल की जानकारी अधूरी है।"
      }, 400);
    }

    // User केवल उसी Workspace में Report कर सकता है
    // जिसमें उसकी Active Membership है।
    const membership = await env.DB.prepare(`
      SELECT id
      FROM workspace_memberships
      WHERE workspace_id = ?
        AND user_id = ?
        AND status = 'active'
      LIMIT 1
    `).bind(workspaceId, user.user_id).first();

    if (!membership) {
      return json({
        success: false,
        message: "इस दुकान में Report करने की अनुमति नहीं है।"
      }, 403);
    }

    const billSnapshot = {
      bill_number: billId,
      customer_name: customerName,
      customer_mobile: String(bill.mobile || ""),
      customer_address: String(bill.address || ""),
      bill_date: String(bill.date || ""),
      total: Number(bill.total || 0),
      payment_mode: String(bill.mode || ""),
      payment_status: String(bill.status || ""),
      utr: String(bill.utr || "")
    };

    const reportDetails = JSON.stringify({
      message,
      bill: billSnapshot
    });

    await env.DB.prepare(`
      INSERT INTO operator_reports (
        id,
        workspace_id,
        reported_user_id,
        reported_by,
        bill_id,
        reason,
        details,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
    `).bind(
      crypto.randomUUID(),
      workspaceId,
      user.user_id,
      user.user_id,
      billId,
      reason,
      reportDetails
    ).run();

    return json({
      success: true,
      message: "आपकी Report Main Admin को भेज दी गई है।"
    }, 201);

  } catch (error) {
    return json({
      success: false,
      message: "Report भेजने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
