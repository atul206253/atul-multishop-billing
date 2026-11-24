
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
    if (request.method !== "POST") {
      return json({
        success: false,
        message: "केवल POST Request की अनुमति है।"
      }, 405);
    }

    // 1. Admin Session Check
    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया पहले Login करें।"
      }, 401);
    }

    const tokenHash = await hashToken(token);

    const admin = await env.DB.prepare(`
      SELECT
        u.id,
        u.name,
        u.mobile,
        u.is_admin
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
        message: "केवल Main Admin Report दर्ज कर सकता है।"
      }, 403);
    }

    // 2. Request Data
    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Request Data सही नहीं है।"
      }, 400);
    }

    const reportedUserId = String(body.reportedUserId || "").trim();
    const workspaceId = String(body.workspaceId || "").trim();
    const reason = String(body.reason || "").trim();
    const message = String(body.details || "").trim();
    const billNumber = String(body.billNumber || "").trim();

    if (!reportedUserId || !workspaceId || !reason || !message) {
      return json({
        success: false,
        message: "Operator, दुकान, Report का कारण और विवरण भरना जरूरी है।"
      }, 400);
    }

    if (
      reason.length > 200 ||
      message.length > 5000 ||
      billNumber.length > 100
    ) {
      return json({
        success: false,
        message: "Report का विवरण या Bill Number निर्धारित सीमा से अधिक है।"
      }, 400);
    }

    // 3. Target Operator Check
    const operator = await env.DB.prepare(`
      SELECT
        u.id,
        u.name,
        u.mobile
      FROM users u
      JOIN workspace_memberships m
        ON m.user_id = u.id
      WHERE u.id = ?
        AND u.status = 'active'
        AND u.is_admin = 0
        AND m.workspace_id = ?
        AND m.status = 'active'
      LIMIT 1
    `).bind(reportedUserId, workspaceId).first();

    if (!operator) {
      return json({
        success: false,
        message: "चुना गया Operator इस दुकान का Active सदस्य नहीं है।"
      }, 404);
    }

    // 4. Optional Bill Number Check
    let billId = null;
    let billSnapshot = {};

    if (billNumber) {
      const bill = await env.DB.prepare(`
        SELECT
          b.id,
          b.bill_number,
          b.customer_name,
          b.customer_mobile,
          b.total,
          b.payment_mode,
          b.payment_status,
          b.utr,
          b.created_at,
          b.created_by,
          c.address AS customer_address
        FROM bills b
        LEFT JOIN customers c ON c.id = b.customer_id
        WHERE b.bill_number = ?
          AND b.workspace_id = ?
        LIMIT 1
      `).bind(billNumber, workspaceId).first();

      if (!bill) {
        return json({
          success: false,
          message: "इस दुकान में दिया गया Bill No. नहीं मिला। कृपया Bill Number जाँचें।"
        }, 404);
      }

      if (bill.created_by && bill.created_by !== reportedUserId) {
        return json({
          success: false,
          message: "यह Bill चुने गए Operator का नहीं है।"
        }, 400);
      }

      // असली Database Bill ID
      billId = bill.id;

      billSnapshot = {
        bill_number: bill.bill_number,
        customer_name: bill.customer_name,
        customer_mobile: bill.customer_mobile,
        customer_address: bill.customer_address || "",
        total: bill.total,
        payment_mode: bill.payment_mode,
        payment_status: bill.payment_status,
        utr: bill.utr,
        bill_date: bill.created_at
      };
    }

    // 5. Create Report
    const reportId = crypto.randomUUID();

    const reportDetails = JSON.stringify({
      message,
      bill: billSnapshot,
      reported_by_admin: true,
      admin_name: admin.name
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
        status,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'open', CURRENT_TIMESTAMP)
    `).bind(
      reportId,
      workspaceId,
      reportedUserId,
      admin.id,
      billId,
      reason,
      reportDetails
    ).run();

    return json({
      success: true,
      message: "Operator के लिए Report सफलतापूर्वक दर्ज हो गई।",
      reportId,
      billId
    });

  } catch (error) {
    return json({
      success: false,
      message: "Report दर्ज करने में Server समस्या हुई।",
      error: error.message
    }, 500);
  }
}
