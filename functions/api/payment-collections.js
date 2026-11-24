
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

    if (key === name) return decodeURIComponent(value);
  }

  return "";
}

async function authenticate(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return {
      error: json({ success: false, message: "Login आवश्यक है।" }, 401)
    };
  }

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const bytes = new Uint8Array(hashBuffer);
  let binary = "";

  for (const byte of bytes) binary += String.fromCharCode(byte);

  const tokenHash = btoa(binary);

  const session = await env.DB.prepare(`
    SELECT
      s.id AS session_id,
      s.user_id,
      s.expires_at,
      u.name,
      u.mobile,
      u.status AS user_status
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session || session.user_status !== "active") {
    return {
      error: json({
        success: false,
        message: "Login समाप्त है। दोबारा Login करें।"
      }, 401)
    };
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).bind(session.session_id).run();

    return {
      error: json({
        success: false,
        message: "Login की अवधि समाप्त हो गई है।"
      }, 401)
    };
  }

  const membership = await env.DB.prepare(`
    SELECT
      m.workspace_id,
      m.role,
      w.name AS workspace_name
    FROM workspace_memberships m
    JOIN workspaces w ON w.id = m.workspace_id
    WHERE m.user_id = ?
      AND m.status = 'active'
      AND w.status = 'active'
    ORDER BY m.created_at ASC
    LIMIT 1
  `).bind(session.user_id).first();

  if (!membership) {
    return {
      error: json({
        success: false,
        message: "कोई सक्रिय Workspace नहीं मिला।"
      }, 403)
    };
  }

  return {
    user: session,
    workspace: membership
  };
}

function textValue(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

const settlementStatuses = [
  "Pending",
  "Received by Family",
  "Transferred to Shop",
  "Settled"
];

const transactionStatuses = [
  "Completed",
  "Pending",
  "Failed"
];

const paymentModes = [
  "Paytm QR",
  "UPI QR",
  "UPI ID",
  "Mobile Number",
  "Cash",
  "Bank Transfer",
  "Card",
  "Other"
];

const transactionTypes = [
  "received",
  "sent"
];

async function handleRequest(request, env, method) {
  try {
    if (!env.DB) {
      return json({
        success: false,
        message: "Database उपलब्ध नहीं है।"
      }, 500);
    }

    const auth = await authenticate(request, env);
    if (auth.error) return auth.error;

    const userId = auth.user.user_id;
    const workspaceId = auth.workspace.workspace_id;

    // GET: Workspace के सभी Payment Register रिकॉर्ड
    if (method === "GET") {
      const result = await env.DB.prepare(`
        SELECT
          id,
          workspace_id,
          created_by,
          customer_name,
          customer_mobile,
          customer_location,
          amount,
          payment_mode,
          utr,
          received_by,
          money_went_to,
          settlement_status,
          settlement_note,
          received_at,
          created_at,
          updated_at,
          transaction_type,
          purpose,
          paid_by,
          recipient_name,
          recipient_mobile,
          recipient_location,
          transaction_status
        FROM payment_collections
        WHERE workspace_id = ?
        ORDER BY received_at DESC, created_at DESC
      `).bind(workspaceId).all();

      return json({
        success: true,
        collections: result.results || []
      });
    }

    // POST: नया लेन-देन सेव करें
    if (method === "POST") {
      let body;

      try {
        body = await request.json();
      } catch {
        return json({
          success: false,
          message: "गलत JSON डेटा।"
        }, 400);
      }

      const transactionType = textValue(
        body.transactionType || "received",
        20
      ).toLowerCase();

      const amount = Number(body.amount);
      const paymentMode = textValue(body.paymentMode, 50);
      const utr = textValue(body.utr, 120);
      const purpose = textValue(body.purpose, 500);

      const transactionStatus = textValue(
        body.transactionStatus || "Completed",
        30
      );

      const receivedAt = textValue(
        body.receivedAt || new Date().toISOString(),
        40
      );

      if (!transactionTypes.includes(transactionType)) {
        return json({
          success: false,
          message: "लेन-देन का प्रकार सही नहीं है।"
        }, 400);
      }

      if (!Number.isFinite(amount) || amount <= 0 || amount > 100000000) {
        return json({
          success: false,
          message: "कृपया सही राशि दर्ज करें।"
        }, 400);
      }

      if (!paymentModes.includes(paymentMode)) {
        return json({
          success: false,
          message: "Payment Mode सही चुनें।"
        }, 400);
      }

      if (!transactionStatuses.includes(transactionStatus)) {
        return json({
          success: false,
          message: "Transaction Status सही नहीं है।"
        }, 400);
      }

      if (Number.isNaN(Date.parse(receivedAt))) {
        return json({
          success: false,
          message: "तारीख सही दर्ज करें।"
        }, 400);
      }

      let customerName = "";
      let customerMobile = "";
      let customerLocation = "";
      let receivedBy = "";
      let moneyWentTo = "";
      let settlementStatus = "Pending";
      let settlementNote = "";

      let paidBy = "";
      let recipientName = "";
      let recipientMobile = "";
      let recipientLocation = "";

      if (transactionType === "received") {
        customerName = textValue(body.customerName, 150);
        customerMobile = textValue(body.customerMobile, 20);
        customerLocation = textValue(body.customerLocation, 250);
        receivedBy = textValue(body.receivedBy, 150);
        moneyWentTo = textValue(body.moneyWentTo, 150);

        settlementStatus = textValue(
          body.settlementStatus || "Pending",
          60
        );

        settlementNote = textValue(body.settlementNote, 1000);

        if (!customerName) {
          return json({
            success: false,
            message: "ग्राहक का नाम जरूरी है।"
          }, 400);
        }

        if (!settlementStatuses.includes(settlementStatus)) {
          return json({
            success: false,
            message: "Settlement Status सही नहीं है।"
          }, 400);
        }
      } else {
        paidBy = textValue(body.paidBy, 150);
        recipientName = textValue(body.recipientName, 150);
        recipientMobile = textValue(body.recipientMobile, 20);
        recipientLocation = textValue(body.recipientLocation, 250);

        if (!recipientName) {
          return json({
            success: false,
            message: "जिसे पैसा भेजा है उसका नाम जरूरी है।"
          }, 400);
        }
      }

      const id = crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO payment_collections (
          id,
          workspace_id,
          created_by,
          customer_name,
          customer_mobile,
          customer_location,
          amount,
          payment_mode,
          utr,
          received_by,
          money_went_to,
          settlement_status,
          settlement_note,
          received_at,
          transaction_type,
          purpose,
          paid_by,
          recipient_name,
          recipient_mobile,
          recipient_location,
          transaction_status
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?
        )
      `).bind(
        id,
        workspaceId,
        userId,
        customerName,
        customerMobile,
        customerLocation,
        amount,
        paymentMode,
        utr,
        receivedBy,
        moneyWentTo,
        settlementStatus,
        settlementNote,
        receivedAt,
        transactionType,
        purpose,
        paidBy,
        recipientName,
        recipientMobile,
        recipientLocation,
        transactionStatus
      ).run();

      return json({
        success: true,
        message: transactionType === "received"
          ? "पैसा प्राप्त होने का रिकॉर्ड सेव हो गया।"
          : "पैसा भेजने का रिकॉर्ड सेव हो गया।",
        id
      }, 201);
    }

    // PATCH: Settlement या Transaction Status अपडेट
    if (method === "PATCH") {
      let body;

      try {
        body = await request.json();
      } catch {
        return json({
          success: false,
          message: "गलत JSON डेटा।"
        }, 400);
      }

      const id = textValue(body.id, 100);

      if (!id) {
        return json({
          success: false,
          message: "रिकॉर्ड ID जरूरी है।"
        }, 400);
      }

      const existing = await env.DB.prepare(`
        SELECT id, transaction_type
        FROM payment_collections
        WHERE id = ? AND workspace_id = ?
        LIMIT 1
      `).bind(id, workspaceId).first();

      if (!existing) {
        return json({
          success: false,
          message: "रिकॉर्ड नहीं मिला।"
        }, 404);
      }

      const updates = [];
      const values = [];

      if (body.transactionStatus !== undefined) {
        const status = textValue(body.transactionStatus, 30);

        if (!transactionStatuses.includes(status)) {
          return json({
            success: false,
            message: "Transaction Status सही नहीं है।"
          }, 400);
        }

        updates.push("transaction_status = ?");
        values.push(status);
      }

      if (body.settlementStatus !== undefined) {
        if (existing.transaction_type !== "received") {
          return json({
            success: false,
            message: "Settlement Status केवल प्राप्त भुगतान में लागू है।"
          }, 400);
        }

        const status = textValue(body.settlementStatus, 60);

        if (!settlementStatuses.includes(status)) {
          return json({
            success: false,
            message: "Settlement Status सही नहीं है।"
          }, 400);
        }

        updates.push("settlement_status = ?");
        values.push(status);
      }

      if (body.settlementNote !== undefined) {
        updates.push("settlement_note = ?");
        values.push(textValue(body.settlementNote, 1000));
      }

      if (!updates.length) {
        return json({
          success: false,
          message: "अपडेट करने के लिए कोई जानकारी नहीं मिली।"
        }, 400);
      }

      updates.push("updated_at = CURRENT_TIMESTAMP");

      values.push(id, workspaceId);

      await env.DB.prepare(`
        UPDATE payment_collections
        SET ${updates.join(", ")}
        WHERE id = ? AND workspace_id = ?
      `).bind(...values).run();

      return json({
        success: true,
        message: "लेन-देन अपडेट हो गया।"
      });
    }

    // DELETE: रिकॉर्ड हटाएं
    if (method === "DELETE") {
      const url = new URL(request.url);
      const id = textValue(url.searchParams.get("id"), 100);

      if (!id) {
        return json({
          success: false,
          message: "रिकॉर्ड ID जरूरी है।"
        }, 400);
      }

      const result = await env.DB.prepare(`
        DELETE FROM payment_collections
        WHERE id = ? AND workspace_id = ?
      `).bind(id, workspaceId).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({
          success: false,
          message: "रिकॉर्ड नहीं मिला।"
        }, 404);
      }

      return json({
        success: true,
        message: "लेन-देन रिकॉर्ड हटा दिया गया।"
      });
    }

    return json({
      success: false,
      message: "Method स्वीकार नहीं है।"
    }, 405);

  } catch (error) {
    return json({
      success: false,
      message: "Server में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestGet({ request, env }) {
  return handleRequest(request, env, "GET");
}

export async function onRequestPost({ request, env }) {
  return handleRequest(request, env, "POST");
}

export async function onRequestPatch({ request, env }) {
  return handleRequest(request, env, "PATCH");
}

export async function onRequestDelete({ request, env }) {
  return handleRequest(request, env, "DELETE");
}
