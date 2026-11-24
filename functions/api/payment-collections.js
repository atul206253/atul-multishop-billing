
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
    return { error: json({ success: false, message: "Login आवश्यक है।" }, 401) };
  }

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const bytes = new Uint8Array(hashBuffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

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
    return { error: json({ success: false, message: "Login समाप्त है। दोबारा Login करें।" }, 401) };
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).bind(session.session_id).run();

    return { error: json({ success: false, message: "Login की अवधि समाप्त हो गई है।" }, 401) };
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
    return { error: json({ success: false, message: "कोई सक्रिय Workspace नहीं मिला।" }, 403) };
  }

  return {
    user: session,
    workspace: membership
  };
}

function validText(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

const allowedStatuses = [
  "Pending",
  "Received by Family",
  "Transferred to Shop",
  "Settled"
];

async function handleRequest(request, env, method) {
  try {
    if (!env.DB) {
      return json({ success: false, message: "Database उपलब्ध नहीं है।" }, 500);
    }

    const auth = await authenticate(request, env);

    if (auth.error) return auth.error;

    const userId = auth.user.user_id;
    const workspaceId = auth.workspace.workspace_id;

    // GET: इस Workspace के Payment Collection रिकॉर्ड
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
          updated_at
        FROM payment_collections
        WHERE workspace_id = ?
        ORDER BY received_at DESC, created_at DESC
      `).bind(workspaceId).all();

      return json({
        success: true,
        collections: result.results || []
      });
    }

    // POST: नया Payment Collection रिकॉर्ड
    if (method === "POST") {
      let body;

      try {
        body = await request.json();
      } catch {
        return json({ success: false, message: "गलत JSON डेटा।" }, 400);
      }

      const customerName = validText(body.customerName, 150);
      const customerMobile = validText(body.customerMobile, 20);
      const customerLocation = validText(body.customerLocation, 250);
      const amount = Number(body.amount);
      const paymentMode = validText(body.paymentMode, 50);
      const utr = validText(body.utr, 120);
      const receivedBy = validText(body.receivedBy, 150);
      const moneyWentTo = validText(body.moneyWentTo, 150);
      const settlementStatus = validText(body.settlementStatus || "Pending", 60);
      const settlementNote = validText(body.settlementNote, 1000);
      const receivedAt = validText(body.receivedAt, 40) || new Date().toISOString();

      if (!customerName) {
        return json({ success: false, message: "ग्राहक का नाम जरूरी है।" }, 400);
      }

      if (!Number.isFinite(amount) || amount <= 0 || amount > 100000000) {
        return json({ success: false, message: "कृपया सही राशि दर्ज करें।" }, 400);
      }

      if (!paymentMode) {
        return json({ success: false, message: "Payment Mode चुनें।" }, 400);
      }

      if (!allowedStatuses.includes(settlementStatus)) {
        return json({ success: false, message: "Settlement Status सही नहीं है।" }, 400);
      }

      if (Number.isNaN(Date.parse(receivedAt))) {
        return json({ success: false, message: "प्राप्ति की तारीख सही नहीं है।" }, 400);
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
          received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        receivedAt
      ).run();

      return json({
        success: true,
        message: "Payment Collection रिकॉर्ड सेव हो गया।",
        id
      }, 201);
    }

    // PATCH: Settlement Status / Note अपडेट
    if (method === "PATCH") {
      let body;

      try {
        body = await request.json();
      } catch {
        return json({ success: false, message: "गलत JSON डेटा।" }, 400);
      }

      const id = validText(body.id, 100);
      const settlementStatus = validText(body.settlementStatus, 60);
      const settlementNote = validText(body.settlementNote, 1000);

      if (!id) {
        return json({ success: false, message: "रिकॉर्ड ID जरूरी है।" }, 400);
      }

      if (!allowedStatuses.includes(settlementStatus)) {
        return json({ success: false, message: "Settlement Status सही नहीं है।" }, 400);
      }

      const result = await env.DB.prepare(`
        UPDATE payment_collections
        SET
          settlement_status = ?,
          settlement_note = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND workspace_id = ?
      `).bind(
        settlementStatus,
        settlementNote,
        id,
        workspaceId
      ).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({ success: false, message: "रिकॉर्ड नहीं मिला।" }, 404);
      }

      return json({
        success: true,
        message: "Settlement अपडेट हो गया।"
      });
    }

    // DELETE: रिकॉर्ड हटाना
    if (method === "DELETE") {
      const url = new URL(request.url);
      const id = validText(url.searchParams.get("id"), 100);

      if (!id) {
        return json({ success: false, message: "रिकॉर्ड ID जरूरी है।" }, 400);
      }

      const result = await env.DB.prepare(`
        DELETE FROM payment_collections
        WHERE id = ?
          AND workspace_id = ?
      `).bind(id, workspaceId).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({ success: false, message: "रिकॉर्ड नहीं मिला।" }, 404);
      }

      return json({
        success: true,
        message: "Payment Collection रिकॉर्ड हटा दिया गया।"
      });
    }

    return json({ success: false, message: "Method स्वीकार नहीं है।" }, 405);

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
