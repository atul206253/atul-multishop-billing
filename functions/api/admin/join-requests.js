
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
      return json({ success: false, message: "Invalid request origin." }, 403);
    }

    const token = getCookie(request, "session");
    if (!token) {
      return json({ success: false, message: "कृपया Login करें।" }, 401);
    }

    const session = await env.DB.prepare(`
      SELECT s.user_id, s.expires_at, u.is_admin, u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(await sha256(token)).first();

    if (
      !session ||
      !session.expires_at ||
      new Date(session.expires_at).getTime() <= Date.now() ||
      session.status !== "active"
    ) {
      return json({ success: false, message: "Login समाप्त हो गया है।" }, 401);
    }

    if (Number(session.is_admin) !== 1) {
      return json({ success: false, message: "केवल Main Admin को अनुमति है।" }, 403);
    }

    const body = await request.json();
    const requestId = String(body.requestId || "").trim();
    const action = String(body.action || "").trim();

    if (!requestId || !["approve", "reject"].includes(action)) {
      return json({ success: false, message: "Request या Action सही नहीं है।" }, 400);
    }

    const joinRequest = await env.DB.prepare(`
      SELECT id, user_id, workspace_id, status
      FROM join_requests
      WHERE id = ?
      LIMIT 1
    `).bind(requestId).first();

    if (!joinRequest) {
      return json({ success: false, message: "Join Request नहीं मिली।" }, 404);
    }

    if (joinRequest.status !== "pending") {
      return json({ success: false, message: "यह Request पहले ही Process हो चुकी है।" }, 409);
    }

    const workspace = await env.DB.prepare(`
      SELECT id FROM workspaces
      WHERE id = ? AND status = 'active'
    `).bind(joinRequest.workspace_id).first();

    if (!workspace) {
      return json({ success: false, message: "दुकान उपलब्ध या Active नहीं है।" }, 404);
    }

    const membership = await env.DB.prepare(`
      SELECT id, role, status
      FROM workspace_memberships
      WHERE workspace_id = ? AND user_id = ?
      LIMIT 1
    `).bind(joinRequest.workspace_id, joinRequest.user_id).first();

    if (action === "approve") {
      if (membership) {
        await env.DB.batch([
          env.DB.prepare(`
            UPDATE workspace_memberships
            SET status = 'active'
            WHERE id = ?
          `).bind(membership.id),
          env.DB.prepare(`
            UPDATE join_requests
            SET status = 'approved',
                reviewed_at = CURRENT_TIMESTAMP,
                reviewed_by = ?
            WHERE id = ? AND status = 'pending'
          `).bind(session.user_id, requestId)
        ]);
      } else {
        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO workspace_memberships
              (id, workspace_id, user_id, role, status)
            VALUES (?, ?, ?, 'operator', 'active')
          `).bind(crypto.randomUUID(), joinRequest.workspace_id, joinRequest.user_id),
          env.DB.prepare(`
            UPDATE join_requests
            SET status = 'approved',
                reviewed_at = CURRENT_TIMESTAMP,
                reviewed_by = ?
            WHERE id = ? AND status = 'pending'
          `).bind(session.user_id, requestId)
        ]);
      }

      return json({
        success: true,
        message: "Join Request Approve हो गई। Operator अब Login कर सकता है।"
      });
    }

    await env.DB.batch([
      env.DB.prepare(`
        UPDATE join_requests
        SET status = 'rejected',
            reviewed_at = CURRENT_TIMESTAMP,
            reviewed_by = ?
        WHERE id = ? AND status = 'pending'
      `).bind(session.user_id, requestId),
      env.DB.prepare(`
        UPDATE workspace_memberships
        SET status = 'rejected'
        WHERE workspace_id = ? AND user_id = ? AND status = 'pending'
      `).bind(joinRequest.workspace_id, joinRequest.user_id)
    ]);

    return json({
      success: true,
      message: "Join Request Reject कर दी गई।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Join Request पर कार्रवाई नहीं हो सकी।",
      error: String(error.message || error)
    }, 500);
  }
}
