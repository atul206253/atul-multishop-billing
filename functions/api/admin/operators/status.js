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
        message: "अनुमति नहीं है।"
      }, 403);
    }

    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया Login करें।"
      }, 401);
    }

    const tokenHash = await sha256(token);

    const admin = await env.DB.prepare(`
      SELECT s.user_id, s.expires_at, u.is_admin, u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (
      !admin ||
      !admin.expires_at ||
      new Date(admin.expires_at).getTime() <= Date.now() ||
      admin.status !== "active"
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
    const userId = String(body.userId || "").trim();
    const newStatus = String(body.status || "").trim();

    if (!userId) {
      return json({
        success: false,
        message: "User ID जरूरी है।"
      }, 400);
    }

    if (!["active", "suspended", "deleted"].includes(newStatus)) {
      return json({
        success: false,
        message: "गलत Status दिया गया है।"
      }, 400);
    }

    if (userId === admin.user_id) {
      return json({
        success: false,
        message: "आप अपना Admin अकाउंट बंद नहीं कर सकते।"
      }, 400);
    }

    const target = await env.DB.prepare(`
      SELECT id, name, mobile, status, is_admin
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(userId).first();

    if (!target) {
      return json({
        success: false,
        message: "User नहीं मिला।"
      }, 404);
    }

    if (Number(target.is_admin) === 1) {
      return json({
        success: false,
        message: "Main Admin को Delete या Deactivate नहीं किया जा सकता।"
      }, 403);
    }

    // PERMANENT DELETE
    if (newStatus === "deleted") {
      // जिन दुकानों का मालिक यह Operator है, उनकी सूची
      const ownedWorkspaces = await env.DB.prepare(`
        SELECT id, name
        FROM workspaces
        WHERE owner_user_id = ?
      `).bind(userId).all();

      const ownedIds = (ownedWorkspaces.results || []).map(w => w.id);

      // यदि अपनी दुकान में अन्य Operator जुड़े हैं,
      // तो पूरी Delete प्रक्रिया रोक दें।
      for (const workspaceId of ownedIds) {
        const otherMembers = await env.DB.prepare(`
          SELECT COUNT(*) AS total
          FROM workspace_memberships
          WHERE workspace_id = ?
            AND user_id != ?
        `).bind(workspaceId, userId).first();

        if (Number(otherMembers?.total || 0) > 0) {
          return json({
            success: false,
            message:
              "इस Operator की दुकान में अन्य सदस्य जुड़े हैं। " +
              "दूसरे सदस्यों का डेटा सुरक्षित रखने के लिए Delete रोक दिया गया है।"
          }, 409);
        }
      }

      const statements = [];

      // दूसरे रिकॉर्ड में इस User के references हटाएँ,
      // ताकि Foreign Key की समस्या न आए।
      statements.push(
        env.DB.prepare(`
          UPDATE join_requests
          SET reviewed_by = NULL
          WHERE reviewed_by = ?
        `).bind(userId)
      );

      statements.push(
        env.DB.prepare(`
          UPDATE invite_codes
          SET created_by = NULL
          WHERE created_by = ?
        `).bind(userId)
      );

      statements.push(
        env.DB.prepare(`
          UPDATE invite_codes
          SET used_by = NULL
          WHERE used_by = ?
        `).bind(userId)
      );

      // यदि Operator ने किसी ऐसी दुकान में Bills बनाए हैं
      // जो उसकी अपनी नहीं है, तो Bills सुरक्षित रहेंगे।
      // केवल created_by reference हटेगा।
      statements.push(
        env.DB.prepare(`
          UPDATE bills
          SET created_by = NULL
          WHERE created_by = ?
        `).bind(userId)
      );

      // Operator से संबंधित Reports हटाएँ।
      if (ownedIds.length > 0) {
        const placeholders = ownedIds.map(() => "?").join(",");

        statements.push(
          env.DB.prepare(`
            DELETE FROM operator_reports
            WHERE reported_user_id = ?
               OR reported_by = ?
               OR workspace_id IN (${placeholders})
          `).bind(userId, userId, ...ownedIds)
        );

        // Operator के Logs और उसकी अपनी दुकान के Logs हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM audit_logs
            WHERE user_id = ?
               OR workspace_id IN (${placeholders})
          `).bind(userId, ...ownedIds)
        );

        // अपनी दुकान के Bill Items हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM bill_items
            WHERE bill_id IN (
              SELECT id FROM bills
              WHERE workspace_id IN (${placeholders})
            )
          `).bind(...ownedIds)
        );

        // अपनी दुकान के Bills हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM bills
            WHERE workspace_id IN (${placeholders})
          `).bind(...ownedIds)
        );

        // अपनी दुकान के Customers हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM customers
            WHERE workspace_id IN (${placeholders})
          `).bind(...ownedIds)
        );

        // अपनी दुकान की Settings हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM shop_settings
            WHERE workspace_id IN (${placeholders})
          `).bind(...ownedIds)
        );

        // अपनी दुकान के Join Requests हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM join_requests
            WHERE user_id = ?
               OR workspace_id IN (${placeholders})
          `).bind(userId, ...ownedIds)
        );

        // अपनी दुकान के Invite Codes हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM invite_codes
            WHERE workspace_id IN (${placeholders})
          `).bind(...ownedIds)
        );

        // अपनी दुकान की Memberships हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM workspace_memberships
            WHERE user_id = ?
               OR workspace_id IN (${placeholders})
          `).bind(userId, ...ownedIds)
        );

        // अपनी दुकानें हटाएँ।
        statements.push(
          env.DB.prepare(`
            DELETE FROM workspaces
            WHERE owner_user_id = ?
          `).bind(userId)
        );
      } else {
        statements.push(
          env.DB.prepare(`
            DELETE FROM operator_reports
            WHERE reported_user_id = ?
               OR reported_by = ?
          `).bind(userId, userId)
        );

        statements.push(
          env.DB.prepare(`
            DELETE FROM audit_logs
            WHERE user_id = ?
          `).bind(userId)
        );

        statements.push(
          env.DB.prepare(`
            DELETE FROM join_requests
            WHERE user_id = ?
          `).bind(userId)
        );

        statements.push(
          env.DB.prepare(`
            DELETE FROM workspace_memberships
            WHERE user_id = ?
          `).bind(userId)
        );
      }

      // Login Sessions हटाएँ।
      statements.push(
        env.DB.prepare(`
          DELETE FROM sessions
          WHERE user_id = ?
        `).bind(userId)
      );

      // अंत में User अकाउंट स्थायी रूप से हटाएँ।
      statements.push(
        env.DB.prepare(`
          DELETE FROM users
          WHERE id = ?
            AND is_admin = 0
        `).bind(userId)
      );

      // D1 batch सभी statements को एक transaction में चलाता है।
      await env.DB.batch(statements);

      return json({
        success: true,
        message:
          "Operator का अकाउंट और उससे संबंधित रिकॉर्ड स्थायी रूप से Delete हो गए।",
        deleted: true,
        user: {
          id: target.id,
          name: target.name,
          mobile: target.mobile
        }
      });
    }

    // ACTIVATE / DEACTIVATE
    if (target.status === newStatus) {
      return json({
        success: true,
        message: "यह Status पहले से लागू है।"
      });
    }

    const details = JSON.stringify({
      target_user_id: target.id,
      target_name: target.name,
      target_mobile: target.mobile,
      old_status: target.status,
      new_status: newStatus
    });

    await env.DB.batch([
      env.DB.prepare(`
        UPDATE users
        SET status = ?
        WHERE id = ?
          AND is_admin = 0
      `).bind(newStatus, userId),

      env.DB.prepare(`
        INSERT INTO audit_logs
          (user_id, workspace_id, action, details, created_at)
        VALUES (?, NULL, ?, ?, datetime('now'))
      `).bind(
        admin.user_id,
        "operator_status_changed",
        details
      )
    ]);

    return json({
      success: true,
      message: "Operator का Status सफलतापूर्वक बदल गया।",
      user: {
        id: target.id,
        name: target.name,
        status: newStatus
      }
    });

  } catch (error) {
    return json({
      success: false,
      message: "Operator पर कार्रवाई करने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
