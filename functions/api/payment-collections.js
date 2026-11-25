
const json = (data, status = 200) => new Response(JSON.stringify(data), {
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

async function getContext(request, env) {
  if (!env.DB) {
    return {
      error: json({
        success: false,
        message: "Database binding नहीं मिला।"
      }, 500)
    };
  }

  const token = getCookie(request, "session");

  if (!token) {
    return {
      error: json({
        success: false,
        message: "कृपया Login करें।"
      }, 401)
    };
  }

  const tokenHash = await sha256(token);

  const user = await env.DB.prepare(`
    SELECT s.user_id, s.expires_at, u.name, u.mobile, u.status, u.is_admin
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (
    !user ||
    !user.expires_at ||
    new Date(user.expires_at).getTime() <= Date.now() ||
    user.status !== "active"
  ) {
    return {
      error: json({
        success: false,
        message: "Login समाप्त हो गया है। कृपया दोबारा Login करें।"
      }, 401)
    };
  }

  let membership = await env.DB.prepare(`
    SELECT m.workspace_id
    FROM workspace_memberships m
    JOIN workspaces w ON w.id = m.workspace_id
    WHERE m.user_id = ?
      AND m.status = 'active'
      AND w.status = 'active'
    ORDER BY m.created_at ASC
    LIMIT 1
  `).bind(user.user_id).first();

  if (!membership?.workspace_id) {
    membership = await env.DB.prepare(`
      SELECT id AS workspace_id
      FROM workspaces
      WHERE owner_user_id = ?
        AND status = 'active'
      ORDER BY created_at ASC
      LIMIT 1
    `).bind(user.user_id).first();
  }

  if (!membership?.workspace_id) {
    return {
      error: json({
        success: false,
        message: "आपका Active Workspace नहीं मिला। Admin से संपर्क करें।"
      }, 403)
    };
  }

  return {
    user,
    workspaceId: membership.workspace_id
  };
}

function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function validMobile(value) {
  return !value || /^[0-9+() -]{7,18}$/.test(value);
}

function finalAmount(type, amount, charge) {
  return type === "received"
    ? amount - charge
    : amount + charge;
}

export async function onRequestGet({ request, env }) {
  try {
    const context = await getContext(request, env);
    if (context.error) return context.error;

    const result = await env.DB.prepare(`
      SELECT *
      FROM payment_collections
      WHERE workspace_id = ?
      ORDER BY COALESCE(received_at, created_at) DESC
      LIMIT 2000
    `).bind(context.workspaceId).all();

    return json({
      success: true,
      collections: result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      message: "Payment Records लोड नहीं हुए।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const context = await getContext(request, env);
    if (context.error) return context.error;

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "गलत Request Data।"
      }, 400);
    }

    const type = body.transactionType === "sent"
      ? "sent"
      : "received";

    const amount = Number(body.amount);
    const charge = Number(body.cscCharge ?? 0);
    const mode = clean(body.paymentMode, 50);
    const status = clean(body.transactionStatus || "Completed", 30);
    const receivedAt = clean(body.receivedAt, 50) || new Date().toISOString();

    if (!Number.isFinite(amount) || amount <= 0) {
      return json({
        success: false,
        message: "राशि सही दर्ज करें।"
      }, 400);
    }

    if (!Number.isFinite(charge) || charge < 0) {
      return json({
        success: false,
        message: "CSC Charge सही दर्ज करें।"
      }, 400);
    }

    if (type === "received" && charge > amount) {
      return json({
        success: false,
        message: "प्राप्त राशि से CSC Charge अधिक नहीं हो सकता।"
      }, 400);
    }

    if (!mode) {
      return json({
        success: false,
        message: "Payment Mode चुनें।"
      }, 400);
    }

    if (!["Completed", "Pending", "Failed"].includes(status)) {
      return json({
        success: false,
        message: "Transaction Status सही नहीं है।"
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
    let purpose = "";
    let recipientName = "";
    let recipientMobile = "";
    let recipientLocation = "";

    if (type === "received") {
      customerName = clean(body.customerName, 200);
      customerMobile = clean(body.customerMobile, 30);
      customerLocation = clean(body.customerLocation, 300);

      // पैसा लेने वाले का मोबाइल
      recipientMobile = clean(
        body.receiverMobile ?? body.recipientMobile,
        30
      );

      receivedBy = clean(body.receivedBy, 200);
      moneyWentTo = clean(body.moneyWentTo, 300);
      settlementStatus = clean(
        body.settlementStatus || "Pending",
        40
      );
      settlementNote = clean(body.settlementNote, 1000);

      if (!customerName) {
        return json({
          success: false,
          message: "पैसा भेजने वाले का नाम दर्ज करें।"
        }, 400);
      }

      if (!validMobile(customerMobile)) {
        return json({
          success: false,
          message: "पैसा भेजने वाले का मोबाइल नंबर सही दर्ज करें।"
        }, 400);
      }

      if (!validMobile(recipientMobile)) {
        return json({
          success: false,
          message: "पैसा लेने वाले का मोबाइल नंबर सही दर्ज करें।"
        }, 400);
      }

      if (!moneyWentTo) {
        return json({
          success: false,
          message: "नकद किसे दिया गया, यह चुनें।"
        }, 400);
      }

      if (![
        "Pending",
        "Received by Family",
        "Transferred to Shop",
        "Settled"
      ].includes(settlementStatus)) {
        settlementStatus = "Pending";
      }

    } else {
      paidBy = clean(body.paidBy, 200);

      const paidByMobile = clean(body.paidByMobile, 30);
      const paidByLocation = clean(body.paidByLocation, 300);

      recipientName = clean(body.recipientName, 200);
      recipientMobile = clean(body.recipientMobile, 30);
      recipientLocation = clean(body.recipientLocation, 300);
      purpose = clean(body.purpose, 1000);

      if (!recipientName) {
        return json({
          success: false,
          message: "जिसे पैसा भेजा है उसका नाम दर्ज करें।"
        }, 400);
      }

      if (!validMobile(paidByMobile) || !validMobile(recipientMobile)) {
        return json({
          success: false,
          message: "मोबाइल नंबर सही दर्ज करें।"
        }, 400);
      }

      // भेजने वाले की जानकारी customer_* कॉलम में
      customerName = paidBy;
      customerMobile = paidByMobile;
      customerLocation = paidByLocation;
    }

    const id = crypto.randomUUID();
    const final = finalAmount(type, amount, charge);

    await env.DB.prepare(`
      INSERT INTO payment_collections (
        id, workspace_id, created_by,
        customer_name, customer_mobile, customer_location,
        amount, csc_charge, final_amount, payment_mode, utr,
        received_by, money_went_to, settlement_status, settlement_note,
        received_at, created_at, updated_at,
        transaction_type, purpose, paid_by,
        recipient_name, recipient_mobile, recipient_location,
        transaction_status
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
        ?, ?, ?, ?, ?, ?, ?
      )
    `).bind(
      id,
      context.workspaceId,
      context.user.user_id,
      customerName,
      customerMobile,
      customerLocation,
      amount,
      charge,
      final,
      mode,
      clean(body.utr, 150),
      receivedBy,
      moneyWentTo,
      settlementStatus,
      settlementNote,
      receivedAt,
      type,
      purpose,
      paidBy,
      recipientName,
      recipientMobile,
      recipientLocation,
      status
    ).run();

    return json({
      success: true,
      id,
      message: "लेन-देन सफलतापूर्वक सेव हो गया।",
      finalAmount: final
    });

  } catch (error) {
    return json({
      success: false,
      message: "लेन-देन सेव नहीं हुआ।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestPatch({ request, env }) {
  try {
    const context = await getContext(request, env);
    if (context.error) return context.error;

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "गलत Request Data।"
      }, 400);
    }

    const id = clean(body.id, 100);

    if (!id) {
      return json({
        success: false,
        message: "Payment ID नहीं मिला।"
      }, 400);
    }

    const record = await env.DB.prepare(`
      SELECT id, transaction_type, amount, csc_charge
      FROM payment_collections
      WHERE id = ? AND workspace_id = ?
      LIMIT 1
    `).bind(id, context.workspaceId).first();

    if (!record) {
      return json({
        success: false,
        message: "Payment Record नहीं मिला।"
      }, 404);
    }

    const updates = [];
    const values = [];

    if (body.settlementStatus !== undefined) {
      const allowed = [
        "Pending",
        "Received by Family",
        "Transferred to Shop",
        "Settled"
      ];

      if (!allowed.includes(body.settlementStatus)) {
        return json({
          success: false,
          message: "Settlement Status सही नहीं है।"
        }, 400);
      }

      updates.push("settlement_status = ?");
      values.push(body.settlementStatus);
    }

    if (body.transactionStatus !== undefined) {
      const allowed = ["Completed", "Pending", "Failed"];

      if (!allowed.includes(body.transactionStatus)) {
        return json({
          success: false,
          message: "Transaction Status सही नहीं है।"
        }, 400);
      }

      updates.push("transaction_status = ?");
      values.push(body.transactionStatus);
    }

    if (body.cscCharge !== undefined) {
      const charge = Number(body.cscCharge);

      if (
        !Number.isFinite(charge) ||
        charge < 0 ||
        (
          record.transaction_type === "received" &&
          charge > Number(record.amount)
        )
      ) {
        return json({
          success: false,
          message: "CSC Charge सही दर्ज करें।"
        }, 400);
      }

      updates.push("csc_charge = ?");
      values.push(charge);

      updates.push("final_amount = ?");
      values.push(
        finalAmount(
          record.transaction_type || "received",
          Number(record.amount),
          charge
        )
      );
    }

    if (!updates.length) {
      return json({
        success: false,
        message: "अपडेट करने के लिए कोई जानकारी नहीं मिली।"
      }, 400);
    }

    updates.push("updated_at = CURRENT_TIMESTAMP");
    values.push(id, context.workspaceId);

    await env.DB.prepare(`
      UPDATE payment_collections
      SET ${updates.join(", ")}
      WHERE id = ? AND workspace_id = ?
    `).bind(...values).run();

    return json({
      success: true,
      message: "Payment Record अपडेट हो गया।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Payment Record अपडेट नहीं हुआ।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const context = await getContext(request, env);
    if (context.error) return context.error;

    const id = clean(
      new URL(request.url).searchParams.get("id"),
      100
    );

    if (!id) {
      return json({
        success: false,
        message: "Payment ID नहीं मिला।"
      }, 400);
    }

    const result = await env.DB.prepare(`
      DELETE FROM payment_collections
      WHERE id = ? AND workspace_id = ?
    `).bind(id, context.workspaceId).run();

    if (!result.meta?.changes) {
      return json({
        success: false,
        message: "Payment Record नहीं मिला।"
      }, 404);
    }

    return json({
      success: true,
      message: "Payment Record हटा दिया गया।"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Payment Record हटाया नहीं जा सका।",
      error: String(error.message || error)
    }, 500);
  }
}
