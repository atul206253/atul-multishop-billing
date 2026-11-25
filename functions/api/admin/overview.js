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

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({
        success: false,
        message: "Database binding नहीं मिला।"
      }, 500);
    }

    const token = getCookie(request, "session");

    if (!token) {
      return json({
        success: false,
        message: "कृपया Login करें।"
      }, 401);
    }

    const tokenHash = await sha256(token);

    const session = await env.DB.prepare(`
      SELECT
        s.user_id,
        s.expires_at,
        u.name,
        u.mobile,
        u.is_admin,
        u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (
      !session ||
      !session.expires_at ||
      new Date(session.expires_at).getTime() <= Date.now() ||
      session.status !== "active"
    ) {
      return json({
        success: false,
        message: "Login समाप्त हो गया है।"
      }, 401);
    }

    // केवल Main Admin को सभी दुकानों का डेटा मिलेगा।
    if (Number(session.is_admin) !== 1) {
      return json({
        success: false,
        message: "केवल Main Admin को अनुमति है।"
      }, 403);
    }

    const [
      users,
      workspaces,
      memberships,
      bills,
      customers,
      reports,
      joinRequests
    ] = await Promise.all([

      // सभी Users
      env.DB.prepare(`
        SELECT id, name, mobile, status, is_admin
        FROM users
        ORDER BY name
      `).all(),

      // सभी Shops
      env.DB.prepare(`
        SELECT
          w.id,
          w.name,
          w.slug,
          w.owner_user_id,
          w.status,
          w.created_at,
          u.name AS owner_name,
          u.mobile AS owner_mobile,
          ss.business_name,
          ss.address,
          ss.phone
        FROM workspaces w
        LEFT JOIN users u ON u.id = w.owner_user_id
        LEFT JOIN shop_settings ss ON ss.workspace_id = w.id
        ORDER BY w.created_at DESC
      `).all(),

      // सभी Memberships
      env.DB.prepare(`
        SELECT
          m.id,
          m.workspace_id,
          m.user_id,
          m.role,
          m.status,
          u.name AS user_name,
          u.mobile,
          w.name AS workspace_name
        FROM workspace_memberships m
        LEFT JOIN users u ON u.id = m.user_id
        LEFT JOIN workspaces w ON w.id = m.workspace_id
        ORDER BY m.created_at DESC
      `).all(),

      // सभी Bills
      env.DB.prepare(`
        SELECT
          b.id,
          b.workspace_id,
          b.customer_id,
          b.bill_number,
          b.customer_name,
          b.customer_mobile,
          b.subtotal,
          b.extra_fee,
          b.total,
          b.payment_mode,
          b.utr,
          b.payment_status,
          b.created_by,
          b.created_at,
          u.name AS operator_name,
          u.mobile AS operator_mobile,
          w.name AS workspace_name
        FROM bills b
        LEFT JOIN users u ON u.id = b.created_by
        LEFT JOIN workspaces w ON w.id = b.workspace_id
        ORDER BY b.created_at DESC
        LIMIT 2000
      `).all(),

      // सभी Customers
      env.DB.prepare(`
        SELECT
          c.id,
          c.workspace_id,
          c.name,
          c.mobile,
          c.address,
          c.created_at,
          w.name AS workspace_name
        FROM customers c
        LEFT JOIN workspaces w ON w.id = c.workspace_id
        ORDER BY c.created_at DESC
        LIMIT 2000
      `).all(),

      // सभी Operator Reports
      env.DB.prepare(`
        SELECT
          r.id,
          r.workspace_id,
          r.reported_user_id,
          r.reported_by,
          r.bill_id,
          r.reason,
          r.details,
          r.status,
          r.admin_note,
          r.created_at,
          r.reviewed_at,
          r.reviewed_by,
          u.name AS operator_name,
          u.mobile AS operator_mobile,
          w.name AS workspace_name
        FROM operator_reports r
        LEFT JOIN users u ON u.id = r.reported_user_id
        LEFT JOIN workspaces w ON w.id = r.workspace_id
        ORDER BY r.created_at DESC
      `).all(),

      // सभी Join Requests
      env.DB.prepare(`
        SELECT
          j.id,
          j.user_id,
          j.workspace_id,
          j.status,
          j.requested_at,
          j.reviewed_at,
          j.reviewed_by,
          u.name AS user_name,
          u.mobile,
          w.name AS workspace_name
        FROM join_requests j
        LEFT JOIN users u ON u.id = j.user_id
        LEFT JOIN workspaces w ON w.id = j.workspace_id
        ORDER BY j.requested_at DESC
      `).all()
    ]);

    // सभी दुकानों का Payment Register
    // यह Query Main Admin की जाँच सफल होने के बाद ही चलती है।
    let paymentCollections = [];
    let paymentCollectionsError = null;

    try {
      const payments = await env.DB.prepare(`
        SELECT
          pc.*,
          u.name AS operator_name,
          u.mobile AS operator_mobile,
          w.name AS workspace_name
        FROM payment_collections pc
        LEFT JOIN users u ON u.id = pc.created_by
        LEFT JOIN workspaces w ON w.id = pc.workspace_id
        ORDER BY
          COALESCE(pc.received_at, pc.created_at) DESC
        LIMIT 5000
      `).all();

      paymentCollections = payments.results || [];

    } catch (error) {
      paymentCollectionsError = String(
        error.message || error
      );
    }

    return json({
      success: true,

      admin: {
        id: session.user_id,
        name: session.name,
        mobile: session.mobile
      },

      data: {
        users: users.results || [],
        workspaces: workspaces.results || [],
        memberships: memberships.results || [],
        bills: bills.results || [],
        customers: customers.results || [],
        reports: reports.results || [],
        joinRequests: joinRequests.results || [],

        // नया Payment Register डेटा
        paymentCollections,

        // यदि Payment Register Query में समस्या हो
        paymentCollectionsError
      }
    });

  } catch (error) {
    return json({
      success: false,
      message: "Admin डेटा लाने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
