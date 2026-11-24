
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

async function getAuth(request, env) {
  if (!env.DB) {
    return { error: json({ success: false, message: "Database binding नहीं मिला।" }, 500) };
  }

  const token = getCookie(request, "session");

  if (!token) {
    return { error: json({ success: false, message: "कृपया Login करें।" }, 401) };
  }

  const tokenHash = await sha256(token);

  const session = await env.DB.prepare(`
    SELECT s.user_id, s.expires_at, u.name, u.mobile, u.status
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session || !session.expires_at ||
      new Date(session.expires_at).getTime() <= Date.now() ||
      session.status !== "active") {
    return { error: json({ success: false, message: "Login समाप्त हो गया है।" }, 401) };
  }

  const membership = await env.DB.prepare(`
    SELECT m.workspace_id, m.role, m.status
    FROM workspace_memberships m
    WHERE m.user_id = ?
      AND m.status = 'active'
    ORDER BY m.created_at ASC
    LIMIT 1
  `).bind(session.user_id).first();

  if (!membership) {
    return { error: json({ success: false, message: "कोई सक्रिय Workspace नहीं मिला।" }, 403) };
  }

  return {
    user: session,
    workspaceId: membership.workspace_id
  };
}

export async function onRequestGet({ request, env }) {
  try {
    const auth = await getAuth(request, env);
    if (auth.error) return auth.error;

    const result = await env.DB.prepare(`
      SELECT b.id, b.workspace_id, b.bill_number,
             b.customer_name AS name,
             b.customer_mobile AS mobile,
             c.address,
             b.subtotal, b.extra_fee, b.total,
             b.payment_mode AS mode,
             b.utr,
             b.payment_status AS status,
             b.created_at, b.created_by
      FROM bills b
      LEFT JOIN customers c ON c.id = b.customer_id
      WHERE b.workspace_id = ?
      ORDER BY b.created_at DESC
      LIMIT 2000
    `).bind(auth.workspaceId).all();

    const itemResult = await env.DB.prepare(`
      SELECT bi.id, bi.bill_id, bi.service_name AS name, bi.amount
      FROM bill_items bi
      JOIN bills b ON b.id = bi.bill_id
      WHERE b.workspace_id = ?
      ORDER BY bi.rowid ASC
    `).bind(auth.workspaceId).all();

    const itemsByBill = {};

    for (const item of (itemResult.results || [])) {
      if (!itemsByBill[item.bill_id]) itemsByBill[item.bill_id] = [];
      itemsByBill[item.bill_id].push({
        name: item.name,
        amount: Number(item.amount || 0)
      });
    }

    const bills = (result.results || []).map(bill => ({
      id: bill.bill_number,
      name: bill.name,
      mobile: bill.mobile || "",
      address: bill.address || "",
      date: bill.created_at ? String(bill.created_at).slice(0, 10) : "",
      mode: bill.mode || "",
      utr: bill.utr || "",
      status: String(bill.status).toLowerCase() === "paid" ? "Paid" : "Unpaid",
      services: itemsByBill[bill.id] || [],
      extra: Number(bill.extra_fee || 0),
      total: Number(bill.total || 0)
    }));

    return json({ success: true, bills });

  } catch (error) {
    return json({
      success: false,
      message: "बिल डेटा लाने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const auth = await getAuth(request, env);
    if (auth.error) return auth.error;

    const body = await request.json();

    const bill = body.bill || body;
    const billNumber = String(bill.id || "").trim();
    const customerName = String(bill.name || "").trim();
    const mobile = String(bill.mobile || "").trim();
    const address = String(bill.address || "").trim();
    const services = Array.isArray(bill.services) ? bill.services : [];

    if (!billNumber || !customerName || !services.length) {
      return json({ success: false, message: "बिल की जरूरी जानकारी अधूरी है।" }, 400);
    }

    if (mobile && !/^[0-9]{10}$/.test(mobile)) {
      return json({ success: false, message: "ग्राहक का मोबाइल नंबर सही नहीं है।" }, 400);
    }

    const cleanServices = services
      .filter(item => String(item.name || "").trim())
      .map(item => ({
        name: String(item.name).trim(),
        amount: Math.max(0, Number(item.amount) || 0)
      }));

    if (!cleanServices.length) {
      return json({ success: false, message: "कम से कम एक सेवा जरूरी है।" }, 400);
    }

    const extra = Math.max(0, Number(bill.extra) || 0);
    const subtotal = cleanServices.reduce((sum, item) => sum + item.amount, 0);
    const total = subtotal + extra;

    const paymentStatus =
      String(bill.status || "").toLowerCase() === "paid" ? "paid" : "unpaid";

    const paymentMode = String(bill.mode || "Other").slice(0, 50);
    const utr = String(bill.utr || "").slice(0, 150);

    const existing = await env.DB.prepare(`
      SELECT id FROM bills
      WHERE workspace_id = ? AND bill_number = ?
      LIMIT 1
    `).bind(auth.workspaceId, billNumber).first();

    if (existing) {
      return json({ success: false, message: "यह बिल पहले से सर्वर पर मौजूद है।" }, 409);
    }

    let customer = null;

    if (mobile) {
      customer = await env.DB.prepare(`
        SELECT id FROM customers
        WHERE workspace_id = ? AND mobile = ?
        LIMIT 1
      `).bind(auth.workspaceId, mobile).first();
    } else {
      customer = await env.DB.prepare(`
        SELECT id FROM customers
        WHERE workspace_id = ? AND name = ? AND (mobile IS NULL OR mobile = '')
        LIMIT 1
      `).bind(auth.workspaceId, customerName).first();
    }

    const customerId = customer?.id || crypto.randomUUID();

    const statements = [];

    if (customer) {
      statements.push(
        env.DB.prepare(`
          UPDATE customers
          SET name = ?, mobile = ?, address = ?
          WHERE id = ? AND workspace_id = ?
        `).bind(customerName, mobile, address, customerId, auth.workspaceId)
      );
    } else {
      statements.push(
        env.DB.prepare(`
          INSERT INTO customers (id, workspace_id, name, mobile, address)
          VALUES (?, ?, ?, ?, ?)
        `).bind(customerId, auth.workspaceId, customerName, mobile, address)
      );
    }

    statements.push(
      env.DB.prepare(`
        INSERT INTO bills (
          id, workspace_id, customer_id, bill_number,
          customer_name, customer_mobile, subtotal, extra_fee,
          total, payment_mode, utr, payment_status, created_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(),
        auth.workspaceId,
        customerId,
        billNumber,
        customerName,
        mobile,
        subtotal,
        extra,
        total,
        paymentMode,
        utr,
        paymentStatus,
        auth.user.id || auth.user.user_id
      )
    );

    for (const item of cleanServices) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO bill_items (id, bill_id, service_name, amount)
          VALUES (?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(),
          billNumber,
          item.name,
          item.amount
        )
      );
    }

    await env.DB.batch(statements);

    return json({
      success: true,
      message: "बिल सर्वर पर सेव हो गया।",
      billNumber
    });

  } catch (error) {
    return json({
      success: false,
      message: "बिल सेव करने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const auth = await getAuth(request, env);
    if (auth.error) return auth.error;

    const url = new URL(request.url);
    const billNumber = String(url.searchParams.get("id") || "").trim();

    if (!billNumber) {
      return json({ success: false, message: "बिल नंबर नहीं मिला।" }, 400);
    }

    const result = await env.DB.prepare(`
      DELETE FROM bills
      WHERE workspace_id = ? AND bill_number = ?
    `).bind(auth.workspaceId, billNumber).run();

    return json({
      success: true,
      deleted: Number(result.meta?.changes || 0)
    });

  } catch (error) {
    return json({
      success: false,
      message: "बिल हटाने में समस्या हुई।",
      error: String(error.message || error)
    }, 500);
  }
}
