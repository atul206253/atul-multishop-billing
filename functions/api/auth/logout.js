
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const item of cookieHeader.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return rest.join("=");
  }

  return null;
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

const clearCookie =
  "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

export async function onRequestPost({ request, env }) {
  try {
    const origin = request.headers.get("Origin");

    if (!origin || origin !== new URL(request.url).origin) {
      return json({ success: false, message: "Invalid request origin." }, 403);
    }

    if (!env.DB) {
      return json({ success: false, message: "Database binding missing." }, 500);
    }

    const token = getCookie(request, "session");

    if (token) {
      const tokenHash = await sha256(token);

      await env.DB.prepare(`
        DELETE FROM sessions WHERE token_hash = ?
      `).bind(tokenHash).run();
    }

    return json(
      { success: true, message: "Logout सफल।" },
      200,
      { "Set-Cookie": clearCookie }
    );

  } catch (error) {
    return json(
      { success: false, message: "Logout में समस्या हुई।" },
      500
    );
  }
}
