export async function onRequestGet({ env }) {
  try {
    if (!env.DB) {
      return Response.json(
        {
          success: false,
          message: "D1 Database binding DB नहीं मिला।"
        },
        { status: 500 }
      );
    }

    const result = await env.DB
      .prepare("SELECT 1 AS database_connected")
      .first();

    return Response.json({
      success: true,
      message: "Backend API और Database सही काम कर रहे हैं।",
      database: result?.database_connected === 1 ? "Connected" : "Error",
      project: "Atul Multi-Shop Billing"
    });

  } catch (error) {
    return Response.json(
      {
        success: false,
        message: "Database connection failed.",
        error: error.message
      },
      { status: 500 }
    );
  }
}
