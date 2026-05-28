export async function onRequest({ env }) {
  try {
    // 测试 D1 数据库连接
    const result = await env.DB.prepare("SELECT 1 as test").first();
    return new Response(JSON.stringify({ success: true, result }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
