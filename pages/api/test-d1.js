export default async function handler(req, res) {
  try {
    // 读取Cloudflare Pages的环境变量
    const { env } = process;
    const result = await env.DB.prepare("SELECT 1 as test").first();
    res.status(200).json({ success: true, result });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
}
