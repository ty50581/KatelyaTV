// src/app/api/image-proxy/route.ts
export const runtime = 'edge';

import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const url = searchParams.get('url');

  console.log('收到图片代理请求，地址:', url);

  if (!url) {
    console.error('错误：缺少图片地址');
    return NextResponse.json({ error: '缺少图片地址' }, { status: 400 });
  }

  try {
    console.log('正在请求源图片:', url);
    const response = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://www.themoviedb.org/" // 关键：加个 Referer，模拟浏览器访问
      },
    });

    if (!response.ok) {
      throw new Error(`图片请求失败，状态码: ${response.status}`);
    }

    const imageBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';

    console.log('图片代理成功，返回类型:', contentType);

    // ✅ 加跨域头，解决可能的跨域问题
    return new NextResponse(imageBuffer, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=31536000',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      },
    });
  } catch (error) {
    console.error('图片代理失败:', error);
    const placeholder = await fetch('https://via.placeholder.com/300x450/222/fff?text=加载失败').then(r => r.arrayBuffer());
    return new NextResponse(placeholder, {
      headers: { 
        'Content-Type': 'image/png',
        'Access-Control-Allow-Origin': '*'
      },
      status: 500,
    });
  }
}
