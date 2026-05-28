// src/app/api/image-proxy/route.ts
export const runtime = 'edge';

import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const url = searchParams.get('url');

  if (!url) {
    return NextResponse.json({ error: '缺少图片地址' }, { status: 400 });
  }

  try {
    // 请求源图片
    const response = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
    });

    if (!response.ok) {
      throw new Error('图片请求失败');
    }

    // 获取图片的二进制数据和类型
    const imageBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';

    // 返回图片
    return new NextResponse(imageBuffer, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=31536000', // 缓存一年，提高速度
      },
    });
  } catch (error) {
    console.error('图片代理失败:', error);
    // 返回一个占位图
    const placeholder = await fetch('https://via.placeholder.com/300x450/222/fff?text=加载失败').then(r => r.arrayBuffer());
    return new NextResponse(placeholder, {
      headers: { 'Content-Type': 'image/png' },
      status: 500,
    });
  }
}
