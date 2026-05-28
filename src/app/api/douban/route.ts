export const runtime = 'edge';

import { NextResponse } from 'next/server';

const TMDB_API_KEY = "770b904f20be269d7b7c5d20b78af81c";
const TMDB_IMAGE_BASE = "https://image.tmdb.org/t/p";

interface TMDBItem {
  id: number;
  title?: string;
  name?: string;
  poster_path: string | null;
  vote_average: number;
  release_date?: string;
  first_air_date?: string;
}

interface TMDBResponse {
  results: TMDBItem[];
  total_results: number;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get('type') || 'movie';
  const page = searchParams.get('page') || '1';

  const mediaType = type === 'tv' ? 'tv' : 'movie';
  const apiUrl = `https://api.themoviedb.org/3/discover/${mediaType}?api_key=${TMDB_API_KEY}&language=zh-CN&page=${page}&sort_by=popularity.desc`;

  try {
    const res = await fetch(apiUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0",
        Accept: "application/json",
      },
    });

    if (!res.ok) throw new Error("TMDB 请求失败");
    const data = await res.json() as TMDBResponse;

    const list = data.results.map((item) => {
      const title = item.title || item.name || "未知标题";
      const year = (item.release_date || item.first_air_date || "").slice(0, 4);
      const posterPath = item.poster_path
        ? `${TMDB_IMAGE_BASE}/w500${item.poster_path}`
        : "https://via.placeholder.com/300x450/222/fff?text=暂无海报";

      return {
        id: String(item.id),
        title,
        card_subtitle: year,
        pic: {
          large: posterPath,
          normal: posterPath.replace("/w500", "/w300"),
        },
        rating: { value: Math.round(item.vote_average * 10) / 10 },
      };
    });

    return NextResponse.json({
      total: data.total_results,
      items: list,
      page: Number(page),
    });
  } catch (err) {
    return NextResponse.json({ error: "获取数据失败" }, { status: 500 });
  }
}
