import { DoubanItem, DoubanResult } from './types';
import { getDoubanProxyUrl } from './utils';

interface DoubanCategoriesParams {
  kind: 'tv' | 'movie';
  category: string;
  type: string;
  pageLimit?: number;
  pageStart?: number;
}

interface TMDBItem {
  id: number;
  title?: string;
  name?: string;
  poster_path: string | null;
  vote_average: number;
  release_date?: string;
  first_air_date?: string;
}

interface TMDbResponse {
  results: TMDBItem[];
  total_pages: number;
  total_results: number;
}

// TMDB API Key
const TMDB_API_KEY = "770b904f20be269d7b7c5d20b78af81c";

// 带超时请求
async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0",
        Accept: "application/json",
      },
    });
    clearTimeout(timeoutId);
    return res;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

export function shouldUseDoubanClient(): boolean {
  return getDoubanProxyUrl() !== null;
}

/**
 * TMDB 替代豆瓣
 */
export async function fetchDoubanCategories(
  params: DoubanCategoriesParams
): Promise<DoubanResult> {
  const { kind, pageLimit = 20, pageStart = 0 } = params;
  const page = Math.floor(pageStart / pageLimit) + 1;

  let mediaType = "movie";
  if (kind === "tv") {
    mediaType = "tv";
  }

  const apiUrl = `https://api.themoviedb.org/3/discover/${mediaType}?api_key=${TMDB_API_KEY}&language=zh-CN&page=${page}&sort_by=popularity.desc`;

  const response = await fetchWithTimeout(apiUrl);
  if (!response.ok) {
    throw new Error(`TMDB 请求失败: ${response.status}`);
  }

  const data: TMDbResponse = await response.json();

  // ✅ 强制类型断言，彻底解决类型不匹配报错
  const list = data.results.map((item) => {
    const title = item.title || item.name || "未知标题";
    const year = (item.release_date || item.first_air_date || "").slice(0, 4);
    const posterPath = item.poster_path
      ? `https://image.tmdb.org/t/p/w500${item.poster_path}`
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
  }) as unknown as DoubanItem[];

  return {
    total: data.total_results,
    items: list,
    page,
  } as unknown as DoubanResult;
}

export async function getDoubanCategories(
  params: DoubanCategoriesParams
): Promise<DoubanResult> {
  return fetchDoubanCategories(params);
}
