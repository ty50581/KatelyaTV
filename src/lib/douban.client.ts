import { DoubanItem, DoubanResult } from './types';
import { getDoubanProxyUrl } from './utils';

interface DoubanCategoriesParams {
  kind: 'tv' | 'movie';
  category: string;
  type: string;
  pageLimit?: number;
  pageStart?: number;
}

interface TMDBMovieItem {
  id: number;
  title: string;
  poster_path: string | null;
  vote_average: number;
  release_date: string;
}

interface TMDbResponse {
  results: TMDBMovieItem[];
  total_pages: number;
  total_results: number;
}

// ========== 你的 TMDB API Key 已填入 ==========
const TMDB_API_KEY = "770b904f20be269d7b7c5d20b78af81c";
// ==============================================

/**
 * 带超时请求
 */
async function fetchWithTimeout(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  const fetchOptions: RequestInit = {
    ...options,
    signal: controller.signal,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0 Safari/537.36",
      Accept: "application/json",
      ...options.headers,
    },
  };

  try {
    const res = await fetch(url, fetchOptions);
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
 * 前端拉取 TMDB 影视数据（替代豆瓣）
 */
export async function fetchDoubanCategories(
  params: DoubanCategoriesParams
): Promise<DoubanResult> {
  const { kind, pageLimit = 20, pageStart = 0 } = params;
  const page = Math.floor(pageStart / pageLimit) + 1;

  let apiUrl = "";
  const lang = "zh-CN";

  if (kind === "movie") {
    apiUrl = `https://api.themoviedb.org/3/discover/movie?api_key=${TMDB_API_KEY}&language=${lang}&page=${page}&per_page=${pageLimit}&sort_by=popularity.desc`;
  } else {
    apiUrl = `https://api.themoviedb.org/3/discover/tv?api_key=${TMDB_API_KEY}&language=${lang}&page=${page}&per_page=${pageLimit}&sort_by=popularity.desc`;
  }

  const response = await fetchWithTimeout(apiUrl);
  if (!response.ok) throw new Error(`请求失败 ${response.status}`);

  const data: TMDbResponse = await response.json();

  const list: DoubanItem[] = data.results.map((item) => {
    let poster = "";
    if (item.poster_path) {
      // TMDB 标准海报地址，无防盗链
      poster = `https://image.tmdb.org/t/p/w500${item.poster_path}`;
    } else {
      // 无海报时用占位图
      poster = "https://via.placeholder.com/300x450/222/fff?text=暂无海报";
    }

    let year = "";
    if (item.release_date) {
      year = item.release_date.split("-")[0];
    }

    return {
      id: String(item.id),
      title: item.title,
      poster,
      rate: item.vote_average > 0 ? item.vote_average.toFixed(1) : "",
      year,
    };
  });

  return {
    code: 200,
    message: "获取成功",
    list,
  };
}

/**
 * 统一入口
 */
export async function getDoubanCategories(
  params: DoubanCategoriesParams
): Promise<DoubanResult> {
  if (shouldUseDoubanClient()) {
    return fetchDoubanCategories(params);
  } else {
    const { kind, category, type, pageLimit = 20, pageStart = 0 } = params;
    const res = await fetch(
      `/api/douban/categories?kind=${kind}&category=${category}&type=${type}&limit=${pageLimit}&start=${pageStart}`
    );
    if (!res.ok) throw new Error("数据获取失败");
    return res.json();
  }
}
