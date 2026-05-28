import { DoubanItem, DoubanResult } from './types';

export function shouldUseDoubanClient(): boolean {
  return true;
}

// 兼容页面传来的 category / type 字段
interface Params {
  kind: 'tv' | 'movie';
  pageLimit?: number;
  pageStart?: number;
  category?: string;
  type?: string;
}

export async function fetchDoubanCategories(
  params: Params
): Promise<DoubanResult> {
  const { kind, pageLimit = 20, pageStart = 0 } = params;
  const page = Math.floor(pageStart / pageLimit) + 1;
  const type = kind === 'tv' ? 'tv' : 'movie';

  const res = await fetch(`/api/douban?type=${type}&page=${page}`, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "application/json",
    },
  });

  if (!res.ok) throw new Error("获取数据失败");
  const data = await res.json();
  return data as DoubanResult;
}

export async function getDoubanCategories(
  params: Params
): Promise<DoubanResult> {
  return fetchDoubanCategories(params);
}
