import { DoubanItem, DoubanResult } from './types';
import { getDoubanProxyUrl } from './utils';

export function shouldUseDoubanClient(): boolean {
  return true;
}

interface Params {
  kind: 'tv' | 'movie';
  pageLimit?: number;
  pageStart?: number;
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
