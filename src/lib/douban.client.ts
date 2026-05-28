import { DoubanItem, DoubanResult } from './types';
import { getDoubanProxyUrl } from './utils';

export function shouldUseDoubanClient(): boolean {
  return true;
}

export async function fetchDoubanCategories(
  params: any
): Promise<DoubanResult> {
  const { kind, pageLimit = 20, pageStart = 0 } = params;
  const page = Math.floor(pageStart / pageLimit) + 1;
  const type = kind === 'tv' ? 'tv' : 'movie';

  // 调用我们新建的后端接口
  const res = await fetch(`/api/douban?type=${type}&page=${page}`, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "application/json",
    },
  });

  if (!res.ok) throw new Error("获取数据失败");
  const data = await res.json();
  return data;
}

export async function getDoubanCategories(
  params: any
): Promise<DoubanResult> {
  return fetchDoubanCategories(params);
}
