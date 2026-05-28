/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    // 允许 Next.js 加载这些域名的图片
    domains: [
      'image.tmdb.org',
      'wsrv.nl'
    ],
  },
}

module.exports = nextConfig
