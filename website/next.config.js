/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/:path*',
        destination: '/not-found',
      },
    ];
  },
  output: "standalone",
}

module.exports = nextConfig