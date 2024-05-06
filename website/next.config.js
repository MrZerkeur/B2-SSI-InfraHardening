/** @type {import('next').NextConfig} */
const cspHeader = `
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
`

const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/:path*',
        destination: '/not-found',
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: cspHeader.replace(/\n/g, ''),
          },
        ],
      },
    ]
  },
  output: "standalone",
}

module.exports = nextConfig