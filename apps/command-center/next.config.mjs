const nextConfig = {
  output: "standalone",
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "/fortress-api"
  },
  async rewrites() {
    return [
      {
        source: "/fortress-api/:path*",
        destination: `${process.env.BACKEND_API_URL || "http://127.0.0.1:8090"}/:path*`
      }
    ];
  }
};

export default nextConfig;
