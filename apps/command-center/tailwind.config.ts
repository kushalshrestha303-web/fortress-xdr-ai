import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        fortress: {
          bg: "#06080d",
          panel: "#10151d",
          line: "#27313f",
          cyan: "#36d7d7",
          amber: "#f5b84b",
          red: "#ff5d5d",
          green: "#53d18a"
        }
      }
    }
  },
  plugins: []
};

export default config;

