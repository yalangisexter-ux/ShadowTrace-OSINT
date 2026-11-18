import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0a0d14",
        panel: "#111722",
        line: "#222d3d",
        accent: "#8b9cff",
        mint: "#67e8c1"
      },
      boxShadow: {
        glow: "0 0 40px rgba(139,156,255,.12)"
      }
    }
  },
  plugins: []
};
export default config;
