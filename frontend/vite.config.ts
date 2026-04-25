import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api":    { target: "http://127.0.0.1:8080", changeOrigin: true },
      "/stream": { target: "ws://127.0.0.1:8080",  ws: true },
    },
  },
  build: {
    outDir: "dist",
    assetsDir: ".",
    rollupOptions: {
      output: { entryFileNames: "main.js", chunkFileNames: "[name].js",
                assetFileNames: "[name][extname]" },
    },
  },
});
