import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      /* @cosmograph/cosmograph's licensing-manager imports from
       * "@/cosmograph/style.module.css" — that path doesn't resolve for
       * downstream Vite/Rollup consumers. Stub it with an empty CSS module
       * so the bundle builds. */
      "@/cosmograph/style.module.css": fileURLToPath(
        new URL("./src/stubs/cosmograph-style.module.css", import.meta.url),
      ),
    },
  },
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
