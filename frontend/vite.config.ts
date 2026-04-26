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
    /* Hashed filenames so each rebuild ships a unique URL — the daemon's
     * cache-control: no-store on index.html guarantees the browser sees
     * the new <script src=…> on next reload, and any in-flight cache of
     * the previous bundle stops mattering. */
    rollupOptions: {
      output: { entryFileNames: "main-[hash].js",
                chunkFileNames: "[name]-[hash].js",
                assetFileNames: "[name]-[hash][extname]" },
    },
  },
});
