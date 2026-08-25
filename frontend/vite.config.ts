import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig(({ mode }) => ({
  root: fileURLToPath(new URL(".", import.meta.url)),
  // IMPORTANT: keep workspace-contained prototype behavior tests on the product renderer instance.
  resolve: {
    alias: mode === "test" ? {
      react: fileURLToPath(new URL("../node_modules/react", import.meta.url)),
      "react-dom": fileURLToPath(new URL("../node_modules/react-dom", import.meta.url)),
      "@phosphor-icons/react": fileURLToPath(new URL("./src/test/phosphorIconsStub.jsx", import.meta.url)),
    } : {},
    dedupe: ["react", "react-dom"],
  },
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    manifest: true,
  },
  server: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
    restoreMocks: true,
    // IMPORTANT: bound cold-install Windows contention without weakening async or test timeouts.
    maxWorkers: 4,
  },
}));
