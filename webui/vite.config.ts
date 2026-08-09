import { defineConfig, type PluginOption } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

// Vite produces a static SPA bundle that is served from `internal/web/static`
// by the Go server. Entry and CSS filenames include content hashes so a binary
// upgrade cannot keep executing a stale dashboard bundle from browser/proxy
// cache. The generated index.html is the source of truth for asset URLs.

// Port the auto-spawned mock backend binds to. We deliberately pick a port
// *other* than 8080 because cloud dev sandboxes (notably the v0 preview)
// already have something on 8080 — its own port-proxy — which returns
// Go's stock "404 page not found" for every path. Proxying to 8080 in
// that environment makes the SPA think the API is broken.
const MOCK_PORT = Number(process.env.VITE_MOCK_PORT) || 8787;

/**
 * In production the SPA is served by the embedded Go server, which also
 * handles `/api/*`. In local dev (and in the v0 preview sandbox) the Go
 * binary usually isn't running, so without this plugin `/api/auth/status`
 * 404s and the SPA gets stuck on a deceptive login screen.
 *
 * This plugin spawns `node mock-backend.mjs` alongside Vite whenever:
 *   - we're in `serve` (dev) mode, AND
 *   - the operator hasn't pointed VITE_API_TARGET at a real backend, AND
 *   - they haven't opted out with `VITE_DISABLE_MOCK=1`.
 *
 * The child listens on MOCK_PORT and the Vite proxy is wired to it
 * automatically (see `server.proxy` below). The child is killed when
 * Vite shuts down so we don't leak processes across restarts.
 */
function mockBackendPlugin(): PluginOption {
  let child: ChildProcess | null = null;
  return {
    name: "xalgorix:mock-backend",
    apply: "serve",
    configureServer(server) {
      if (process.env.VITE_DISABLE_MOCK === "1" || process.env.VITE_API_TARGET) {
        return;
      }
      const mockPath = path.resolve(__dirname, "mock-backend.mjs");
      try {
        child = spawn(process.execPath, [mockPath], {
          stdio: ["ignore", "inherit", "inherit"],
          env: { ...process.env, PORT: String(MOCK_PORT) },
        });
        child.on("exit", (code, signal) => {
          if (code !== 0 && signal !== "SIGTERM" && signal !== "SIGINT") {
            server.config.logger.warn(
              `[mock-backend] exited unexpectedly (code=${code} signal=${signal})`,
            );
          }
          child = null;
        });
        server.config.logger.info(
          `[mock-backend] spawned on :${MOCK_PORT} (set VITE_API_TARGET to use a real backend, or VITE_DISABLE_MOCK=1 to skip)`,
        );
      } catch (err) {
        server.config.logger.warn(
          `[mock-backend] failed to spawn: ${(err as Error).message}`,
        );
      }
      const stop = () => {
        if (child && !child.killed) child.kill("SIGTERM");
      };
      server.httpServer?.once("close", stop);
      process.once("exit", stop);
    },
  };
}

// Resolve the API target once: explicit VITE_API_TARGET wins (operator
// pointing at a real Go server), otherwise fall back to the mock that
// `mockBackendPlugin` just spawned.
const API_TARGET = process.env.VITE_API_TARGET || `http://localhost:${MOCK_PORT}`;

export default defineConfig({
  plugins: [react(), tailwindcss(), mockBackendPlugin()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  build: {
    outDir: path.resolve(__dirname, "../internal/web/static"),
    emptyOutDir: true,
    target: "es2020",
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/app-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": API_TARGET,
      "/ws": { target: API_TARGET.replace(/^http/, "ws"), ws: true },
      "/uploads": API_TARGET,
    },
  },
});
