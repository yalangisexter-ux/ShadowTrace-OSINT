import { serve } from "@hono/node-server";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { app, type Env } from "./index";

const dbPath = path.resolve(process.cwd(), "shadowtrace.db");
const sqlite = new DatabaseSync(dbPath);

const d1Emulator: D1Database = {
  exec: async (query: string) => {
    sqlite.exec(query);
    return { count: 0, duration: 0 } as any;
  },
  prepare: (query: string) => {
    let boundParams: any[] = [];
    const statement: any = {
      bind: (...params: any[]) => {
        boundParams = params;
        return statement;
      },
      first: async <T = unknown>(colName?: string): Promise<T | null> => {
        const stmt = sqlite.prepare(query);
        const row = stmt.get(...boundParams);
        if (!row) return null;
        if (colName) return (row as any)[colName];
        return row as T;
      },
      all: async <T = unknown>(): Promise<any> => {
        const stmt = sqlite.prepare(query);
        const rows = stmt.all(...boundParams);
        return {
          results: rows as T[],
          success: true,
          meta: {} as any,
        };
      },
      run: async (): Promise<any> => {
        const stmt = sqlite.prepare(query);
        const res = stmt.run(...boundParams);
        return {
          success: true,
          meta: {
            last_row_id: Number(res.lastInsertRowid),
            changes: Number(res.changes),
            duration: 0,
          },
        };
      },
    };
    return statement;
  },
  batch: async (statements: any[]) => {
    const results = [];
    for (const s of statements) {
      results.push(await s.run());
    }
    return results;
  },
  dump: async () => new ArrayBuffer(0),
};

const htmlPath = path.resolve(process.cwd(), "frontend", "index.html");
const toolsPath = path.resolve(process.cwd(), "frontend", "osint-tools.json");

// Static assets emulator for local development
const assetsEmulator = {
  fetch: async (req: Request) => {
    const url = new URL(req.url);
    const pathname = url.pathname;
    const targetFile = (pathname === "/" || pathname === "/index.html")
      ? htmlPath
      : path.resolve(process.cwd(), "frontend", pathname.replace(/^\/+/, ""));

    if (fs.existsSync(targetFile) && fs.statSync(targetFile).isFile()) {
      const ext = path.extname(targetFile).toLowerCase();
      const mimeTypes: Record<string, string> = {
        ".html": "text/html; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".png": "image/png",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
      };
      const contentType = mimeTypes[ext] || "application/octet-stream";
      const content = fs.readFileSync(targetFile);
      return new Response(content, {
        status: 200,
        headers: { "Content-Type": contentType },
      });
    }
    return new Response("Not Found", { status: 404 });
  },
};

// Request logger middleware
app.use("*", async (c, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  const status = c.res.status;
  const method = c.req.method;
  const path = c.req.path;
  if (!path.startsWith("/_") && path !== "/favicon.ico") {
    console.log(`[${new Date().toLocaleTimeString()}] ${method} ${path} ${status} (${ms}ms)`);
  }
});

const env: Env = {
  DB: d1Emulator,
  ASSETS: assetsEmulator as any,
  SECRET_KEY: "local-dev-secret-key-32-chars-long-for-jwt",
  APP_ENV: "development",
  ACCESS_TOKEN_MINUTES: "60",
  OFFLINE_MODE: process.env.OFFLINE_MODE || "false",
};

const port = 8000;

serve(
  {
    fetch: (req) => app.fetch(req, env),
    port,
    hostname: "0.0.0.0",
  },
  (info) => {
    console.log(`\n=================================================================`);
    console.log(`  ✅ ShadowTrace OSINT Server is LIVE and READY!`);
    console.log(`  🌐 Web Application: http://localhost:${info.port}/`);
    console.log(`  ⚡ API Health Check: http://localhost:${info.port}/healthz`);
    console.log(`  🧰 OSINT Toolbox:    http://localhost:${info.port}/osint-tools.json`);
    console.log(`  📴 Offline Support:  100% Offline-Ready (Zero Cloud Lock-in)`);
    console.log(`  ---------------------------------------------------------------`);
    console.log(`  * Actively listening for incoming browser & API requests.`);
    console.log(`  * Runs 100% offline with local SQLite D1 & asset emulation.`);
    console.log(`  * Press Ctrl+C in this terminal whenever you wish to stop it.`);
    console.log(`=================================================================\n`);
  }
);
