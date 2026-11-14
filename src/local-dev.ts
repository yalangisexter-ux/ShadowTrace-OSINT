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
const htmlContent = fs.readFileSync(htmlPath, "utf-8");

// Mount static frontend for local dev
app.get("/", (c) => {
  return c.html(htmlContent);
});
app.get("/index.html", (c) => {
  return c.html(htmlContent);
});

const env: Env = {
  DB: d1Emulator,
  SECRET_KEY: "local-dev-secret-key-32-chars-long-for-jwt",
  APP_ENV: "development",
  ACCESS_TOKEN_MINUTES: "60",
};

const port = 8000;
console.log(`ShadowTrace OSINT local server starting on http://localhost:${port}`);

serve({
  fetch: (req) => app.fetch(req, env),
  port,
});
