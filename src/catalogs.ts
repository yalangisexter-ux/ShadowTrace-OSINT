/**
 * ShadowTrace Reference Catalogs Engine
 * Parses, indexes, and queries the 7 upstream API & OSINT reference catalogs:
 * 1. public-apis
 * 2. public-api-lists
 * 3. free-public-apis
 * 4. API-mega-list
 * 5. APIs-Hub
 * 6. awesome-osint
 * 7. OSINT-Framework (arf.json)
 */

import fs from "node:fs";
import path from "node:path";

export interface CatalogApiItem {
  id: string;
  name: string;
  url: string;
  description: string;
  category: string;
  auth: string; // "apiKey" | "OAuth" | "none" | etc.
  https: boolean;
  cors: string; // "yes" | "no" | "unknown"
  sources: string[];
}

export interface CatalogOsintItem {
  id: string;
  name: string;
  url: string;
  description: string;
  category: string;
  categoryPath?: string;
  pricing?: string;
  bestFor?: string;
  opsec?: string;
  opsecNote?: string;
  sources: string[];
  tags: string[];
}

export interface CatalogStats {
  indexedAt: string;
  totalApis: number;
  totalOsintResources: number;
  apiCategories: string[];
  osintCategories: string[];
  repositories: Record<string, { status: string; count: number; description: string }>;
}

const LINK_RE = /(?<!!)\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/;

function cleanStr(s: any): string {
  return String(s ?? "")
    .replace(/`/g, "")
    .replace(/\*\*|__/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function stripMarkdownLinks(s: any): string {
  return cleanStr(String(s ?? "").replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1"));
}

function splitTableRow(line: string): string[] {
  let l = line.trim();
  if (l.startsWith("|")) l = l.slice(1);
  if (l.endsWith("|")) l = l.slice(0, -1);
  return l.split("|").map((c) => c.trim());
}

function isTableSeparator(cells: string[]): boolean {
  return cells.length > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c.replace(/\s/g, "")));
}

function mapApiHeader(cells: string[]): Record<string, number> {
  const map: Record<string, number> = {};
  cells.forEach((c, i) => {
    const h = c.toLowerCase();
    if (/api|name|title/.test(h)) map.name = i;
    else if (/descr/.test(h)) map.description = i;
    else if (/auth|key/.test(h)) map.auth = i;
    else if (/https|ssl/.test(h)) map.https = i;
    else if (/cors/.test(h)) map.cors = i;
    else if (/categ/.test(h)) map.category = i;
  });
  return map;
}

export function parseMarkdownApis(md: string, sourceName: string): CatalogApiItem[] {
  const items: CatalogApiItem[] = [];
  let currentCategory = "General";
  let colMap: Record<string, number> | null = null;

  for (const raw of String(md).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;

    // Header Category
    const headerMatch = /^#{1,6}\s+(.*)$/.exec(line);
    if (headerMatch) {
      const heading = stripMarkdownLinks(headerMatch[1]);
      if (!/table of contents|license|contributing|acknowledg/i.test(heading)) {
        currentCategory = heading;
      }
      colMap = null;
      continue;
    }

    // Markdown Table Row
    if (line.includes("|")) {
      const cells = splitTableRow(line);
      if (isTableSeparator(cells)) continue;

      const linkIdx = cells.findIndex((c) => LINK_RE.test(c));
      if (linkIdx === -1) {
        if (cells.length >= 2) colMap = mapApiHeader(cells);
        continue;
      }

      const match = LINK_RE.exec(cells[linkIdx]);
      if (!match) continue;

      const map = colMap || {};
      const descIdx = map.description ?? (linkIdx === 0 ? 1 : -1);
      const authIdx = map.auth ?? 2;
      const httpsIdx = map.https ?? 3;
      const corsIdx = map.cors ?? 4;
      const catIdx = map.category ?? -1;

      const authRaw = authIdx >= 0 && authIdx < cells.length ? cleanStr(cells[authIdx]) : "";
      const httpsRaw = httpsIdx >= 0 && httpsIdx < cells.length ? cleanStr(cells[httpsIdx]).toLowerCase() : "";
      const corsRaw = corsIdx >= 0 && corsIdx < cells.length ? cleanStr(cells[corsIdx]).toLowerCase() : "";
      const catRaw = catIdx >= 0 && catIdx < cells.length ? stripMarkdownLinks(cells[catIdx]) : currentCategory;

      items.push({
        id: `api-${sourceName}-${items.length + 1}`,
        name: cleanStr(match[1]),
        url: match[2],
        description: descIdx >= 0 && descIdx < cells.length ? stripMarkdownLinks(cells[descIdx]).slice(0, 400) : "",
        category: catRaw || currentCategory,
        auth: !authRaw || /^(no|none|n\/a|-)$/i.test(authRaw) ? "none" : authRaw,
        https: /^(yes|true|y|✓|✔)/i.test(httpsRaw),
        cors: /^(yes|true|y|✓|✔)/i.test(corsRaw) ? "yes" : /^(no|false|n|✗|✘)/i.test(corsRaw) ? "no" : "unknown",
        sources: [sourceName],
      });
      continue;
    }

    // Bullet list link
    const bulletMatch = /^(?:[-*+]|\d+\.)\s+(.*)$/.exec(line);
    if (bulletMatch) {
      const linkMatch = LINK_RE.exec(bulletMatch[1]);
      if (linkMatch) {
        const after = bulletMatch[1].slice(bulletMatch[1].indexOf(linkMatch[0]) + linkMatch[0].length).replace(/^[\s:–—-]+/, "");
        items.push({
          id: `api-${sourceName}-${items.length + 1}`,
          name: cleanStr(linkMatch[1]),
          url: linkMatch[2],
          description: stripMarkdownLinks(after).slice(0, 400),
          category: currentCategory,
          auth: "none",
          https: linkMatch[2].startsWith("https://"),
          cors: "unknown",
          sources: [sourceName],
        });
      }
    }
  }

  return items;
}

export function parseMarkdownOsint(md: string, sourceName: string): CatalogOsintItem[] {
  const items: CatalogOsintItem[] = [];
  let currentCategory = "General OSINT";

  for (const raw of String(md).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;

    const headerMatch = /^#{1,6}\s+(.*)$/.exec(line);
    if (headerMatch) {
      const heading = stripMarkdownLinks(headerMatch[1]);
      if (!/table of contents|license|contributing|acknowledg|awesome osint/i.test(heading)) {
        currentCategory = heading;
      }
      continue;
    }

    const bulletMatch = /^(?:[-*+]|\d+\.)\s+(.*)$/.exec(line);
    if (bulletMatch) {
      const linkMatch = LINK_RE.exec(bulletMatch[1]);
      if (linkMatch) {
        const after = bulletMatch[1].slice(bulletMatch[1].indexOf(linkMatch[0]) + linkMatch[0].length).replace(/^[\s:–—-]+/, "");
        items.push({
          id: `osint-${sourceName}-${items.length + 1}`,
          name: cleanStr(linkMatch[1]),
          url: linkMatch[2],
          description: stripMarkdownLinks(after).slice(0, 400),
          category: currentCategory,
          categoryPath: currentCategory,
          pricing: "free",
          sources: [sourceName],
          tags: [currentCategory.toLowerCase().replace(/[^a-z0-9]+/g, "-")],
        });
      }
    }
  }

  return items;
}

export function flattenArfJson(node: any, trail: string[] = []): CatalogOsintItem[] {
  const out: CatalogOsintItem[] = [];
  if (!node || typeof node !== "object") return out;

  const currentPath = node.name ? [...trail, cleanStr(node.name)] : trail;

  if (node.url && /^https?:\/\//i.test(node.url)) {
    const category = trail[1] || trail[0] || "OSINT Framework";
    out.push({
      id: `arf-${out.length + 1}`,
      name: cleanStr(node.name),
      url: node.url,
      description: cleanStr(node.description || currentPath.join(" › ")).slice(0, 400),
      category,
      categoryPath: currentPath.join(" › "),
      pricing: node.pricing || "free",
      bestFor: node.bestFor,
      opsec: node.opsec,
      opsecNote: node.opsecNote,
      sources: ["OSINT-Framework"],
      tags: trail.map((t) => t.toLowerCase().replace(/[^a-z0-9]+/g, "-")),
    });
  }

  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      out.push(...flattenArfJson(child, currentPath));
    }
  }

  return out;
}

export function deduplicateApis(items: CatalogApiItem[]): CatalogApiItem[] {
  const map = new Map<string, CatalogApiItem>();
  for (const item of items) {
    const key = item.url.toLowerCase().replace(/\/+$/, "");
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...item });
    } else {
      if (!existing.sources.includes(item.sources[0])) {
        existing.sources.push(item.sources[0]);
      }
      if (!existing.description && item.description) {
        existing.description = item.description;
      }
      if (existing.auth === "none" && item.auth !== "none") {
        existing.auth = item.auth;
      }
    }
  }
  return Array.from(map.values());
}

export function deduplicateOsint(items: CatalogOsintItem[]): CatalogOsintItem[] {
  const map = new Map<string, CatalogOsintItem>();
  for (const item of items) {
    const key = item.url.toLowerCase().replace(/\/+$/, "");
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...item });
    } else {
      if (!existing.sources.includes(item.sources[0])) {
        existing.sources.push(item.sources[0]);
      }
      if (!existing.description && item.description) {
        existing.description = item.description;
      }
      for (const t of item.tags) {
        if (!existing.tags.includes(t)) existing.tags.push(t);
      }
    }
  }
  return Array.from(map.values());
}

// In-Memory Cached Storage for Quick Search & API Responses
let cachedApis: CatalogApiItem[] | null = null;
let cachedOsint: CatalogOsintItem[] | null = null;
let cachedStats: CatalogStats | null = null;

export function loadCatalogsFromDisk(baseDir: string = process.cwd()): { apis: CatalogApiItem[]; osint: CatalogOsintItem[]; stats: CatalogStats | null } {
  const dataDir = path.resolve(baseDir, "data", "catalogs");
  const apisPath = path.join(dataDir, "apis.json");
  const osintPath = path.join(dataDir, "osint.json");
  const statsPath = path.join(dataDir, "stats.json");

  let apis: CatalogApiItem[] = [];
  let osint: CatalogOsintItem[] = [];
  let stats: CatalogStats | null = null;

  try {
    if (fs.existsSync(apisPath)) {
      apis = JSON.parse(fs.readFileSync(apisPath, "utf8"));
      cachedApis = apis;
    }
    if (fs.existsSync(osintPath)) {
      osint = JSON.parse(fs.readFileSync(osintPath, "utf8"));
      cachedOsint = osint;
    }
    if (fs.existsSync(statsPath)) {
      stats = JSON.parse(fs.readFileSync(statsPath, "utf8"));
      cachedStats = stats;
    }
  } catch (e) {
    console.warn("Notice loading catalog files:", e);
  }

  return { apis, osint, stats };
}

export function queryApis(params: {
  q?: string;
  category?: string;
  auth?: string;
  https?: string;
  source?: string;
  page?: number;
  limit?: number;
}): { total: number; page: number; limit: number; items: CatalogApiItem[] } {
  if (!cachedApis) {
    loadCatalogsFromDisk();
  }
  const apis = cachedApis || [];

  const tokens = String(params.q || "").toLowerCase().split(/\s+/).filter(Boolean);
  const cat = String(params.category || "").toLowerCase();
  const authVal = String(params.auth || "").toLowerCase();
  const sourceVal = String(params.source || "").toLowerCase();
  const wantHttps = params.https === "true" ? true : params.https === "false" ? false : null;

  const filtered = apis.filter((item) => {
    if (cat && !item.category.toLowerCase().includes(cat)) return false;
    if (authVal && !item.auth.toLowerCase().includes(authVal)) return false;
    if (sourceVal && !item.sources.some((s) => s.toLowerCase().includes(sourceVal))) return false;
    if (wantHttps !== null && item.https !== wantHttps) return false;
    if (tokens.length > 0) {
      const hay = `${item.name.toLowerCase()} ${item.description.toLowerCase()} ${item.category.toLowerCase()}`;
      if (!tokens.every((t) => hay.includes(t))) return false;
    }
    return true;
  });

  const page = Math.max(1, Number(params.page) || 1);
  const limit = Math.min(200, Math.max(1, Number(params.limit) || 40));
  const start = (page - 1) * limit;

  return {
    total: filtered.length,
    page,
    limit,
    items: filtered.slice(start, start + limit),
  };
}

export function queryOsint(params: {
  q?: string;
  category?: string;
  source?: string;
  page?: number;
  limit?: number;
}): { total: number; page: number; limit: number; items: CatalogOsintItem[] } {
  if (!cachedOsint) {
    loadCatalogsFromDisk();
  }
  const osint = cachedOsint || [];

  const tokens = String(params.q || "").toLowerCase().split(/\s+/).filter(Boolean);
  const cat = String(params.category || "").toLowerCase();
  const sourceVal = String(params.source || "").toLowerCase();

  const filtered = osint.filter((item) => {
    if (cat && !item.category.toLowerCase().includes(cat) && !item.categoryPath?.toLowerCase().includes(cat)) return false;
    if (sourceVal && !item.sources.some((s) => s.toLowerCase().includes(sourceVal))) return false;
    if (tokens.length > 0) {
      const hay = `${item.name.toLowerCase()} ${item.description.toLowerCase()} ${item.category.toLowerCase()} ${item.tags.join(" ")}`;
      if (!tokens.every((t) => hay.includes(t))) return false;
    }
    return true;
  });

  const page = Math.max(1, Number(params.page) || 1);
  const limit = Math.min(200, Math.max(1, Number(params.limit) || 40));
  const start = (page - 1) * limit;

  return {
    total: filtered.length,
    page,
    limit,
    items: filtered.slice(start, start + limit),
  };
}

export function getStats(): CatalogStats {
  if (!cachedStats) {
    loadCatalogsFromDisk();
  }
  if (cachedStats) return cachedStats;

  return {
    indexedAt: new Date().toISOString(),
    totalApis: cachedApis?.length || 0,
    totalOsintResources: cachedOsint?.length || 0,
    apiCategories: [],
    osintCategories: [],
    repositories: {},
  };
}
