/**
 * Build Script: Indexes all 7 upstream catalog reference repositories into high-speed JSON catalogs.
 * Run with: npm run catalogs:build
 */

import fs from "node:fs";
import path from "node:path";
import {
  parseMarkdownApis,
  parseMarkdownOsint,
  flattenArfJson,
  deduplicateApis,
  deduplicateOsint,
  type CatalogApiItem,
  type CatalogOsintItem,
  type CatalogStats,
} from "../src/catalogs.ts";

const BASE_DIR = path.resolve(process.cwd());
const REFERENCES_DIR = path.resolve(BASE_DIR, "references");
const OUTPUT_DIR = path.resolve(BASE_DIR, "data", "catalogs");

function walkDir(dir: string, filter: (name: string, fullPath: string) => boolean, maxFiles = 500): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  function recurse(current: string) {
    if (results.length >= maxFiles) return;
    try {
      const entries = fs.readdirSync(current, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === ".git" || entry.name === "node_modules") continue;
        const fullPath = path.join(current, entry.name);
        if (entry.isDirectory()) {
          recurse(fullPath);
        } else if (entry.isFile() && filter(entry.name, fullPath)) {
          results.push(fullPath);
          if (results.length >= maxFiles) break;
        }
      }
    } catch {
      // ignore
    }
  }

  recurse(dir);
  return results;
}

export function buildCatalogs() {
  console.log("⚡ Starting ShadowTrace Catalog Indexer across 7 upstream reference repositories...");
  const startTime = Date.now();
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const allApis: CatalogApiItem[] = [];
  const allOsint: CatalogOsintItem[] = [];
  const repoStats: Record<string, { status: string; count: number; description: string }> = {};

  // 1. public-apis
  const pubApisPath = path.join(REFERENCES_DIR, "public-apis", "README.md");
  if (fs.existsSync(pubApisPath)) {
    const content = fs.readFileSync(pubApisPath, "utf8");
    const parsed = parseMarkdownApis(content, "public-apis");
    allApis.push(...parsed);
    repoStats["public-apis"] = { status: "indexed", count: parsed.length, description: "A collective list of free APIs for use in software and web development." };
    console.log(`  ✓ public-apis: ${parsed.length} APIs indexed`);
  } else {
    repoStats["public-apis"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 2. public-api-lists
  const pubListsPath = path.join(REFERENCES_DIR, "public-api-lists", "README.md");
  if (fs.existsSync(pubListsPath)) {
    const content = fs.readFileSync(pubListsPath, "utf8");
    const parsed = parseMarkdownApis(content, "public-api-lists");
    allApis.push(...parsed);
    repoStats["public-api-lists"] = { status: "indexed", count: parsed.length, description: "Curated lists of public APIs across diverse categories." };
    console.log(`  ✓ public-api-lists: ${parsed.length} APIs indexed`);
  } else {
    repoStats["public-api-lists"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 3. free-public-apis
  const freeApisDir = path.join(REFERENCES_DIR, "free-public-apis");
  let freeCount = 0;
  if (fs.existsSync(freeApisDir)) {
    const jsonPath = path.join(freeApisDir, "docs", "data", "apis.json");
    if (fs.existsSync(jsonPath)) {
      try {
        const json = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
        if (Array.isArray(json.apis)) {
          for (const item of json.apis) {
            allApis.push({
              id: `api-free-public-${allApis.length + 1}`,
              name: item.name || "API",
              url: item.docs_url || item.pricing_or_limits_url || "",
              description: item.description || "",
              category: item.category || "General",
              auth: item.authentication || "none",
              https: true,
              cors: "unknown",
              sources: ["free-public-apis"],
            });
            freeCount++;
          }
        }
      } catch (e) {
        console.warn("Could not parse free-public-apis json:", e);
      }
    }
    const freeReadme = path.join(freeApisDir, "README.md");
    if (fs.existsSync(freeReadme)) {
      const parsed = parseMarkdownApis(fs.readFileSync(freeReadme, "utf8"), "free-public-apis");
      allApis.push(...parsed);
      freeCount += parsed.length;
    }
    repoStats["free-public-apis"] = { status: "indexed", count: freeCount, description: "Free public APIs with no key or free tier." };
    console.log(`  ✓ free-public-apis: ${freeCount} APIs indexed`);
  } else {
    repoStats["free-public-apis"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 4. API-mega-list
  const megaDir = path.join(REFERENCES_DIR, "API-mega-list");
  let megaCount = 0;
  if (fs.existsSync(megaDir)) {
    const mdFiles = walkDir(megaDir, (name) => /\.md$/i.test(name), 300);
    for (const f of mdFiles) {
      if (/LICENSE|CONTRIBUTING|FOLLOW_CREATOR|SPONSORED/i.test(path.basename(f))) continue;
      const content = fs.readFileSync(f, "utf8");
      const folderName = path.basename(path.dirname(f));
      const parsed = parseMarkdownApis(content, `API-mega-list:${folderName}`);
      allApis.push(...parsed);
      megaCount += parsed.length;
    }
    repoStats["API-mega-list"] = { status: "indexed", count: megaCount, description: "Mega collection of over 20,000 categorized APIs." };
    console.log(`  ✓ API-mega-list: ${megaCount} APIs indexed from ${mdFiles.length} files`);
  } else {
    repoStats["API-mega-list"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 5. APIs-Hub
  const apisHubPath = path.join(REFERENCES_DIR, "APIs-Hub", "README.md");
  if (fs.existsSync(apisHubPath)) {
    const content = fs.readFileSync(apisHubPath, "utf8");
    const parsed = parseMarkdownApis(content, "APIs-Hub");
    allApis.push(...parsed);
    repoStats["APIs-Hub"] = { status: "indexed", count: parsed.length, description: "Curated collection of developer APIs." };
    console.log(`  ✓ APIs-Hub: ${parsed.length} APIs indexed`);
  } else {
    repoStats["APIs-Hub"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 6. awesome-osint
  const awesomePath = path.join(REFERENCES_DIR, "awesome-osint", "README.md");
  if (fs.existsSync(awesomePath)) {
    const content = fs.readFileSync(awesomePath, "utf8");
    const parsed = parseMarkdownOsint(content, "awesome-osint");
    allOsint.push(...parsed);
    repoStats["awesome-osint"] = { status: "indexed", count: parsed.length, description: "A curated list of amazingly awesome OSINT tools and resources." };
    console.log(`  ✓ awesome-osint: ${parsed.length} OSINT resources indexed`);
  } else {
    repoStats["awesome-osint"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // 7. OSINT-Framework
  const arfPath = path.join(REFERENCES_DIR, "OSINT-Framework", "public", "arf.json");
  if (fs.existsSync(arfPath)) {
    try {
      const arfData = JSON.parse(fs.readFileSync(arfPath, "utf8"));
      const parsed = flattenArfJson(arfData);
      allOsint.push(...parsed);
      repoStats["OSINT-Framework"] = { status: "indexed", count: parsed.length, description: "OSINT Framework focused on gathering information from free tools/resources." };
      console.log(`  ✓ OSINT-Framework: ${parsed.length} OSINT tree nodes indexed`);
    } catch (e) {
      console.warn("Could not parse arf.json:", e);
    }
  } else {
    repoStats["OSINT-Framework"] = { status: "missing", count: 0, description: "Not found in references" };
  }

  // Deduplicate
  console.log("  Deduplicating entries and compiling indexes...");
  const uniqueApis = deduplicateApis(allApis);
  const uniqueOsint = deduplicateOsint(allOsint);

  // Extract unique categories
  const apiCats = Array.from(new Set(uniqueApis.map((a) => a.category).filter(Boolean))).sort();
  const osintCats = Array.from(new Set(uniqueOsint.map((o) => o.category).filter(Boolean))).sort();

  const stats: CatalogStats = {
    indexedAt: new Date().toISOString(),
    totalApis: uniqueApis.length,
    totalOsintResources: uniqueOsint.length,
    apiCategories: apiCats,
    osintCategories: osintCats,
    repositories: repoStats,
  };

  // Write outputs
  fs.writeFileSync(path.join(OUTPUT_DIR, "apis.json"), JSON.stringify(uniqueApis, null, 2), "utf8");
  fs.writeFileSync(path.join(OUTPUT_DIR, "osint.json"), JSON.stringify(uniqueOsint, null, 2), "utf8");
  fs.writeFileSync(path.join(OUTPUT_DIR, "stats.json"), JSON.stringify(stats, null, 2), "utf8");

  const elapsed = Date.now() - startTime;
  console.log(`\n🎉 Indexing completed in ${elapsed}ms:`);
  console.log(`   - Total Unique APIs: ${uniqueApis.length}`);
  console.log(`   - Total OSINT Resources: ${uniqueOsint.length}`);
  console.log(`   - Catalog output stored in: ${OUTPUT_DIR}\n`);

  return stats;
}

// Execute if run directly
buildCatalogs();
