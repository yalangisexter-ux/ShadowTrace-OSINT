import test from "node:test";
import assert from "node:assert/strict";
import { runMaigretScan } from "../src/maigret.ts";
import { runReconNgScan } from "../src/recon_ng.ts";
import { runAmassScan } from "../src/amass.ts";
import { runSubfinderScan } from "../src/subfinder.ts";
import { queryApis, queryOsint, getStats } from "../src/catalogs.ts";
import { runDoctorCheck, ALL_REPOSITORIES } from "../src/doctor.ts";

test("Doctor check verifies all 15 reference repositories", () => {
  const report = runDoctorCheck();
  assert.equal(report.summary.total, 15);
  assert.equal(report.summary.ready, 15);
  assert.equal(report.summary.missing, 0);
  assert.ok(report.catalogs.totalApis > 1000);
  assert.ok(report.catalogs.totalOsintResources > 500);

  const repos = report.repositories.map((r) => r.id);
  for (const expected of [
    "public-apis", "public-api-lists", "free-public-apis", "api-mega-list", "apis-hub",
    "awesome-osint", "osint-framework",
    "sherlock", "maigret", "theharvester", "spiderfoot", "phoneinfoga", "recon-ng", "amass", "subfinder"
  ]) {
    assert.ok(repos.includes(expected), `Missing expected repo ${expected}`);
  }
});

test("Catalogs query engine searches indexed APIs and OSINT resources", () => {
  // Query APIs
  const apiRes = queryApis({ q: "weather", limit: 5 });
  assert.ok(apiRes.total > 0);
  assert.ok(apiRes.items.length <= 5);
  assert.ok(apiRes.items.some((item) => /weather|climate/i.test(item.name + item.description + item.category)));

  // Query OSINT resources
  const osintRes = queryOsint({ q: "username", limit: 5 });
  assert.ok(osintRes.total > 0);
  assert.ok(osintRes.items.some((item) => /user|social|name/i.test(item.name + item.description + item.category)));

  // Stats
  const stats = getStats();
  assert.ok(stats.totalApis >= 10000);
  assert.ok(stats.totalOsintResources >= 2000);
});

test("Maigret offline scan synthesizes candidate URLs across loaded sites", async () => {
  const results = await runMaigretScan("osint_target_analyst", { offline: true, limit: 10 });
  assert.equal(results.length, 10);
  for (const r of results) {
    assert.equal(r.status, "candidate");
    assert.ok(r.url.includes("osint_target_analyst"));
    assert.ok(r.detail.includes("Offline Maigret Recon"));
  }
});

test("Recon-ng scan discovers subdomains and administrative points of contact", async () => {
  const result = await runReconNgScan("example.com", { offline: true });
  assert.equal(result.tool, "recon-ng");
  assert.equal(result.targetDomain, "example.com");
  assert.ok(result.hosts.length >= 5);
  assert.ok(result.contacts.length >= 2);
  assert.ok(result.contacts.some((c) => c.email.includes("@example.com")));
});

test("OWASP Amass scan constructs attack surface graph topology", async () => {
  const result = await runAmassScan("example.org", { offline: true });
  assert.equal(result.tool, "amass");
  assert.equal(result.targetDomain, "example.org");
  assert.ok(result.assets.length >= 5);
  assert.ok(result.relations.length >= 4);
  assert.ok(result.relations.some((r) => r.relationship === "subdomain_of"));
});

test("Subfinder passive discovery outputs deduplicated subdomains", async () => {
  const result = await runSubfinderScan("example.net", { offline: true });
  assert.equal(result.tool, "subfinder");
  assert.equal(result.targetDomain, "example.net");
  assert.ok(result.subdomains.length >= 4);
  assert.ok(result.subdomains.every((s) => s.endsWith("example.net")));
});
