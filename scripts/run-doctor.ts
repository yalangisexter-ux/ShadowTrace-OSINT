/**
 * Terminal Doctor CLI: Prints verification status for all 15 reference repositories,
 * tool engines, and catalogs.
 * Run with: npm run doctor
 */

import { runDoctorCheck } from "../src/doctor.ts";

console.log("\n=================================================================");
console.log("  🩺 ShadowTrace OSINT — 15 Reference Repositories Doctor Check");
console.log("=================================================================\n");

const report = runDoctorCheck();

console.log(`  System Node:     ${report.system.nodeVersion} (${report.system.platform})`);
console.log(`  Database Engine: ${report.system.database}`);
console.log(`  Indexed APIs:    ${Number(report.catalogs.totalApis).toLocaleString()}`);
console.log(`  OSINT Resources: ${Number(report.catalogs.totalOsintResources).toLocaleString()}\n`);

console.log("-----------------------------------------------------------------");
console.log("  REPOSITORY STATUS (15/15 Upstream Projects):");
console.log("-----------------------------------------------------------------");

for (const repo of report.repositories) {
  const icon = repo.present ? "✅ [OPERATIONAL]" : "❌ [MISSING]";
  const cat = repo.category.toUpperCase().padEnd(16);
  console.log(`  ${icon.padEnd(17)} ${repo.name.padEnd(20)} [${cat}]`);
  console.log(`     └─ ${repo.details}`);
  console.log(`     └─ Path: ${repo.path}\n`);
}

console.log("=================================================================");
console.log(`  Summary: ${report.summary.ready}/${report.summary.total} Repositories Verified & Ready to Run!`);
console.log("=================================================================\n");
