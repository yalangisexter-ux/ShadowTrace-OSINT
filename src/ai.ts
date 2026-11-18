/**
 * Evidence-first analysis. This module summarizes source responses; it does
 * not infer identity, manufacture dates, or turn missing data into findings.
 */
export interface AISummaryResult {
  executiveSummary: string;
  executive_summary?: string;
  threatLevel: "UNKNOWN" | "LOW" | "ELEVATED" | "HIGH" | "CRITICAL";
  threatScore: number;
  threat_radar?: { score: number; level: "UNKNOWN" | "LOW" | "ELEVATED" | "HIGH" | "CRITICAL"; factors: string[] };
  keyFindings: string[];
  key_findings?: string[];
  timeline: {
    date: string;
    timestamp?: string;
    title: string;
    event?: string;
    description: string;
    source: string;
    provider?: string;
    category: string;
  }[];
  recommendedPivots: {
    label?: string;
    query: string;
    type: string;
    reason: string;
    priority: "high" | "medium" | "low";
  }[];
  recommended_pivots?: {
    label?: string;
    query: string;
    type: string;
    reason: string;
    priority?: "high" | "medium" | "low";
  }[];
  anomalyFlags: string[];
  anomaly_flags?: string[];
}

interface EvidenceInput {
  provider: string;
  category?: string | null;
  profile_url?: string | null;
  domain?: string | null;
  status: string;
  identity_name?: string | null;
  identifier_display?: string | null;
  confidence?: string | null;
  detail?: string | null;
  extra_fields?: Record<string, string>;
  checked_at?: string;
}

export function generateAISummary(
  query: string,
  searchType: string,
  entities: {
    names?: string[];
    profile_pictures?: string[];
    banners?: string[];
    usernames?: string[];
    emails?: string[];
    phones?: string[];
    first_seen?: string;
    last_seen?: string;
  },
  evidence: EvidenceInput[],
  threatMatrix?: {
    overall_threat_score: number;
    risk_level: string;
    categories?: Record<string, { score: number; label: string }>;
  }
): AISummaryResult {
  const candidates = evidence.filter(e => e.status === "candidate");
  const observations = evidence.filter(e => e.status === "observed");
  const inconclusive = evidence.filter(e => e.status === "inconclusive");
  const score = threatMatrix?.overall_threat_score ?? 0;
  const isAssessed = Boolean(threatMatrix && threatMatrix.risk_level !== "unassessed" && threatMatrix.risk_level !== "unknown");
  const threatLevel: AISummaryResult["threatLevel"] = !isAssessed ? "UNKNOWN" :
    score >= 75 ? "CRITICAL" : score >= 55 ? "HIGH" : score >= 35 ? "ELEVATED" : "LOW";

  const anomalyFlags: string[] = [];
  for (const item of evidence) {
    const cves = item.extra_fields?.["CVE identifiers"] || item.extra_fields?.["Known Vulnerabilities (CVEs)"];
    if (item.status === "observed" && cves && cves !== "None returned" && cves !== "None detected") {
      anomalyFlags.push(`Source-reported vulnerability identifiers for ${item.provider}: ${cves}`);
    }
    const breachCount = item.extra_fields?.["Breach count"] || item.extra_fields?.["Exposure count"];
    if (item.status === "observed" && breachCount && Number(breachCount) > 0) {
      anomalyFlags.push(`A breach source reported ${breachCount} exposure(s); review the source record and date.`);
    }
  }

  const keyFindings = [
    `Investigation target: ${query} (${searchType}).`,
    `${evidence.length} source result(s): ${observations.length} technical observation(s), ${candidates.length} candidate profile lead(s), and ${inconclusive.length} inconclusive check(s).`,
    "No person or account ownership is established by correlation alone. Review each source record independently.",
  ];
  if (entities.names?.length) keyFindings.push(`Names returned by sources: ${entities.names.join(", ")}.`);
  if (entities.usernames?.length) keyFindings.push(`Usernames returned by sources: ${entities.usernames.join(", ")}.`);
  if (entities.emails?.length) keyFindings.push(`${entities.emails.length} email indicator(s) are attached to this investigation.`);
  if (entities.phones?.length) keyFindings.push(`${entities.phones.length} phone indicator(s) are attached to this investigation.`);

  // This is a collection timeline only. It is not a historical first-seen/last-seen timeline.
  const timeline = evidence
    .filter(item => item.checked_at && item.status !== "inconclusive")
    .map(item => ({
      date: item.checked_at as string,
      timestamp: item.checked_at as string,
      title: item.status === "candidate" ? "Candidate profile returned" : item.status === "observed" ? "Source observation returned" : "Source returned no match",
      event: `${item.provider}: ${item.detail || item.status}`,
      description: item.detail || item.status,
      source: item.provider,
      provider: item.provider,
      category: item.category || "collection",
    }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const recommendedPivots: AISummaryResult["recommendedPivots"] = [];
  const addPivot = (value: string, type: string, reason: string) => {
    if (!value || value.toLowerCase() === query.toLowerCase()) return;
    if (recommendedPivots.some(p => p.query.toLowerCase() === value.toLowerCase() && p.type === type)) return;
    recommendedPivots.push({ query: value, type, reason, priority: "medium" });
  };
  for (const email of entities.emails || []) addPivot(email, "email", "Source-returned email indicator; investigate as a separate lead.");
  for (const phone of entities.phones || []) addPivot(phone, "phone", "Source-returned phone indicator; number parsing does not establish subscriber identity.");
  for (const username of entities.usernames || []) addPivot(username, "username", "Source-returned username indicator; verify the profile with its original provider.");
  if (searchType === "email" && query.includes("@")) {
    addPivot(query.split("@")[1], "domain", "Inspect the email domain's DNS and RDAP records; this does not validate the mailbox.");
  }

  const executiveSummary = [
    `### Evidence summary: ${query}`,
    "",
    `ShadowTrace ran deterministic, rule-based evidence synthesis (no generative AI model is configured) for this ${searchType} indicator. It returned ${evidence.length} result(s): ${observations.length} observed technical fact(s), ${candidates.length} candidate profile lead(s), ${inconclusive.length} inconclusive check(s), and ${evidence.filter(e => e.status === "not_found").length} negative result(s).`,
    "",
    isAssessed
      ? `A source-backed risk score of ${score}/100 was calculated (${threatLevel}). Review the supporting indicators before drawing conclusions.`
      : "Threat level is UNKNOWN / UNASSESSED. No defensible risk score is available from the current evidence.",
    "",
    "This report does not assert that separate records belong to the same person. Candidate matches require manual verification.",
  ].join("\n");

  const normalizedPivots = recommendedPivots.map(p => ({ ...p, label: `${p.type.toUpperCase()}: ${p.query}` }));
  return {
    executiveSummary,
    executive_summary: executiveSummary,
    threatLevel,
    threatScore: isAssessed ? score : 0,
    threat_radar: { score: isAssessed ? score : 0, level: threatLevel, factors: anomalyFlags },
    keyFindings,
    key_findings: keyFindings,
    timeline,
    recommendedPivots: normalizedPivots,
    recommended_pivots: normalizedPivots,
    anomalyFlags,
    anomaly_flags: anomalyFlags,
  };
}
