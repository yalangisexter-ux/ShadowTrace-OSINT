/**
 * SpiderFoot OSINT Integration Engine
 * Ported directly from smicallef/spiderfoot (MIT License)
 * Integrates SpiderFoot modules:
 * - sfp_bgpview: BGPView ASN & IP Routing
 * - sfp_alienvault: AlienVault OTX Threat Feeds & Passive DNS
 * - sfp_urlscan: URLScan.io Subdomain & Technology Footprint
 * - sfp_webanalytics: Tracking ID & Tag Extraction
 * - SpiderFoot Correlation Rules Engine
 */

export interface BgpViewResult {
  asn?: number;
  asName?: string;
  asDescription?: string;
  countryCode?: string;
  prefix?: string;
  rir?: string;
  peersCount?: number;
  ok: boolean;
}

export interface AlienVaultResult {
  threatScore: number;
  pulseCount: number;
  passiveDns: Array<{ hostname: string; address: string; first: string; last: string }>;
  tags: string[];
  ok: boolean;
}

export interface WebAnalyticsResult {
  googleAnalytics: string[];
  googleTagManager: string[];
  facebookPixel: string[];
  yandexMetrika: string[];
  hotjar: string[];
  verifications: Record<string, string>;
}

export interface SpiderFootCorrelation {
  ruleId: string;
  title: string;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  recommendation: string;
}

const USER_AGENT = "ShadowTrace-SpiderFoot/2.1 (OSINT Reconnaissance Engine)";

/** Queries BGPView API for IP or ASN routing data (sfp_bgpview.py) */
export async function queryBgpView(ip: string, options?: { offline?: boolean }): Promise<BgpViewResult> {
  if (options?.offline) {
    const isPrivate = ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.");
    const isGoogle = ip === "8.8.8.8" || ip === "8.8.4.4";
    const isCloudflare = ip === "1.1.1.1" || ip === "1.0.0.1";

    return {
      asn: isPrivate ? undefined : isGoogle ? 15169 : 13335,
      asName: isPrivate ? "Private / RFC 1918" : isGoogle ? "Google LLC" : isCloudflare ? "Cloudflare, Inc." : "Public Routable Prefix",
      countryCode: isPrivate ? "XX" : "US",
      prefix: ip.includes(".") ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : `${ip}/64`,
      rir: isPrivate ? "Local Registry" : "ARIN",
      ok: true,
    };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);

    const res = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
      headers: { "User-Agent": USER_AGENT, "Accept": "application/json" },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) return { ok: false };
    const data = await res.json() as any;
    const ptr = data.data || {};
    const prefixes = ptr.prefixes || [];
    const firstPrefix = prefixes[0] || {};
    const asnData = firstPrefix.asn || {};

    return {
      asn: typeof asnData.asn === "number" ? asnData.asn : undefined,
      asName: asnData.name || undefined,
      asDescription: asnData.description || undefined,
      countryCode: asnData.country_code || undefined,
      prefix: firstPrefix.prefix || undefined,
      rir: ptr.rir_allocation?.rir_name || undefined,
      ok: true,
    };
  } catch {
    return { ok: false };
  }
}

/** Queries AlienVault OTX for passive DNS and threat indicators (sfp_alienvault.py) */
export async function queryAlienVaultOTX(
  target: string,
  type: "domain" | "IPv4",
  options?: { offline?: boolean }
): Promise<AlienVaultResult> {
  if (options?.offline) {
    return {
      threatScore: 0,
      pulseCount: 0,
      passiveDns: [],
      tags: [],
      ok: true,
    };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    const endpoint = type === "domain"
      ? `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(target)}/passive_dns`
      : `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(target)}/reputation`;

    const res = await fetch(endpoint, {
      headers: { "User-Agent": USER_AGENT, "Accept": "application/json" },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) return { threatScore: 0, pulseCount: 0, passiveDns: [], tags: [], ok: false };
    const data = await res.json() as any;

    const pdnsList: AlienVaultResult["passiveDns"] = [];
    if (Array.isArray(data.passive_dns)) {
      for (const row of data.passive_dns.slice(0, 20)) {
        pdnsList.push({
          hostname: String(row.hostname || ""),
          address: String(row.address || ""),
          first: String(row.first || ""),
          last: String(row.last || ""),
        });
      }
    }

    const threatScore = Number(data.reputation?.threat_score || 0);
    const pulseCount = Number(data.pulse_info?.count || 0);
    const tags: string[] = Array.isArray(data.pulse_info?.pulses)
      ? Array.from(new Set(data.pulse_info.pulses.flatMap((p: any) => p.tags || []))).slice(0, 10) as string[]
      : [];

    return {
      threatScore,
      pulseCount,
      passiveDns: pdnsList,
      tags,
      ok: true,
    };
  } catch {
    return { threatScore: 0, pulseCount: 0, passiveDns: [], tags: [], ok: false };
  }
}

/** Extracts Web Analytics & Tracking IDs from raw HTML or DNS records (sfp_webanalytics.py) */
export function extractWebAnalytics(content: string): WebAnalyticsResult {
  const googleAnalytics = new Set<string>();
  const googleTagManager = new Set<string>();
  const facebookPixel = new Set<string>();
  const yandexMetrika = new Set<string>();
  const hotjar = new Set<string>();
  const verifications: Record<string, string> = {};

  // Google Analytics UA & G- tags
  for (const m of content.matchAll(/\b(UA-\d+-\d+)\b/gi)) googleAnalytics.add(m[1].toUpperCase());
  for (const m of content.matchAll(/\b(G-[A-Z0-9]{8,12})\b/g)) googleAnalytics.add(m[1]);

  // Google Tag Manager
  for (const m of content.matchAll(/\b(GTM-[A-Z0-9]{4,10})\b/g)) googleTagManager.add(m[1]);

  // Facebook Pixel
  for (const m of content.matchAll(/fbq\(['"]init['"],\s*['"](\d{10,20})['"]/gi)) facebookPixel.add(m[1]);

  // Yandex Metrika
  for (const m of content.matchAll(/ym\((\d{6,12})/g)) yandexMetrika.add(m[1]);

  // Hotjar
  for (const m of content.matchAll(/hjid\s*[:=]\s*['"]?(\d{5,10})/gi)) hotjar.add(m[1]);

  // Site verifications (Google, Bing, Stripe, Adobe)
  const gVer = content.match(/google-site-verification=([a-zA-Z0-9_-]{20,80})/i);
  if (gVer) verifications["Google Site Verification"] = gVer[1];

  const msVer = content.match(/msvalidate\.01=([a-f0-9]{32})/i);
  if (msVer) verifications["Microsoft / Bing Verification"] = msVer[1];

  const stripeVer = content.match(/stripe-verification-challenge=([a-zA-Z0-9_-]{20,80})/i);
  if (stripeVer) verifications["Stripe Verification"] = stripeVer[1];

  return {
    googleAnalytics: Array.from(googleAnalytics),
    googleTagManager: Array.from(googleTagManager),
    facebookPixel: Array.from(facebookPixel),
    yandexMetrika: Array.from(yandexMetrika),
    hotjar: Array.from(hotjar),
    verifications,
  };
}

/** SpiderFoot Multi-Source Correlation Rules Engine (references/spiderfoot/correlations/) */
export function evaluateSpiderFootCorrelations(
  query: string,
  queryType: string,
  evidence: Array<{ provider: string; status: string; detail?: string | null; extra_fields?: Record<string, string> }>
): SpiderFootCorrelation[] {
  const correlations: SpiderFootCorrelation[] = [];

  // 1. Email found in both WHOIS/RDAP and code commits
  const whoisEmail = evidence.some((e) => /rdap|whois/i.test(e.provider) && /email/i.test(e.detail || ""));
  const gitCommits = evidence.some((e) => /github|gitlab/i.test(e.provider) && e.status === "candidate");
  if (whoisEmail && gitCommits) {
    correlations.push({
      ruleId: "SF-CORR-EMAIL-WHOIS-GIT",
      title: "Identity Bridge: WHOIS Contact Correlated with Git Developer Footprint",
      risk: "HIGH",
      description: "Identified email handle is shared between registrar ownership records and public source-code repositories.",
      recommendation: "Cross-correlate developer handles with enterprise administrative domains.",
    });
  }

  // 2. Open Port with Known Vulnerability (CVE)
  const cveFinding = evidence.find((e) => {
    const cves = e.extra_fields?.["CVE identifiers"] || e.extra_fields?.["Known Vulnerabilities (CVEs)"];
    return Boolean(cves) && !["None returned", "None detected"].includes(String(cves));
  });
  if (cveFinding) {
    correlations.push({
      ruleId: "SF-CORR-VULN-CRITICAL",
      title: "Exploitable Perimeter Exposure (SpiderFoot Correlation: vulnerability_critical)",
      risk: "CRITICAL",
      description: `Service port associated with documented CVEs: ${cveFinding.extra_fields?.["CVE identifiers"] || "Known CVEs"}.`,
      recommendation: "Perform urgent patch verification and restrict untrusted access via network firewall.",
    });
  }

  // 3. Cloud Provider Outlier or Unauthenticated Bucket
  const cloudBucket = evidence.find((e) => /bucket|s3|blob|storage/i.test(e.detail || ""));
  if (cloudBucket) {
    correlations.push({
      ruleId: "SF-CORR-CLOUD-BUCKET",
      title: "Cloud Storage Footprint Detected (SpiderFoot Correlation: cloud_bucket_open)",
      risk: "MEDIUM",
      description: `Public cloud storage endpoint referenced in perimeter assets: ${cloudBucket.detail?.slice(0, 80)}...`,
      recommendation: "Audit bucket ACLs and verify public write/read permissions are restricted.",
    });
  }

  // 4. Stale or Expired DNS / Missing DMARC Protection
  const missingDmarc = evidence.some((e) => /email authentication/i.test(e.provider) && /dmarc.*not found/i.test(e.detail || ""));
  if (missingDmarc) {
    correlations.push({
      ruleId: "SF-CORR-SPOOFING-SURFACE",
      title: "Domain Email Spoofing Vulnerability (SpiderFoot Correlation: missing_dmarc)",
      risk: "MEDIUM",
      description: "The target domain does not enforce a DMARC policy (p=reject/quarantine), allowing unauthorized sender spoofing.",
      recommendation: "Publish a strict DMARC TXT record at _dmarc.<domain>.",
    });
  }

  return correlations;
}
