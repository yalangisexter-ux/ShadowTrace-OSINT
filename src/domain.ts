/**
 * Domain intelligence from live DNS-over-HTTPS, Certificate Transparency,
 * and RDAP responses. No placeholder WHOIS or crt.sh cards are emitted.
 */
export interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}
interface DnsLookup {
  answers: DnsAnswer[];
  ok: boolean;
  httpStatus: number | null;
  error?: string;
}
interface EvidenceItem {
  provider: string;
  category: "domain" | "identity" | "security" | "code";
  profile_url: string;
  domain: string;
  status: "observed" | "candidate" | "not_found" | "inconclusive";
  http_status: number | null;
  confidence: "high" | "medium" | "low";
  detail: string;
  checked_at: string;
  extra_fields?: Record<string, string>;
}

export interface DomainResult {
  domain: string;
  ipAddresses: string[];
  ipv6Addresses: string[];
  mailServers: string[];
  nameServers: string[];
  txtRecords: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  dmarcPolicy: string;
  isCloudflare: boolean;
  registeredAt?: string;
  expiresAt?: string;
  evidence: EvidenceItem[];
}

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const RECORD_TYPES: Record<string, number> = { A: 1, NS: 2, MX: 15, TXT: 16, AAAA: 28 };

async function queryDns(name: string, type: string): Promise<DnsLookup> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4500);
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return { answers: [], ok: false, httpStatus: res.status, error: `DNS provider HTTP ${res.status}` };
    const data = await res.json() as { Answer?: DnsAnswer[] };
    return { answers: Array.isArray(data.Answer) ? data.Answer : [], ok: true, httpStatus: res.status };
  } catch (error) {
    return { answers: [], ok: false, httpStatus: null, error: error instanceof Error ? error.message : "DNS lookup failed" };
  } finally {
    clearTimeout(timeout);
  }
}

async function queryCertificateTransparency(domain: string): Promise<{ names: string[]; httpStatus: number | null; ok: boolean }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      headers: { Accept: "application/json", "User-Agent": "ShadowTrace-OSINT/2.1" },
      signal: controller.signal,
    });
    if (!res.ok) return { names: [], httpStatus: res.status, ok: false };
    const rows = await res.json() as Array<{ name_value?: string }>;
    const names = new Set<string>();
    for (const row of Array.isArray(rows) ? rows.slice(0, 1000) : []) {
      for (const raw of String(row.name_value || "").split(/\r?\n/)) {
        const name = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
        if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
      }
    }
    return { names: Array.from(names).sort(), httpStatus: res.status, ok: true };
  } catch {
    return { names: [], httpStatus: null, ok: false };
  } finally {
    clearTimeout(timeout);
  }
}

async function queryRdap(domain: string): Promise<{ data: any | null; httpStatus: number | null; ok: boolean }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6500);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json, application/json", "User-Agent": "ShadowTrace-OSINT/2.1" },
      signal: controller.signal,
    });
    if (!res.ok) return { data: null, httpStatus: res.status, ok: false };
    return { data: await res.json(), httpStatus: res.status, ok: true };
  } catch {
    return { data: null, httpStatus: null, ok: false };
  } finally {
    clearTimeout(timeout);
  }
}

function calculateEntropy(str: string): number {
  const map: Record<string, number> = {};
  for (const c of str) map[c] = (map[c] || 0) + 1;
  let entropy = 0;
  for (const c in map) {
    const p = map[c] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export async function analyzeDomain(rawDomain: string, options?: { offline?: boolean }): Promise<DomainResult> {
  const domain = rawDomain.trim().toLowerCase().replace(/\.$/, "");
  if (!DOMAIN_RE.test(domain) || /\.(localhost|local|internal|test|invalid|example|onion)$/.test(domain)) {
    throw new Error("Enter a valid public domain name without a URL path.");
  }
  const checkedAt = new Date().toISOString();

  if (options?.offline) {
    const parts = domain.split(".");
    const tld = parts[parts.length - 1];
    const sld = parts.length > 1 ? parts[parts.length - 2] : parts[0];
    const subdomainsCount = Math.max(0, parts.length - 2);
    const entropy = calculateEntropy(sld);
    const isHighEntropy = entropy > 3.8;

    const evidence: EvidenceItem[] = [
      {
        provider: "Domain Syntax & TLD Delegation (Offline Mode)",
        category: "domain",
        profile_url: `https://${domain}`,
        domain,
        status: "observed",
        http_status: 200,
        confidence: "high",
        detail: `Syntactic structure validated locally. Top-level domain .${tld} recognized; second-level domain "${sld}".`,
        checked_at: checkedAt,
        extra_fields: {
          "Top-Level Domain (TLD)": `.${tld}`,
          "Second-Level Domain": sld,
          "Domain Character Count": String(domain.length),
          "Subdomains Detected": String(subdomainsCount),
        },
      },
      {
        provider: "Domain Entropy & DGA Heuristics (Offline Mode)",
        category: "security",
        profile_url: `https://${domain}`,
        domain,
        status: "observed",
        http_status: 200,
        confidence: "high",
        detail: `Shannon entropy: ${entropy.toFixed(2)} bits. ${isHighEntropy ? "Elevated randomness detected (possible algorithmically generated domain)." : "Normal human-readable lexical distribution."}`,
        checked_at: checkedAt,
        extra_fields: {
          "Shannon Entropy": `${entropy.toFixed(2)} bits`,
          "Randomness Assessment": isHighEntropy ? "Suspicious (High Entropy)" : "Standard Lexical Pattern",
          "Hyphens / Numerics": /[-0-9]/.test(sld) ? "Present in domain" : "None detected",
        },
      },
      {
        provider: "Offline Analysis Notice",
        category: "security",
        profile_url: "",
        domain,
        status: "observed",
        http_status: 200,
        confidence: "high",
        detail: "Running in Offline / Air-Gapped Mode. Live DNS-over-HTTPS (Cloudflare DoH), RDAP registrar queries, and Certificate Transparency (crt.sh) queries were skipped.",
        checked_at: checkedAt,
        extra_fields: {
          "Mode": "Offline Local Execution",
          "External Network Requests": "0 (None dispatched)",
        },
      },
    ];

    return {
      domain,
      ipAddresses: [],
      ipv6Addresses: [],
      mailServers: [],
      nameServers: [],
      txtRecords: [],
      hasSpf: false,
      hasDmarc: false,
      dmarcPolicy: "Not assessed (Offline Mode)",
      isCloudflare: false,
      evidence,
    };
  }

  const [a, aaaa, mx, txt, ns, dmarc, ct, rdap] = await Promise.all([
    queryDns(domain, "A"),
    queryDns(domain, "AAAA"),
    queryDns(domain, "MX"),
    queryDns(domain, "TXT"),
    queryDns(domain, "NS"),
    queryDns(`_dmarc.${domain}`, "TXT"),
    queryCertificateTransparency(domain),
    queryRdap(domain),
  ]);

  const ipAddresses = a.answers.map(r => r.data);
  const ipv6Addresses = aaaa.answers.map(r => r.data);
  const mailServers = mx.answers.map(r => r.data.replace(/\.$/, ""));
  const nameServers = ns.answers.map(r => r.data.replace(/\.$/, ""));
  const txtRecords = txt.answers.map(r => r.data.replace(/^"|"$/g, ""));
  const dmarcRecords = dmarc.answers.map(r => r.data.replace(/^"|"$/g, ""));
  const spfRecord = txtRecords.find(r => /^v=spf1\b/i.test(r));
  const dmarcRecord = dmarcRecords.find(r => /^v=DMARC1\b/i.test(r));
  const dmarcPolicy = dmarcRecord?.match(/(?:^|;)\s*p=(none|quarantine|reject)/i)?.[1]?.toUpperCase() || "Not published";
  const isCloudflare = nameServers.some(nsName => nsName.toLowerCase().endsWith("ns.cloudflare.com"));

  const evidence: EvidenceItem[] = [];
  const addDns = (label: string, lookup: DnsLookup, values: string[], recordType: string) => {
    if (!lookup.ok) {
      evidence.push({
        provider: `DNS ${recordType} lookup`, category: "domain", profile_url: "", domain,
        status: "inconclusive", http_status: lookup.httpStatus, confidence: "low",
        detail: lookup.error || `${label} lookup failed; no conclusion can be drawn.`, checked_at: checkedAt,
      });
      return;
    }
    evidence.push({
      provider: `DNS ${recordType} records`, category: "domain", profile_url: "", domain,
      status: values.length ? "observed" : "not_found", http_status: lookup.httpStatus, confidence: "high",
      detail: values.length ? `${label}: ${values.join(", ")}` : `The DNS query succeeded but returned no ${recordType} records.`,
      checked_at: checkedAt,
      ...(values.length ? { extra_fields: { "Records": values.join(", ") } } : {}),
    });
  };

  addDns("IPv4 addresses", a, ipAddresses, "A");
  addDns("IPv6 addresses", aaaa, ipv6Addresses, "AAAA");
  addDns("Mail exchangers", mx, mailServers, "MX");
  addDns("Nameservers", ns, nameServers, "NS");
  addDns("TXT records", txt, txtRecords, "TXT");
  addDns("DMARC TXT records", dmarc, dmarcRecords, "DMARC");

  evidence.push({
    provider: "Email authentication posture", category: "security", profile_url: `https://dmarcian.com/dmarc-inspector/?domain=${encodeURIComponent(domain)}`, domain,
    status: txt.ok && dmarc.ok ? "observed" : "inconclusive",
    http_status: txt.ok && dmarc.ok ? 200 : null,
    confidence: txt.ok && dmarc.ok ? "high" : "low",
    detail: txt.ok && dmarc.ok
      ? `DNS observations: SPF ${spfRecord ? "published" : "not found"}; DMARC ${dmarcRecord ? `published (policy ${dmarcPolicy})` : "not found"}. Missing records are configuration observations, not proof of compromise.`
      : "SPF/DMARC posture could not be fully checked because one or more DNS requests failed.",
    checked_at: checkedAt,
    extra_fields: {
      "SPF": spfRecord || "Not found in successful TXT response",
      "DMARC": dmarcRecord || "Not found in successful _dmarc TXT response",
      "DMARC policy": dmarcPolicy,
    },
  });

  if (ct.ok) {
    evidence.push({
      provider: "Certificate Transparency (crt.sh)", category: "security",
      profile_url: `https://crt.sh/?q=%25.${encodeURIComponent(domain)}`, domain: "crt.sh",
      status: ct.names.length ? "observed" : "not_found", http_status: ct.httpStatus, confidence: "high",
      detail: ct.names.length ? `Certificate Transparency returned ${ct.names.length} matching DNS name(s).` : "Certificate Transparency query succeeded but returned no matching certificate names.",
      checked_at: checkedAt,
      ...(ct.names.length ? { extra_fields: { "Certificate names": ct.names.join(", ") } } : {}),
    });
  } else {
    evidence.push({
      provider: "Certificate Transparency (crt.sh)", category: "security",
      profile_url: `https://crt.sh/?q=%25.${encodeURIComponent(domain)}`, domain: "crt.sh",
      status: "inconclusive", http_status: ct.httpStatus, confidence: "low",
      detail: "Certificate Transparency provider did not return a successful response; no conclusion can be drawn.",
      checked_at: checkedAt,
    });
  }

  let registeredAt: string | undefined;
  let expiresAt: string | undefined;
  if (rdap.ok && rdap.data) {
    const events = Array.isArray(rdap.data.events) ? rdap.data.events : [];
    registeredAt = events.find((e: any) => /registration/i.test(e.eventAction))?.eventDate;
    expiresAt = events.find((e: any) => /expiration/i.test(e.eventAction))?.eventDate;
    evidence.push({
      provider: "RDAP domain registration", category: "identity",
      profile_url: `https://rdap.org/domain/${encodeURIComponent(domain)}`, domain: "rdap.org",
      status: "observed", http_status: rdap.httpStatus, confidence: "high",
      detail: `RDAP returned a domain registration object for ${domain}.`,
      checked_at: checkedAt,
      extra_fields: {
        ...(rdap.data.ldhName ? { "Registered domain": String(rdap.data.ldhName) } : {}),
        ...(registeredAt ? { "Registration date": registeredAt } : {}),
        ...(expiresAt ? { "Expiry date": expiresAt } : {}),
        ...(rdap.data.registrar?.name ? { "Registrar": String(rdap.data.registrar.name) } : {}),
      },
    });
  } else {
    evidence.push({
      provider: "RDAP domain registration", category: "identity",
      profile_url: `https://rdap.org/domain/${encodeURIComponent(domain)}`, domain: "rdap.org",
      status: rdap.httpStatus === 404 ? "not_found" : "inconclusive",
      http_status: rdap.httpStatus, confidence: "low",
      detail: rdap.httpStatus === 404 ? "RDAP returned HTTP 404 for this domain." : "RDAP provider did not return a successful registration response.",
      checked_at: checkedAt,
    });
  }

  return {
    domain, ipAddresses, ipv6Addresses, mailServers, nameServers, txtRecords,
    hasSpf: Boolean(spfRecord), hasDmarc: Boolean(dmarcRecord), dmarcPolicy,
    isCloudflare, registeredAt, expiresAt, evidence,
  };
}
