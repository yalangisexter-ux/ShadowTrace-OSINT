/**
 * Domain & Infrastructure OSINT Intelligence Engine
 * Queries Cloudflare DoH (DNS-over-HTTPS) for authoritative records,
 * checks mail exchanges (MX), SPF / DMARC records, and security posture.
 */

export interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
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
  evidence: {
    provider: string;
    category: "domain" | "identity" | "security" | "code";
    profile_url: string;
    domain: string;
    status: "candidate" | "not_found" | "inconclusive";
    http_status: number;
    confidence: "high" | "medium" | "low";
    detail: string;
    checked_at: string;
  }[];
}

const RECORD_TYPES: Record<string, number> = {
  A: 1,
  NS: 2,
  MX: 15,
  TXT: 16,
  AAAA: 28,
};

async function queryDns(domain: string, type: string): Promise<DnsAnswer[]> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data: any = await res.json();
    return data.Answer || [];
  } catch {
    return [];
  }
}

export async function analyzeDomain(rawDomain: string): Promise<DomainResult> {
  const domain = rawDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const checkedAt = new Date().toISOString();

  // Concurrent DNS resolution via Cloudflare DoH
  const [aRecords, aaaaRecords, mxRecords, txtRecords, nsRecords, dmarcRecords] = await Promise.all([
    queryDns(domain, "A"),
    queryDns(domain, "AAAA"),
    queryDns(domain, "MX"),
    queryDns(domain, "TXT"),
    queryDns(domain, "NS"),
    queryDns(`_dmarc.${domain}`, "TXT"),
  ]);

  const ipAddresses = aRecords.map((r) => r.data);
  const ipv6Addresses = aaaaRecords.map((r) => r.data);
  const mailServers = mxRecords.map((r) => r.data);
  const nameServers = nsRecords.map((r) => r.data.replace(/\.$/, ""));
  const allTxt = txtRecords.map((r) => r.data.replace(/^"|"$/g, ""));
  const allDmarcTxt = dmarcRecords.map((r) => r.data.replace(/^"|"$/g, ""));

  const spfRecord = allTxt.find((t) => t.startsWith("v=spf1"));
  const hasSpf = Boolean(spfRecord);
  const dmarcRecord = allDmarcTxt.find((t) => t.startsWith("v=DMARC1"));
  const hasDmarc = Boolean(dmarcRecord);

  let dmarcPolicy = "None configured";
  if (dmarcRecord) {
    const match = dmarcRecord.match(/p=(none|quarantine|reject)/i);
    dmarcPolicy = match ? match[1].toUpperCase() : "Configured";
  }

  const isCloudflare = nameServers.some((ns) => ns.toLowerCase().includes("cloudflare.com"));

  const evidence: DomainResult["evidence"] = [];

  // 1. IP Infrastructure
  if (ipAddresses.length > 0) {
    evidence.push({
      provider: "Authoritative IPv4 Resolution",
      category: "domain",
      profile_url: `https://${domain}`,
      domain,
      status: "candidate",
      http_status: 200,
      confidence: "high",
      detail: `Resolved IPv4: ${ipAddresses.join(", ")} ${isCloudflare ? "(Protected by Cloudflare Edge)" : ""}`,
      checked_at: checkedAt,
    });
  }

  // 2. Mail Infrastructure (MX)
  if (mailServers.length > 0) {
    evidence.push({
      provider: "Mail Exchanger (MX Records)",
      category: "domain",
      profile_url: `https://${domain}`,
      domain,
      status: "candidate",
      http_status: 200,
      confidence: "high",
      detail: `Active Mail Routing: ${mailServers.slice(0, 3).join(", ")}`,
      checked_at: checkedAt,
    });
  }

  // 3. Email Security Posture (SPF & DMARC)
  evidence.push({
    provider: "Email Spoofing Defense (SPF & DMARC)",
    category: "security",
    profile_url: `https://dmarcian.com/dmarc-inspector/?domain=${encodeURIComponent(domain)}`,
    domain: "dmarcian.com",
    status: hasSpf && hasDmarc ? "candidate" : "inconclusive",
    http_status: 200,
    confidence: "high",
    detail: `SPF: ${hasSpf ? "Valid (" + spfRecord?.slice(0, 45) + "...)" : "MISSING"} · DMARC: ${hasDmarc ? "Enforced (Policy: " + dmarcPolicy + ")" : "MISSING"}`,
    checked_at: checkedAt,
  });

  // 4. Authoritative Nameservers
  if (nameServers.length > 0) {
    evidence.push({
      provider: "DNS Delegation (Nameservers)",
      category: "domain",
      profile_url: `https://${nameServers[0] || domain}`,
      domain,
      status: "candidate",
      http_status: 200,
      confidence: "high",
      detail: `Authoritative Nameservers: ${nameServers.join(", ")}`,
      checked_at: checkedAt,
    });
  }

  // 5. SSL/TLS Certificate Transparency (crt.sh)
  evidence.push({
    provider: "SSL/TLS Certificate Logs (crt.sh)",
    category: "security",
    profile_url: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
    domain: "crt.sh",
    status: "candidate",
    http_status: 200,
    confidence: "medium",
    detail: `Search historical cryptographic certificates and discover unlisted subdomains for ${domain}.`,
    checked_at: checkedAt,
  });

  // 6. WHOIS & RDAP Registration
  evidence.push({
    provider: "Domain WHOIS & RDAP Registry",
    category: "identity",
    profile_url: `https://whois.domaintools.com/${encodeURIComponent(domain)}`,
    domain: "domaintools.com",
    status: "candidate",
    http_status: 200,
    confidence: "medium",
    detail: `Inspect registrar, creation date, expiry, and registrant contact records for ${domain}.`,
    checked_at: checkedAt,
  });

  return {
    domain,
    ipAddresses,
    ipv6Addresses,
    mailServers,
    nameServers,
    txtRecords: allTxt,
    hasSpf,
    hasDmarc,
    dmarcPolicy,
    isCloudflare,
    evidence,
  };
}
