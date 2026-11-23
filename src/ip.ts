/**
 * IP intelligence based only on successful provider responses.
 * GeoIP is approximate network geolocation, not a person's location.
 * Shodan InternetDB is an indexed snapshot, not a live port scan.
 */
export interface IPResult {
  ip: string;
  type: "IPv4" | "IPv6";
  isBogon: boolean;
  hostname?: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  postal?: string;
  latitude?: number;
  longitude?: number;
  timezone: string;
  asn?: number;
  asnOrg?: string;
  isp?: string;
  cloudProvider?: string;
  flagUrl?: string;
  entities: {
    names: string[];
    profile_pictures: string[];
    banners: string[];
    usernames: string[];
    emails: string[];
    phones: string[];
    first_seen?: string;
    last_seen?: string;
  };
  platforms: {
    name: string;
    category: string;
    url: string;
    status: "observed" | "candidate" | "not_found" | "inconclusive";
    verified?: boolean;
    confidence?: "high" | "medium" | "low" | "none";
    identityName?: string;
    identifierDisplay?: string;
    fieldsCount?: number;
    extraFields?: Record<string, string>;
    detail: string;
    icon: string;
    httpStatus?: number | null;
  }[];
}

const KNOWN_CLOUD_PROVIDERS: Record<number, string> = {
  13335: "Cloudflare",
  16509: "Amazon Web Services",
  14618: "Amazon Web Services",
  15169: "Google",
  396982: "Google Cloud",
  8075: "Microsoft",
  14061: "DigitalOcean",
  24940: "Hetzner",
  16276: "OVHcloud",
  63949: "Akamai / Linode",
  20473: "Vultr",
  31898: "Oracle Cloud",
};

export function isBogonIP(ip: string): boolean {
  if (ip.includes(".")) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b, c] = parts;
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) ||
      (a === 203 && b === 0 && c === 113);
  }
  const v6 = ip.toLowerCase();
  return v6 === "::" || v6 === "::1" || v6.startsWith("fc") || v6.startsWith("fd") ||
    v6.startsWith("fe80:") || v6.startsWith("ff") || v6.startsWith("2001:db8:");
}

function expandIPv6(ip: string): string {
  const halves = ip.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = Math.max(0, 8 - left.length - right.length);
  return [...left, ...Array(missing).fill("0"), ...right].map(x => x.padStart(4, "0")).join(":");
}

async function queryReverseDns(ip: string): Promise<{ hostname?: string; status: number | null; ok: boolean }> {
  try {
    const arpa = ip.includes(".")
      ? ip.split(".").reverse().join(".") + ".in-addr.arpa"
      : expandIPv6(ip).replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(arpa)}&type=PTR`, {
        headers: { Accept: "application/dns-json" }, signal: controller.signal,
      });
      if (!res.ok) return { status: res.status, ok: false };
      const data = await res.json() as { Answer?: Array<{ data?: string }> };
      const hostname = data.Answer?.[0]?.data?.replace(/\.$/, "");
      return { hostname, status: res.status, ok: true };
    } finally { clearTimeout(timer); }
  } catch { return { status: null, ok: false }; }
}

interface ShodanData {
  ip?: string;
  ports?: number[];
  hostnames?: string[];
  cpes?: string[];
  tags?: string[];
  vulns?: string[];
}
async function queryShodan(ip: string): Promise<{ data: ShodanData | null; status: number | null; ok: boolean }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    try {
      const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
        headers: { "User-Agent": "ShadowTrace-OSINT/2.1" }, signal: controller.signal,
      });
      if (res.status === 404) return { data: null, status: 404, ok: true };
      if (!res.ok) return { data: null, status: res.status, ok: false };
      const data = await res.json() as ShodanData;
      if (data.ip && data.ip !== ip) return { data: null, status: res.status, ok: false };
      return { data, status: res.status, ok: true };
    } finally { clearTimeout(timer); }
  } catch { return { data: null, status: null, ok: false }; }
}

async function queryGeoIp(ip: string): Promise<{ data: any | null; status: number | null; ok: boolean }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    try {
      const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
        headers: { "User-Agent": "ShadowTrace-OSINT/2.1" }, signal: controller.signal,
      });
      if (!res.ok) return { data: null, status: res.status, ok: false };
      const data = await res.json() as any;
      if (data.success !== true || (data.ip && data.ip !== ip)) return { data: null, status: res.status, ok: false };
      return { data, status: res.status, ok: true };
    } finally { clearTimeout(timer); }
  } catch { return { data: null, status: null, ok: false }; }
}

export async function analyzeIP(input: string, options?: { offline?: boolean }): Promise<IPResult> {
  const ip = input.trim();
  const isV4 = ip.includes(".");
  if (isBogonIP(ip) && !ip.includes(".") && !ip.includes(":")) throw new Error("Invalid IP address.");
  const type: IPResult["type"] = isV4 ? "IPv4" : "IPv6";
  const isBogon = isBogonIP(ip);

  let country = "Unknown";
  let countryCode = "XX";
  let region = "Unknown";
  let city = "Unknown";
  let postal: string | undefined;
  let latitude: number | undefined;
  let longitude: number | undefined;
  let timezone = "Unknown";
  let asn: number | undefined;
  let asnOrg: string | undefined;
  let isp: string | undefined;
  let cloudProvider: string | undefined;
  let flagUrl: string | undefined;

  const platforms: IPResult["platforms"] = [];
  let hostname: string | undefined;

  if (options?.offline) {
    const arpa = isV4
      ? ip.split(".").reverse().join(".") + ".in-addr.arpa"
      : expandIPv6(ip).replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";

    let intVal = "";
    let hexVal = "";
    if (isV4) {
      const octets = ip.split(".").map(Number);
      const num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
      intVal = String(num >>> 0);
      hexVal = "0x" + (num >>> 0).toString(16).padStart(8, "0").toUpperCase();
    }

    platforms.push({
      name: isBogon ? "PRIVATE / RESERVED IP CLASSIFICATION" : "IP ADDRESS ARCHITECTURE & SUBNET",
      category: "Address classification",
      url: "",
      status: "observed",
      verified: true,
      confidence: "high",
      identifierDisplay: `${type}: ${ip}`,
      fieldsCount: 5,
      extraFields: {
        "IP Protocol": type,
        "Classification": isBogon ? "Private / Reserved (RFC 6890)" : "Routable Public IP",
        "Reverse DNS Pointer (ARPA)": arpa,
        ...(intVal ? { "Integer Notation": intVal } : {}),
        ...(hexVal ? { "Hexadecimal Notation": hexVal } : {}),
      },
      detail: isBogon
        ? "The address is in a private, shared, loopback, link-local, documentation, multicast, or otherwise non-public range (RFC 6890). Offline analysis completed."
        : `Public ${type} address formatted and classified locally. Reverse DNS ARPA zone: ${arpa}.`,
      icon: "local-ip-classifier",
    });

    platforms.push({
      name: "OFFLINE ANALYSIS NOTICE",
      category: "Network location",
      url: "",
      status: "observed",
      verified: true,
      confidence: "high",
      identifierDisplay: "Offline Mode Active",
      fieldsCount: 2,
      extraFields: {
        "Mode": "Air-Gapped / Offline",
        "Skipped Services": "GeoIP (ipwho.is), Shodan InternetDB, and PTR Resolution",
      },
      detail: "Running in Offline Mode. Remote GeoIP coordinates, ASN registration, and live Shodan vulnerability snapshots were skipped.",
      icon: "offline-notice",
    });

    return {
      ip,
      type,
      isBogon,
      hostname,
      country,
      countryCode,
      region,
      city,
      timezone,
      entities: {
        names: [],
        profile_pictures: [],
        banners: [],
        usernames: [],
        emails: [],
        phones: [],
      },
      platforms,
    };
  }

  if (isBogon) {
    platforms.push({
      name: "PRIVATE / RESERVED IP CLASSIFICATION",
      category: "Address classification",
      url: "",
      status: "observed",
      verified: true,
      confidence: "high",
      identifierDisplay: ip,
      detail: "The address is in a private, shared, loopback, link-local, documentation, multicast, or otherwise non-public range. External intelligence lookups were skipped.",
      icon: "local-ip-classifier",
    });
  } else {
    const [geo, ptr, shodan] = await Promise.all([queryGeoIp(ip), queryReverseDns(ip), queryShodan(ip)]);
    hostname = ptr.hostname || shodan.data?.hostnames?.[0];

    if (geo.ok && geo.data) {
      const g = geo.data;
      country = g.country || country;
      countryCode = g.country_code || countryCode;
      region = g.region || region;
      city = g.city || city;
      postal = g.postal;
      latitude = typeof g.latitude === "number" ? g.latitude : undefined;
      longitude = typeof g.longitude === "number" ? g.longitude : undefined;
      timezone = g.timezone?.id || timezone;
      asn = typeof g.connection?.asn === "number" ? g.connection.asn : undefined;
      asnOrg = g.connection?.org || undefined;
      isp = g.connection?.isp || undefined;
      cloudProvider = asn ? KNOWN_CLOUD_PROVIDERS[asn] : undefined;
      flagUrl = g.flag?.img;

      platforms.push({
        name: "IP GEOLOCATION / NETWORK REGISTRATION",
        category: "Network location",
        url: latitude !== undefined && longitude !== undefined ? `https://www.google.com/maps?q=${latitude},${longitude}` : "https://ipwho.is/",
        status: "observed",
        verified: true,
        confidence: "medium",
        identityName: [city, region, country].filter(Boolean).join(", "),
        identifierDisplay: `${country} (${countryCode}) · ${asn ? `AS${asn}` : "ASN unavailable"}`,
        fieldsCount: 7,
        extraFields: {
          "Country": `${country} (${countryCode})`,
          "Region": region,
          "City": city,
          "Coordinates": latitude !== undefined && longitude !== undefined ? `${latitude}, ${longitude}` : "Not returned",
          "Timezone": timezone,
          ...(asn ? { "ASN": `AS${asn}` } : {}),
          ...(asnOrg ? { "ASN organization": asnOrg } : {}),
          ...(isp ? { "ISP": isp } : {}),
          ...(cloudProvider ? { "Known ASN provider": cloudProvider } : {}),
          ...(postal ? { "Postal code": String(postal) } : {}),
        },
        detail: "Approximate GeoIP and network-registration data returned by ipwho.is. This locates the network endpoint, not a person or device owner.",
        icon: "ipwho.is",
        httpStatus: geo.status,
      });
    } else {
      platforms.push({
        name: "IP GEOLOCATION",
        category: "Network location",
        url: "https://ipwho.is/",
        status: "inconclusive",
        verified: false,
        confidence: "none",
        identifierDisplay: "No successful GeoIP response",
        detail: "The GeoIP provider did not return a valid result for this address; no location is inferred.",
        icon: "ipwho.is",
        httpStatus: geo.status,
      });
    }

    if (ptr.hostname) {
      platforms.push({
        name: "REVERSE DNS (PTR)",
        category: "DNS",
        url: `https://dns.google/resolve?name=${encodeURIComponent(ip)}&type=PTR`,
        status: "observed",
        verified: true,
        confidence: "high",
        identityName: ptr.hostname,
        identifierDisplay: ptr.hostname,
        extraFields: { "PTR hostname": ptr.hostname, "Resolver": "Google Public DNS" },
        detail: "A PTR record was returned for this IP address. Reverse DNS does not establish the owner of the host.",
        icon: "dns.google",
        httpStatus: ptr.status,
      });
    } else if (!ptr.ok) {
      platforms.push({
        name: "REVERSE DNS (PTR)",
        category: "DNS",
        url: "https://dns.google/",
        status: "inconclusive",
        verified: false,
        confidence: "none",
        detail: "Reverse DNS lookup failed; no hostname is inferred.",
        icon: "dns.google",
        httpStatus: ptr.status,
      });
    }

    if (shodan.data && (shodan.data.ports?.length || shodan.data.vulns?.length || shodan.data.hostnames?.length || shodan.data.cpes?.length)) {
      platforms.push({
        name: "SHODAN INTERNETDB",
        category: "Indexed attack-surface data",
        url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
        status: "observed",
        verified: true,
        confidence: "high",
        identifierDisplay: `${shodan.data.ports?.length || 0} indexed port(s) · ${shodan.data.vulns?.length || 0} CVE(s)`,
        fieldsCount: 5,
        extraFields: {
          "Indexed ports": shodan.data.ports?.length ? shodan.data.ports.join(", ") : "None returned",
          "CVE identifiers": shodan.data.vulns?.length ? shodan.data.vulns.join(", ") : "None returned",
          "Hostnames": shodan.data.hostnames?.join(", ") || "None returned",
          "CPEs": shodan.data.cpes?.join(", ") || "None returned",
          "Tags": shodan.data.tags?.join(", ") || "None returned",
        },
        detail: "Shodan InternetDB returned indexed observations. These are not a live scan and may be stale; verify timestamps and services with the provider.",
        icon: "shodan.io",
        httpStatus: shodan.status,
      });
    } else if (!shodan.ok) {
      platforms.push({
        name: "SHODAN INTERNETDB",
        category: "Indexed attack-surface data",
        url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
        status: "inconclusive",
        verified: false,
        confidence: "none",
        detail: "Shodan InternetDB did not return a successful lookup. No open-port or vulnerability conclusion is drawn.",
        icon: "shodan.io",
        httpStatus: shodan.status,
      });
    } else {
      platforms.push({
        name: "SHODAN INTERNETDB",
        category: "Indexed attack-surface data",
        url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
        status: "not_found",
        verified: false,
        confidence: "none",
        detail: "Shodan InternetDB returned no indexed host record. This does not prove that the host has no exposed services.",
        icon: "shodan.io",
        httpStatus: shodan.status,
      });
    }
  }

  return {
    ip, type, isBogon, hostname,
    country, countryCode, region, city, postal, latitude, longitude, timezone,
    asn, asnOrg, isp, cloudProvider, flagUrl,
    entities: {
      names: [],
      profile_pictures: [], banners: [], usernames: [], emails: [], phones: [],
    },
    platforms,
  };
}
