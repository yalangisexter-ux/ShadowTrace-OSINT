/**
 * IP Intelligence & Geolocation Engine
 * Free, live IP intelligence covering GeoIP, ASN, ISP, Reverse DNS,
 * Cloud provider detection, and threat reputation.
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
    status: "verified" | "candidate" | "inconclusive";
    verified?: boolean;
    identityName?: string;
    identifierDisplay?: string;
    fieldsCount?: number;
    extraFields?: Record<string, string>;
    detail: string;
    icon: string;
  }[];
}

const BOGON_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/
];

const KNOWN_CLOUD_PROVIDERS: Record<string, string> = {
  "AS13335": "Cloudflare Edge",
  "AS16509": "Amazon Web Services (AWS)",
  "AS14618": "Amazon Web Services (AWS)",
  "AS15169": "Google Cloud Platform (GCP)",
  "AS396982": "Google Cloud Platform (GCP)",
  "AS8075": "Microsoft Azure",
  "AS14061": "DigitalOcean",
  "AS24940": "Hetzner Online",
  "AS16276": "OVHcloud",
  "AS63949": "Akamai / Linode",
  "AS20473": "Choopa / Vultr",
  "AS31898": "Oracle Cloud Infrastructure",
};

export function isBogonIP(ip: string): boolean {
  return BOGON_RANGES.some(r => r.test(ip));
}

// Reverse DNS PTR query via Google DoH
async function queryReverseDns(ip: string): Promise<string | undefined> {
  try {
    const isV4 = ip.includes(".");
    let arpaName = "";
    if (isV4) {
      arpaName = ip.split(".").reverse().join(".") + ".in-addr.arpa";
    } else {
      // IPv6 reverse nibble format
      const expanded = expandIPv6(ip);
      arpaName = expanded.replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(arpaName)}&type=PTR`, {
      headers: { "Accept": "application/dns-json" },
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) return undefined;
    const data: any = await res.json();
    if (data.Answer && data.Answer.length > 0) {
      return data.Answer[0].data?.replace(/\.$/, "");
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function expandIPv6(ip: string): string {
  const parts = ip.split("::");
  let left = parts[0] ? parts[0].split(":") : [];
  let right = parts[1] ? parts[1].split(":") : [];
  const missing = 8 - (left.length + right.length);
  const mid = Array(missing).fill("0000");
  const full = [...left, ...mid, ...right].map(seg => seg.padStart(4, "0"));
  return full.join(":");
}

export async function analyzeIP(input: string): Promise<IPResult> {
  const ip = input.trim();
  const isV4 = ip.includes(".");
  const type: "IPv4" | "IPv6" = isV4 ? "IPv4" : "IPv6";
  const isBogon = isBogonIP(ip);

  let country = "Unknown Country";
  let countryCode = "XX";
  let region = "Global Network";
  let city = "Unknown City";
  let postal: string | undefined = undefined;
  let latitude: number | undefined = undefined;
  let longitude: number | undefined = undefined;
  let timezone = "UTC";
  let asn: number | undefined = undefined;
  let asnOrg: string | undefined = undefined;
  let isp: string | undefined = undefined;
  let cloudProvider: string | undefined = undefined;
  let flagUrl: string | undefined = undefined;

  // Run live network queries concurrently
  const [geoRes, hostname] = await Promise.all([
    !isBogon ? (async () => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3500);
        const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
          headers: { "User-Agent": "ShadowTrace-OSINT/1.0" },
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return null;
        return await res.json() as any;
      } catch {
        return null;
      }
    })() : Promise.resolve(null),
    queryReverseDns(ip)
  ]);

  if (geoRes && geoRes.success) {
    country = geoRes.country || country;
    countryCode = geoRes.country_code || countryCode;
    region = geoRes.region || region;
    city = geoRes.city || city;
    postal = geoRes.postal;
    latitude = geoRes.latitude;
    longitude = geoRes.longitude;
    timezone = geoRes.timezone?.id || timezone;
    asn = geoRes.connection?.asn;
    asnOrg = geoRes.connection?.org;
    isp = geoRes.connection?.isp;
    flagUrl = geoRes.flag?.img;

    if (asn) {
      const asnKey = `AS${asn}`;
      if (KNOWN_CLOUD_PROVIDERS[asnKey]) {
        cloudProvider = KNOWN_CLOUD_PROVIDERS[asnKey];
      } else if (asnOrg) {
        for (const [key, name] of Object.entries(KNOWN_CLOUD_PROVIDERS)) {
          if (asnOrg.toLowerCase().includes(name.toLowerCase().split(" ")[0])) {
            cloudProvider = name;
            break;
          }
        }
      }
    }
  }

  const entities: IPResult["entities"] = {
    names: [hostname || ip, asnOrg || isp || `${country} Network`].filter(Boolean) as string[],
    profile_pictures: flagUrl ? [flagUrl] : [],
    banners: [],
    usernames: [],
    emails: [],
    phones: [],
    first_seen: "IP Allocation Registry",
    last_seen: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
  };

  const platforms: IPResult["platforms"] = [];

  // 1. Geolocation Platform Card
  platforms.push({
    name: "IP GEOLOCATION",
    category: "Network Location",
    url: latitude && longitude ? `https://www.google.com/maps?q=${latitude},${longitude}` : `https://ipwhois.io/`,
    status: "candidate",
    verified: true,
    identityName: `${city}, ${region}, ${country}`,
    identifierDisplay: `${city}, ${country} (${countryCode})`,
    fieldsCount: 5,
    extraFields: {
      "Country": `${country} (${countryCode})`,
      "Region / State": region,
      "City": city,
      "Coordinates": latitude && longitude ? `${latitude.toFixed(4)}, ${longitude.toFixed(4)}` : "Unavailable",
      "Timezone": timezone,
      ...(postal ? { "Postal Code": postal } : {})
    },
    detail: `Geographic location resolved to ${city}, ${region}, ${country}. Timezone: ${timezone}.`,
    icon: "ipwhois.io"
  });

  // 2. ASN & BGP Routing
  if (asn || isp || asnOrg) {
    platforms.push({
      name: "BGP / AUTONOMOUS SYSTEM",
      category: "Routing & ISP",
      url: asn ? `https://bgpview.io/asn/${asn}` : `https://bgp.he.net/`,
      status: "candidate",
      verified: true,
      identityName: asn ? `AS${asn} (${asnOrg || isp})` : (asnOrg || isp || "Autonomous System"),
      identifierDisplay: `AS${asn || '—'} · ${isp || asnOrg || 'Global ISP'}`,
      fieldsCount: 4,
      extraFields: {
        "ASN Number": asn ? `AS${asn}` : "Unallocated",
        "Organization": asnOrg || "Unknown Org",
        "ISP Network": isp || "Unknown ISP",
        "Route Registry": "IANA / Regional Internet Registry"
      },
      detail: `Autonomous System AS${asn || '—'} operated by ${asnOrg || isp || 'upstream carrier'}.`,
      icon: "bgpview.io"
    });
  }

  // 3. Cloud & Hosting Infrastructure
  platforms.push({
    name: "HOSTING & CLOUD INFRASTRUCTURE",
    category: "Infrastructure",
    url: `https://www.peeringdb.com/`,
    status: "candidate",
    verified: true,
    identityName: cloudProvider || (asnOrg ? `${asnOrg} Infrastructure` : "Public Datacenter"),
    identifierDisplay: cloudProvider ? `Cloud: ${cloudProvider}` : `ISP: ${isp || 'Datacenter / Dedicated'}`,
    fieldsCount: 3,
    extraFields: {
      "Hosting Tier": cloudProvider ? "Major Hyper-Cloud Platform" : "Dedicated Datacenter / Transit",
      "Provider": cloudProvider || asnOrg || isp || "Unknown",
      "Bogon State": isBogon ? "WARNING: Private / Reserved IP Range" : "Routable Public IP"
    },
    detail: cloudProvider ? `Hosted within ${cloudProvider} infrastructure.` : `Assigned to ${asnOrg || isp || 'carrier network'}.`,
    icon: "peeringdb.com"
  });

  // 4. Reverse DNS (PTR)
  if (hostname) {
    platforms.push({
      name: "REVERSE DNS (PTR)",
      category: "DNS Records",
      url: `https://${hostname}`,
      status: "candidate",
      verified: true,
      identityName: hostname,
      identifierDisplay: `PTR: ${hostname}`,
      fieldsCount: 2,
      extraFields: {
        "PTR Record": hostname,
        "Reverse Resolver": "Google Public DNS (DoH)"
      },
      detail: `Reverse DNS pointer record maps ${ip} to fully-qualified hostname ${hostname}.`,
      icon: "dns.google"
    });
  }

  // 5. Threat & Attack Surface Pivots
  platforms.push({
    name: "SHODAN & THREAT PIVOTS",
    category: "Attack Surface",
    url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
    status: "candidate",
    verified: true,
    identifierDisplay: `Shodan IP: ${ip}`,
    fieldsCount: 4,
    extraFields: {
      "Shodan Host Pivot": `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
      "Censys Search": `https://search.censys.io/hosts/${encodeURIComponent(ip)}`,
      "VirusTotal Analysis": `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
      "AbuseIPDB Reports": `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`
    },
    detail: `Threat intelligence, open port scanner, and abuse reputation pivots for ${ip}.`,
    icon: "shodan.io"
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
    postal,
    latitude,
    longitude,
    timezone,
    asn,
    asnOrg,
    isp,
    cloudProvider,
    flagUrl,
    entities,
    platforms,
  };
}
