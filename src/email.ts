/**
 * Email intelligence from public, source-backed records.
 * Mail routing is a domain fact, not proof that a mailbox exists.
 * Account-registration enumeration endpoints and guessed recovery details
 * are intentionally excluded.
 */
export interface EmailResult {
  email: string;
  username: string;
  domain: string;
  provider: string;
  isFreeProvider: boolean;
  isDisposable: boolean;
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

const COMMON_PROVIDERS: Record<string, string> = {
  "gmail.com": "Google Mail (Gmail)", "googlemail.com": "Google Mail (Gmail)",
  "outlook.com": "Microsoft Outlook", "hotmail.com": "Microsoft Hotmail",
  "live.com": "Microsoft Live", "msn.com": "Microsoft MSN",
  "yahoo.com": "Yahoo Mail", "icloud.com": "Apple iCloud", "me.com": "Apple iCloud",
  "proton.me": "Proton Mail", "protonmail.com": "Proton Mail",
  "zoho.com": "Zoho Mail", "mail.com": "Mail.com", "gmx.com": "GMX Mail",
  "yandex.com": "Yandex Mail", "fastmail.com": "Fastmail",
};
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
  "yopmail.com", "throwawaymail.com", "sharklasers.com", "getairmail.com",
  "dispostable.com", "mytemp.email", "fakeinbox.com", "trashmail.com",
  "temp-mail.org", "burnermail.io", "maildrop.cc",
]);

async function fetchWithTimeout(url: string, timeoutMs = 4500, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryPgpKeyserver(email: string): Promise<{ names: string[]; altEmails: string[]; status: number | null }> {
  try {
    const url = `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=${encodeURIComponent(email)}`;
    const res = await fetchWithTimeout(url, 4500, { headers: { "User-Agent": "ShadowTrace-OSINT/2.1" } });
    if (!res.ok) return { names: [], altEmails: [], status: res.status };
    const body = await res.text();
    const names = new Set<string>();
    const altEmails = new Set<string>();
    for (const match of body.matchAll(/<span class="uid">([\s\S]*?)<\/span>/gi)) {
      const uidHtml = match[1];
      const emailMatch = uidHtml.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i);
      const name = uidHtml
        .replace(/<[^>]*>/g, " ")
        .replace(emailMatch?.[0] || "", " ")
        .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
        .replace(/[<>()]/g, " ")
        .replace(/\s+/g, " ").trim();
      if (emailMatch?.[0] && emailMatch[0].toLowerCase() !== email.toLowerCase()) altEmails.add(emailMatch[0].toLowerCase());
      if (name.length > 1 && !name.includes("@")) names.add(name);
    }
    return { names: Array.from(names), altEmails: Array.from(altEmails), status: res.status };
  } catch { return { names: [], altEmails: [], status: null }; }
}

async function queryGravatar(hash: string): Promise<{ displayName?: string; photo?: string; aboutMe?: string; found: boolean; status: number | null }> {
  try {
    const res = await fetchWithTimeout(`https://en.gravatar.com/${hash}.json`, 3500, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.1" },
    });
    if (res.ok) {
      const data = await res.json() as any;
      const entry = Array.isArray(data.entry) ? data.entry[0] : undefined;
      if (entry) {
        return {
          displayName: typeof entry.displayName === "string" ? entry.displayName : undefined,
          photo: typeof entry.photos?.[0]?.value === "string" ? entry.photos[0].value : undefined,
          aboutMe: typeof entry.aboutMe === "string" ? entry.aboutMe : undefined,
          found: true,
          status: res.status,
        };
      }
    }
    const avatar = await fetchWithTimeout(`https://gravatar.com/avatar/${hash}?d=404`, 3000, { method: "HEAD" });
    return avatar.ok ? { photo: `https://gravatar.com/avatar/${hash}?s=200`, found: true, status: avatar.status } : { found: false, status: res.status };
  } catch { return { found: false, status: null }; }
}

async function queryGithubCommits(email: string): Promise<{
  commits: Array<{ author: string; login?: string; avatar?: string; date?: string; url?: string }>;
  status: number | null;
}> {
  try {
    const url = `https://api.github.com/search/commits?q=author-email:${encodeURIComponent(email)}&per_page=20`;
    const res = await fetchWithTimeout(url, 5000, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.1", "Accept": "application/vnd.github+json" },
    });
    if (!res.ok) return { commits: [], status: res.status };
    const data = await res.json() as any;
    const commits = (Array.isArray(data.items) ? data.items : [])
      .filter((item: any) => String(item.commit?.author?.email || "").toLowerCase() === email)
      .map((item: any) => ({
        author: String(item.commit?.author?.name || ""),
        login: item.author?.login ? String(item.author.login) : undefined,
        avatar: item.author?.avatar_url ? String(item.author.avatar_url) : undefined,
        date: item.commit?.author?.date ? String(item.commit.author.date) : undefined,
        url: item.html_url ? String(item.html_url) : undefined,
      }))
      .filter((item: any) => item.author);
    return { commits, status: res.status };
  } catch { return { commits: [], status: null }; }
}

async function queryMxRecords(domain: string): Promise<{ records: string[]; status: number | null; ok: boolean }> {
  try {
    const res = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      3500,
      { headers: { Accept: "application/dns-json" } },
    );
    if (!res.ok) return { records: [], status: res.status, ok: false };
    const data = await res.json() as { Answer?: Array<{ data?: string }> };
    return {
      records: (data.Answer || []).map(a => String(a.data || "").replace(/\.$/, "")).filter(Boolean),
      status: res.status,
      ok: true,
    };
  } catch { return { records: [], status: null, ok: false }; }
}

export async function analyzeEmail(email: string, options?: { offline?: boolean }): Promise<EmailResult> {
  const cleaned = email.trim().toLowerCase();
  const parts = cleaned.split("@");
  if (parts.length !== 2 || !/^[^\s@]+$/.test(parts[0]) || !/^[a-z0-9.-]+\.[a-z]{2,63}$/i.test(parts[1])) {
    throw new Error("Enter a valid email address.");
  }
  const [username, domain] = parts;
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const provider = COMMON_PROVIDERS[domain] || `${domain} (mail domain)`;
  const isFreeProvider = Boolean(COMMON_PROVIDERS[domain]);

  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(cleaned));
  const sha256Hex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");

  if (options?.offline) {
    const roleAccounts = new Set(["admin", "support", "info", "security", "contact", "sales", "billing", "help", "root", "postmaster", "abuse", "compliance", "legal"]);
    const rootLocal = username.split("+")[0];
    const isRole = roleAccounts.has(rootLocal);
    const hasTag = username.includes("+");
    const tag = hasTag ? username.split("+")[1] : undefined;

    const platforms: EmailResult["platforms"] = [
      {
        name: "EMAIL SYNTAX & PROVIDER IDENTIFICATION (OFFLINE MODE)",
        category: "Domain infrastructure",
        url: "",
        status: "observed",
        verified: true,
        confidence: "high",
        identifierDisplay: `${cleaned} · ${provider}`,
        fieldsCount: 5,
        extraFields: {
          "Identified Provider": provider,
          "Domain": domain,
          "Local Mailbox Part": username,
          ...(tag ? { "Sub-address Alias Tag": tag } : {}),
          "Disposable Provider": isDisposable ? "Flagged Disposable" : "Standard Domain",
          "Account Nature": isRole ? "Role / Operational Address" : "Individual / Personal Account",
        },
        detail: `Email syntax and domain verified locally without network lookups. Target domain classified as ${provider}.`,
        icon: "offline-mail-classifier",
      },
      {
        name: "CRYPTOGRAPHIC HASH DERIVATION (OFFLINE MODE)",
        category: "Identity verification",
        url: "",
        status: "observed",
        verified: true,
        confidence: "high",
        identifierDisplay: `SHA-256: ${sha256Hex.slice(0, 16)}...`,
        fieldsCount: 2,
        extraFields: {
          "SHA-256 Hash": sha256Hex,
          "Utility": "Lookup key for Gravatar, HaveIBeenPwned, and forensic databases",
        },
        detail: "Locally derived cryptographic digest for forensic cross-referencing.",
        icon: "hash-generator",
      },
      {
        name: "OFFLINE ANALYSIS NOTICE",
        category: "Identity verification",
        url: "",
        status: "observed",
        verified: true,
        confidence: "high",
        identifierDisplay: "Offline Mode Active",
        fieldsCount: 2,
        extraFields: {
          "Mode": "Air-Gapped / Offline",
          "Skipped Lookups": "OpenPGP keyserver, live Gravatar, and GitHub commit author history",
        },
        detail: "Running in Offline Mode. Live OpenPGP keyserver queries, Gravatar profiles, and GitHub commit index lookups were skipped.",
        icon: "offline-notice",
      },
    ];

    return {
      email: cleaned,
      username,
      domain,
      provider,
      isFreeProvider,
      isDisposable,
      entities: {
        names: [],
        profile_pictures: [],
        banners: [],
        usernames: [username],
        emails: [cleaned],
        phones: [],
      },
      platforms,
    };
  }

  const [pgp, grav, github, mx] = await Promise.all([
    queryPgpKeyserver(cleaned),
    queryGravatar(sha256Hex),
    queryGithubCommits(cleaned),
    queryMxRecords(domain),
  ]);

  const names = new Set<string>();
  pgp.names.forEach(name => names.add(name));
  if (grav.displayName) names.add(grav.displayName);
  github.commits.forEach(commit => names.add(commit.author));

  const usernames = new Set<string>();
  github.commits.forEach(commit => { if (commit.login) usernames.add(commit.login); });
  if (grav.displayName && !grav.displayName.includes(" ")) usernames.add(grav.displayName);

  const avatars = new Set<string>();
  if (grav.photo) avatars.add(grav.photo);
  github.commits.forEach(commit => { if (commit.avatar) avatars.add(commit.avatar); });

  const emails = new Set<string>([cleaned, ...pgp.altEmails]);
  const platforms: EmailResult["platforms"] = [];

  if (mx.ok) {
    platforms.push({
      name: "DOMAIN MAIL ROUTING (MX)",
      category: "Domain infrastructure",
      url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodeURIComponent(domain)}`,
      status: mx.records.length ? "observed" : "not_found",
      verified: true,
      confidence: "high",
      identifierDisplay: mx.records.length ? mx.records[0] : `No MX answer for ${domain}`,
      fieldsCount: 2,
      extraFields: { "Domain": domain, "MX records": mx.records.join(", ") || "No records returned" },
      detail: mx.records.length
        ? `DNS returned ${mx.records.length} MX record(s) for ${domain}. This is a domain-level mail-routing fact and does not prove that this mailbox exists.`
        : `DNS query succeeded but returned no MX records for ${domain}. This does not prove the address is invalid.`,
      icon: "cloudflare-dns.com",
      httpStatus: mx.status,
    });
  } else {
    platforms.push({
      name: "DOMAIN MAIL ROUTING (MX)",
      category: "Domain infrastructure",
      url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodeURIComponent(domain)}`,
      status: "inconclusive",
      verified: false,
      confidence: "none",
      identifierDisplay: "MX provider unavailable",
      detail: "DNS MX lookup failed; mailbox existence and mail routing remain unknown.",
      icon: "cloudflare-dns.com",
      httpStatus: mx.status,
    });
  }

  if (github.commits.length) {
    const first = github.commits[0];
    platforms.push({
      name: "GITHUB PUBLIC COMMITS",
      category: "Public code activity",
      url: first.url || `https://github.com/search?q=${encodeURIComponent(cleaned)}&type=commits`,
      status: "candidate",
      verified: false,
      confidence: "medium",
      identityName: first.author,
      identifierDisplay: `Commit author: ${first.author}${first.login ? ` (@${first.login})` : ""}`,
      fieldsCount: 3,
      extraFields: {
        "Exact author email match": cleaned,
        "Matching public commits": String(github.commits.length),
        ...(first.date ? { "Commit date": first.date } : {}),
        ...(first.login ? { "GitHub login": first.login } : {}),
      },
      detail: "GitHub search returned public commits whose commit-author email exactly matches the queried address. This is a candidate association, not proof of account ownership.",
      icon: "github.com",
      httpStatus: github.status,
    });
  } else if (github.status && github.status >= 200 && github.status < 300) {
    platforms.push({
      name: "GITHUB PUBLIC COMMITS",
      category: "Public code activity",
      url: `https://github.com/search?q=${encodeURIComponent(cleaned)}&type=commits`,
      status: "not_found",
      verified: false,
      confidence: "none",
      detail: "GitHub commit search returned no exact public commit-author email match.",
      icon: "github.com",
      httpStatus: github.status,
    });
  } else {
    platforms.push({
      name: "GITHUB PUBLIC COMMITS",
      category: "Public code activity",
      url: `https://github.com/search?q=${encodeURIComponent(cleaned)}&type=commits`,
      status: "inconclusive",
      verified: false,
      confidence: "none",
      detail: "GitHub search was unavailable or rate-limited; no conclusion is drawn.",
      icon: "github.com",
      httpStatus: github.status,
    });
  }

  if (grav.found) {
    platforms.push({
      name: "GRAVATAR PUBLIC PROFILE",
      category: "Public avatar metadata",
      url: `https://gravatar.com/${sha256Hex}`,
      status: "candidate",
      verified: false,
      confidence: "low",
      ...(grav.displayName ? { identityName: grav.displayName } : {}),
      identifierDisplay: "Matching public Gravatar resource",
      fieldsCount: 2,
      extraFields: {
        ...(grav.displayName ? { "Display name": grav.displayName } : {}),
        ...(grav.photo ? { "Avatar URL": grav.photo } : {}),
        ...(grav.aboutMe ? { "About": grav.aboutMe } : {}),
      },
      detail: "A public Gravatar resource exists for the email hash. This is a candidate association and does not independently verify who controls the mailbox.",
      icon: "gravatar.com",
      httpStatus: grav.status,
    });
  } else {
    platforms.push({
      name: "GRAVATAR PUBLIC PROFILE",
      category: "Public avatar metadata",
      url: `https://gravatar.com/${sha256Hex}`,
      status: grav.status && grav.status >= 200 && grav.status < 300 ? "not_found" : "inconclusive",
      verified: false,
      confidence: "none",
      detail: "No public Gravatar profile was confirmed, or the provider did not return a usable response.",
      icon: "gravatar.com",
      httpStatus: grav.status,
    });
  }

  if (pgp.names.length || pgp.altEmails.length) {
    platforms.push({
      name: "OPENPGP KEYSERVER",
      category: "Public cryptographic metadata",
      url: `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=${encodeURIComponent(cleaned)}`,
      status: "candidate",
      verified: false,
      confidence: "medium",
      ...(pgp.names[0] ? { identityName: pgp.names[0] } : {}),
      identifierDisplay: "Email appears in a public OpenPGP user ID",
      fieldsCount: 2,
      extraFields: {
        "Key user IDs": pgp.names.join(", ") || "Not parsed",
        ...(pgp.altEmails.length ? { "Other emails in matching key": pgp.altEmails.join(", ") } : {}),
      },
      detail: "The address appears in a public OpenPGP key user ID. Key publication is a lead, not proof of the current mailbox controller's identity.",
      icon: "keyserver.ubuntu.com",
      httpStatus: pgp.status,
    });
  } else {
    platforms.push({
      name: "OPENPGP KEYSERVER",
      category: "Public cryptographic metadata",
      url: `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=${encodeURIComponent(cleaned)}`,
      status: pgp.status && pgp.status >= 200 && pgp.status < 300 ? "not_found" : "inconclusive",
      verified: false,
      confidence: "none",
      detail: "No matching OpenPGP user ID was returned, or the keyserver was unavailable.",
      icon: "keyserver.ubuntu.com",
      httpStatus: pgp.status,
    });
  }

  return {
    email: cleaned, username, domain, provider, isFreeProvider, isDisposable,
    entities: {
      names: Array.from(names),
      profile_pictures: Array.from(avatars),
      banners: [],
      usernames: Array.from(usernames),
      emails: Array.from(emails),
      phones: [],
    },
    platforms,
  };
}
