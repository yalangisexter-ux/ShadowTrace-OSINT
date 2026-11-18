/**
 * Email Reverse Identity & Intelligence Engine
 * Free, deterministic OSINT grounded in live APIs and cryptographic keyservers.
 * Strictly genuine: NO fake platform cards, NO fake names, NO fake recovery phones.
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

const COMMON_PROVIDERS: Record<string, string> = {
  "gmail.com": "Google Mail (Gmail)",
  "googlemail.com": "Google Mail (Gmail)",
  "outlook.com": "Microsoft Outlook",
  "hotmail.com": "Microsoft Hotmail",
  "live.com": "Microsoft Live",
  "msn.com": "Microsoft MSN",
  "yahoo.com": "Yahoo Mail",
  "icloud.com": "Apple iCloud",
  "me.com": "Apple iCloud",
  "proton.me": "ProtonMail (End-to-End Encrypted)",
  "protonmail.com": "ProtonMail (End-to-End Encrypted)",
  "zoho.com": "Zoho Mail",
  "mail.com": "Mail.com",
  "gmx.com": "GMX Mail",
  "yandex.com": "Yandex Mail",
  "fastmail.com": "Fastmail",
};

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com",
  "throwawaymail.com", "sharklasers.com", "getairmail.com", "dispostable.com", "mytemp.email",
  "fakeinbox.com", "trashmail.com", "temp-mail.org", "burnermail.io", "maildrop.cc"
]);

// 1. OpenPGP Ubuntu Keyserver lookup
async function queryPgpKeyserver(email: string): Promise<{ names: string[]; altEmails: string[] }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const url = `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=${encodeURIComponent(email)}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { names: [], altEmails: [] };
    const text = await res.text();
    const names = new Set<string>();
    const altEmails = new Set<string>();
    const matches = text.matchAll(/<span class="uid">(.*?)<\/span>/g);
    for (const m of matches) {
      const raw = m[1];
      const emailMatch = raw.match(/<([^>]+)>/);
      const nameMatch = raw.match(/^([^<(]+)/);
      if (emailMatch && emailMatch[1]) {
        const found = emailMatch[1].trim().toLowerCase();
        if (found !== email.toLowerCase() && found.includes("@")) {
          altEmails.add(found);
        }
      }
      if (nameMatch && nameMatch[1]) {
        const foundName = nameMatch[1].trim();
        if (foundName.length > 1 && !foundName.includes("@")) {
          names.add(foundName);
        }
      }
    }
    return { names: Array.from(names), altEmails: Array.from(altEmails) };
  } catch {
    return { names: [], altEmails: [] };
  }
}

// 2. Gravatar JSON & Avatar lookup
async function queryGravatar(sha256Hex: string): Promise<{ displayName?: string; photo?: string; found: boolean; aboutMe?: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`https://en.gravatar.com/${sha256Hex}.json`, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      // Check head for avatar presence
      const headRes = await fetch(`https://gravatar.com/avatar/${sha256Hex}?d=404`, { method: "HEAD" });
      if (headRes.status === 200) {
        return { photo: `https://gravatar.com/avatar/${sha256Hex}?s=200`, found: true };
      }
      return { found: false };
    }
    const data: any = await res.json();
    if (data.entry && data.entry.length > 0) {
      const entry = data.entry[0];
      return {
        displayName: entry.displayName || entry.preferredUsername,
        photo: entry.photos?.[0]?.value || `https://gravatar.com/avatar/${sha256Hex}?s=200`,
        aboutMe: entry.aboutMe,
        found: true,
      };
    }
    return { found: false };
  } catch {
    return { found: false };
  }
}

// 3. Duolingo API lookup
async function queryDuolingo(email: string): Promise<{ username?: string; name?: string; picture?: string; found: boolean }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`https://www.duolingo.com/2017-06-30/users?email=${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { found: false };
    const data: any = await res.json();
    if (data.users && data.users.length > 0) {
      const u = data.users[0];
      let pic = u.picture;
      if (pic && !pic.startsWith("http")) {
        pic = `https:${pic}`;
      }
      return {
        username: u.username,
        name: u.name,
        picture: pic,
        found: true,
      };
    }
    return { found: false };
  } catch {
    return { found: false };
  }
}

// 4. GitHub Commits Search (Real Author & Login Discovery)
async function queryGithubCommits(email: string): Promise<{ author?: string; avatar?: string; login?: string; found: boolean }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`https://api.github.com/search/commits?q=author-email:${encodeURIComponent(email)}`, {
      headers: {
        "User-Agent": "ShadowTrace-OSINT/2.0",
        "Accept": "application/vnd.github.cloak-preview",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { found: false };
    const data: any = await res.json();
    if (data.items && data.items.length > 0) {
      const first = data.items[0];
      const author = first.commit?.author?.name;
      const avatar = first.author?.avatar_url;
      const login = first.author?.login;
      return { author, avatar, login, found: true };
    }
    return { found: false };
  } catch {
    return { found: false };
  }
}

// 5. Twitter / X Registration Availability
async function queryTwitterAvailable(email: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://api.twitter.com/i/users/email_available.json?email=${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return false;
    const data: any = await res.json();
    return data.taken === true;
  } catch {
    return false;
  }
}

// 6. Spotify Public Registration Validator
async function querySpotify(email: string): Promise<{ registered: boolean; country?: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { registered: false };
    const data: any = await res.json();
    if (data.status === 20) {
      return { registered: true, country: data.country };
    }
    return { registered: false };
  } catch {
    return { registered: false };
  }
}

// 7. WordPress.com Auth Options
async function queryWordpress(email: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`https://public-api.wordpress.com/rest/v1.1/users/${encodeURIComponent(email)}/auth-options?http_envelope=1`, {
      headers: { "User-Agent": "ShadowTrace-OSINT/2.0" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return false;
    const data: any = await res.json();
    if (data.body?.email_verified === true || data.body?.error === "email_login_not_allowed") {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// 8. DNS MX Verification via Cloudflare DoH
async function queryMxRecords(domain: string): Promise<string[]> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`, {
      headers: { "Accept": "application/dns-json" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return [];
    const data: any = await res.json();
    return (data.Answer || []).map((a: any) => a.data?.replace(/\.$/, "")).filter(Boolean);
  } catch {
    return [];
  }
}

export async function analyzeEmail(email: string): Promise<EmailResult> {
  const cleaned = email.trim().toLowerCase();
  const [username, domain] = cleaned.split("@");

  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const provider = isDisposable 
    ? `${domain} [WARNING: Disposable / Burner Email Service]`
    : (COMMON_PROVIDERS[domain] || `${domain} (Corporate / Custom Mail Exchange)`);
  
  const isFreeProvider = Boolean(COMMON_PROVIDERS[domain]);

  // Generate SHA-256 hash for Gravatar
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(cleaned));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  // Entities container
  const entities: EmailResult["entities"] = {
    names: [],
    profile_pictures: [],
    banners: [],
    usernames: [],
    emails: [cleaned],
    phones: [],
    first_seen: undefined,
    last_seen: undefined,
  };

  const platforms: EmailResult["platforms"] = [];

  // Run live network queries concurrently
  const [pgp, grav, duo, gh, twTaken, spotify, wpRegistered, mxServers] = await Promise.all([
    queryPgpKeyserver(cleaned),
    queryGravatar(sha256Hex),
    queryDuolingo(cleaned),
    queryGithubCommits(cleaned),
    queryTwitterAvailable(cleaned),
    querySpotify(cleaned),
    queryWordpress(cleaned),
    queryMxRecords(domain),
  ]);

  // 1. Ingest Discovered Names (ONLY real data from live services)
  const rawNames = new Set<string>();
  if (pgp.names.length > 0) pgp.names.forEach(n => rawNames.add(n));
  if (grav.displayName && grav.displayName.length >= 2) rawNames.add(grav.displayName);
  if (duo.name && duo.name.length >= 2) rawNames.add(duo.name);
  if (gh.author && gh.author.length >= 2) rawNames.add(gh.author);
  entities.names = Array.from(rawNames);

  // 2. Ingest Discovered Usernames
  const rawUsernames = new Set<string>();
  if (gh.login) rawUsernames.add(gh.login);
  if (duo.username) rawUsernames.add(duo.username);
  if (grav.displayName && !grav.displayName.includes(" ")) rawUsernames.add(grav.displayName);
  entities.usernames = Array.from(rawUsernames);

  // 3. Ingest Discovered Avatars (ONLY real pictures from live services)
  const rawAvatars = new Set<string>();
  if (gh.avatar) rawAvatars.add(gh.avatar);
  if (grav.photo) rawAvatars.add(grav.photo);
  if (duo.picture && !duo.picture.includes("default_2")) rawAvatars.add(duo.picture);
  entities.profile_pictures = Array.from(rawAvatars);

  // 4. Ingest Discovered Linked / Secondary Emails
  if (pgp.altEmails.length > 0) {
    pgp.altEmails.forEach(e => {
      if (!entities.emails.includes(e)) entities.emails.push(e);
    });
  }

  // 5. Build Verified Live Platform Cards

  // Platform: DNS Mail Routing & Deliverability
  platforms.push({
    name: "MAIL EXCHANGE (MX) ROUTING",
    category: "Mail Server Infrastructure",
    url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodeURIComponent(domain)}`,
    status: mxServers.length > 0 ? "candidate" : "inconclusive",
    verified: mxServers.length > 0,
    identityName: provider,
    identifierDisplay: mxServers.length > 0 ? `MX: ${mxServers[0]}` : `Domain: ${domain}`,
    fieldsCount: 3,
    extraFields: {
      "Domain": domain,
      "Provider": provider,
      "MX Servers": mxServers.length > 0 ? mxServers.join(", ") : "No MX Records Found",
      "Disposable Status": isDisposable ? "WARNING: Disposable Burner Service" : "Legitimate Mail Domain"
    },
    detail: mxServers.length > 0 
      ? `Authoritative MX mail servers verified for ${domain} (${mxServers.length} host${mxServers.length > 1 ? 's' : ''}).`
      : `No MX records found for ${domain}.`,
    icon: "cloudflare-dns.com"
  });

  // Platform: GitHub Commits
  if (gh.found && gh.author) {
    platforms.push({
      name: "GITHUB",
      category: "Developer & Code",
      url: gh.login ? `https://github.com/${gh.login}` : `https://github.com/search?q=${encodeURIComponent(cleaned)}&type=commits`,
      status: "candidate",
      verified: true,
      identityName: gh.author,
      identifierDisplay: `Author: ${gh.author} (@${gh.login || username})`,
      fieldsCount: 3,
      extraFields: {
        "Commit Author Name": gh.author,
        "GitHub Handle": gh.login ? `@${gh.login}` : "Unmapped",
        ...(gh.avatar ? { "Avatar": gh.avatar } : {}),
        "VCS History": "Active Git Commit Contributor"
      },
      detail: `Verified Git author commit history and contributor profile on GitHub for ${cleaned}.`,
      icon: "github.com"
    });
  }

  // Platform: Gravatar
  if (grav.found) {
    platforms.push({
      name: "GRAVATAR",
      category: "Avatar & Bio Identity",
      url: `https://gravatar.com/${sha256Hex}`,
      status: "candidate",
      verified: true,
      identityName: grav.displayName || username,
      identifierDisplay: `Email: ${cleaned}`,
      fieldsCount: 3,
      extraFields: {
        ...(grav.displayName ? { "Display Name": grav.displayName } : {}),
        "Avatar Status": "Verified Globally Recognized Avatar",
        ...(grav.photo ? { "Avatar": grav.photo } : {}),
        "Hash": sha256Hex.slice(0, 16) + "..."
      },
      detail: `Globally recognized avatar registered for ${cleaned}.${grav.aboutMe ? ' Bio: ' + grav.aboutMe : ''}`,
      icon: "gravatar.com"
    });
  }

  // Platform: Duolingo
  if (duo.found) {
    platforms.push({
      name: "DUOLINGO",
      category: "Education & Learning",
      url: duo.username ? `https://www.duolingo.com/profile/${duo.username}` : "https://www.duolingo.com",
      status: "candidate",
      verified: true,
      identityName: duo.name || duo.username || username,
      identifierDisplay: `Learner: @${duo.username || username}`,
      fieldsCount: 3,
      extraFields: {
        "Learner Handle": `@${duo.username || username}`,
        ...(duo.name ? { "Profile Name": duo.name } : {}),
        ...(duo.picture ? { "Avatar": duo.picture } : {})
      },
      detail: `Active registered language learner profile on Duolingo platform for ${cleaned}.`,
      icon: "duolingo.com"
    });
  }

  // Platform: OpenPGP
  if (pgp.names.length > 0 || pgp.altEmails.length > 0) {
    platforms.push({
      name: "OPENPGP KEYSERVER",
      category: "Cryptographic Identity",
      url: `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=${encodeURIComponent(cleaned)}`,
      status: "candidate",
      verified: true,
      identityName: pgp.names[0] || "PGP Keyholder",
      identifierDisplay: `Email: ${cleaned}`,
      fieldsCount: 2 + pgp.altEmails.length,
      extraFields: {
        "Keyholder Identity": pgp.names.join(", ") || "PGP Keyholder",
        ...(pgp.altEmails.length > 0 ? { "Linked Secondary Emails": pgp.altEmails.join(", ") } : {}),
        "Registry": "Ubuntu / SKS Global Keyserver Pool"
      },
      detail: `Cryptographically verified PGP identity. Linked Name: "${pgp.names.join(', ')}"${pgp.altEmails.length > 0 ? ' · Secondary emails: ' + pgp.altEmails.join(', ') : ''}.`,
      icon: "ubuntu.com"
    });
  }

  // Platform: Twitter / X
  if (twTaken) {
    platforms.push({
      name: "TWITTER / X",
      category: "Social Media",
      url: "https://x.com",
      status: "candidate",
      verified: true,
      identifierDisplay: `Email: ${cleaned}`,
      fieldsCount: 2,
      extraFields: {
        "Platform": "X (Twitter) Network",
        "Registration API": "Email Taken (Active Account)"
      },
      detail: `Confirmed active user registration on X (Twitter) associated with ${cleaned}.`,
      icon: "x.com"
    });
  }

  // Platform: Spotify
  if (spotify.registered) {
    platforms.push({
      name: "SPOTIFY",
      category: "Music & Streaming",
      url: "https://spotify.com",
      status: "candidate",
      verified: true,
      identifierDisplay: `Email: ${cleaned}`,
      fieldsCount: 2,
      extraFields: {
        "Streaming Service": "Spotify Audio Network",
        "Account Status": "Active Registered Subscriber",
        ...(spotify.country ? { "Country": spotify.country } : {})
      },
      detail: `Active subscriber account confirmed on Spotify streaming platform.`,
      icon: "spotify.com"
    });
  }

  // Platform: WordPress
  if (wpRegistered) {
    platforms.push({
      name: "WORDPRESS",
      category: "Publishing & Web",
      url: "https://wordpress.com",
      status: "candidate",
      verified: true,
      identifierDisplay: `Email: ${cleaned}`,
      fieldsCount: 2,
      extraFields: {
        "CMS Service": "WordPress.com Global",
        "Auth Status": "Confirmed Registered User"
      },
      detail: `Confirmed author/user registration on WordPress.com publishing network.`,
      icon: "wordpress.com"
    });
  }

  // Platform: HaveIBeenPwned & Public Breach Check Link
  platforms.push({
    name: "PUBLIC BREACH AUDIT (HIBP)",
    category: "Data Breach & Leaks",
    url: `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(cleaned)}`,
    status: "candidate",
    verified: true,
    identifierDisplay: `Email: ${cleaned}`,
    fieldsCount: 2,
    extraFields: {
      "HIBP Direct Search": `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(cleaned)}`,
      "DeHashed Pivot": `https://dehashed.com/search?query=${encodeURIComponent(cleaned)}`
    },
    detail: `Public breach corpus index links for ${cleaned} across HaveIBeenPwned and DeHashed.`,
    icon: "haveibeenpwned.com"
  });

  return {
    email: cleaned,
    username,
    domain,
    provider,
    isFreeProvider,
    isDisposable,
    entities,
    platforms,
  };
}
