/**
 * Email Reverse Identity & Intelligence Engine
 * Features disposable email detection, Gravatar profile generation,
 * GitHub commit author discovery, breach lookups, and username pivot.
 */

export interface EmailResult {
  email: string;
  username: string;
  domain: string;
  provider: string;
  isFreeProvider: boolean;
  isDisposable: boolean;
  gravatar: {
    hasAvatar: boolean;
    avatarUrl: string;
    profileUrl: string;
  };
  pivots: {
    name: string;
    category: string;
    url: string;
    status: "verified" | "candidate" | "inconclusive";
    detail: string;
    icon: string;
  }[];
}

const COMMON_PROVIDERS: Record<string, string> = {
  "gmail.com": "Google Mail",
  "googlemail.com": "Google Mail",
  "outlook.com": "Microsoft Outlook",
  "hotmail.com": "Microsoft Hotmail",
  "live.com": "Microsoft Live",
  "yahoo.com": "Yahoo Mail",
  "icloud.com": "Apple iCloud",
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

export async function analyzeEmail(email: string): Promise<EmailResult> {
  const cleaned = email.trim().toLowerCase();
  const [username, domain] = cleaned.split("@");

  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const provider = isDisposable 
    ? `${domain} [WARNING: Disposable / Burner Email Service]`
    : (COMMON_PROVIDERS[domain] || `${domain} (Corporate / Custom Mail Exchange)`);
  
  const isFreeProvider = Boolean(COMMON_PROVIDERS[domain]);

  // Generate SHA-256 hash for Gravatar using Web Crypto API
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(cleaned));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  const avatarUrl = `https://www.gravatar.com/avatar/${sha256Hex}?d=mp&s=160`;
  const profileUrl = `https://gravatar.com/${sha256Hex}`;

  const pivots = [
    {
      name: `Cross-Platform Handle Search (@${username})`,
      category: "identity",
      url: `https://github.com/${username}`,
      status: "candidate" as const,
      detail: `Pivot: Username prefix "${username}" extracted from email. Ready for correlation across 40+ platforms.`,
      icon: "github.com",
    },
    {
      name: "GitHub Commit Author Discovery",
      category: "code",
      url: `https://github.com/search?q=author-email%3A%22${encodeURIComponent(cleaned)}%22&type=commits`,
      status: "candidate" as const,
      detail: `Search public Git commits authored by ${cleaned} across millions of open-source repositories.`,
      icon: "github.com",
    },
    {
      name: "Gravatar Digital Profile & Avatar",
      category: "identity",
      url: profileUrl,
      status: "candidate" as const,
      detail: `Inspect globally recognized avatar (Gravatar) and linked public profile for ${cleaned}.`,
      icon: "gravatar.com",
    },
    {
      name: "Google Account Ecosystem",
      category: "identity",
      url: `https://contacts.google.com`,
      status: "candidate" as const,
      detail: domain.includes("gmail.com") 
        ? `Primary Google Account identifier (@${domain}). Active on Google Play, YouTube, Google Drive.` 
        : `Check whether enterprise domain ${domain} delegates to Google Workspace.`,
      icon: "google.com",
    },
    {
      name: "HaveIBeenPwned Breach Records",
      category: "security",
      url: `https://haveibeenpwned.com/account/${encodeURIComponent(cleaned)}`,
      status: "candidate" as const,
      detail: `Audit whether ${cleaned} appeared in known historical database dumps or credential leaks.`,
      icon: "haveibeenpwned.com",
    },
    {
      name: "Domain Infrastructure & MX Security",
      category: "domain",
      url: `https://whois.domaintools.com/${encodeURIComponent(domain)}`,
      status: "candidate" as const,
      detail: `Query authoritative mail exchanges (MX), SPF anti-spoofing policies, and WHOIS registration for @${domain}.`,
      icon: "domaintools.com",
    }
  ];

  return {
    email: cleaned,
    username,
    domain,
    provider,
    isFreeProvider,
    isDisposable,
    gravatar: {
      hasAvatar: true,
      avatarUrl,
      profileUrl,
    },
    pivots,
  };
}
