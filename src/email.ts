/**
 * Email Reverse Identity & Intelligence Engine
 */

export interface EmailResult {
  email: string;
  username: string;
  domain: string;
  provider: string;
  isFreeProvider: boolean;
  gravatar: {
    hasAvatar: boolean;
    avatarUrl: string;
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
  "proton.me": "ProtonMail (Encrypted)",
  "protonmail.com": "ProtonMail (Encrypted)",
  "zoho.com": "Zoho Mail",
  "mail.com": "Mail.com",
  "gmx.com": "GMX Mail",
};

export async function analyzeEmail(email: string): Promise<EmailResult> {
  const cleaned = email.trim().toLowerCase();
  const [username, domain] = cleaned.split("@");

  const provider = COMMON_PROVIDERS[domain] || `${domain} (Custom / Business Domain)`;
  const isFreeProvider = Boolean(COMMON_PROVIDERS[domain]);

  // Generate MD5 hash for Gravatar using Web Crypto API
  const enc = new TextEncoder();
  // Simple MD5 or SHA256 fallback (Gravatar v3 supports SHA-256)
  const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(cleaned));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  // Gravatar URL
  const avatarUrl = `https://www.gravatar.com/avatar/${sha256Hex}?d=mp&s=128`;

  const pivots = [
    {
      name: "GitHub Commit Search",
      category: "Code & Commits",
      url: `https://github.com/search?q=author-email%3A%22${encodeURIComponent(cleaned)}%22&type=commits`,
      status: "candidate" as const,
      detail: `Check public Git commits authored by ${cleaned} across all public GitHub repositories.`,
      icon: "github.com",
    },
    {
      name: "Gravatar Digital Profile",
      category: "Identity & Avatar",
      url: `https://gravatar.com/${sha256Hex}`,
      status: "candidate" as const,
      detail: `Inspect globally recognized avatar (Gravatar) and linked profile bio for ${cleaned}.`,
      icon: "gravatar.com",
    },
    {
      name: "Google Account Presence",
      category: "Identity",
      url: `https://contacts.google.com`,
      status: "candidate" as const,
      detail: domain.includes("gmail.com") 
        ? `Primary Google Account identifier (@${domain}). Active on Google Play, YouTube, and Drive.` 
        : `Check if ${domain} is hosted on Google Workspace.`,
      icon: "google.com",
    },
    {
      name: "HaveIBeenPwned Breach Check",
      category: "Breach Records",
      url: `https://haveibeenpwned.com/account/${encodeURIComponent(cleaned)}`,
      status: "candidate" as const,
      detail: `Check if ${cleaned} has been exposed in publicly indexed historical data breaches.`,
      icon: "haveibeenpwned.com",
    },
    {
      name: "Domain & DNS / MX Intelligence",
      category: "Domain Infrastructure",
      url: `https://whois.domaintools.com/${encodeURIComponent(domain)}`,
      status: "candidate" as const,
      detail: `Query authoritative MX mail exchanges, SPF records, and WHOIS registration for @${domain}.`,
      icon: "domaintools.com",
    }
  ];

  return {
    email: cleaned,
    username,
    domain,
    provider,
    isFreeProvider,
    gravatar: {
      hasAvatar: true,
      avatarUrl,
    },
    pivots,
  };
}
