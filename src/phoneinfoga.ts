/**
 * PhoneInfoga Integration Engine
 * Ported directly from sundowndev/phoneinfoga (GPL/MIT Compatible Recon)
 * Generates PhoneInfoga OSINT scanner footprints, Google dorks,
 * and direct messaging inquiry deep-links.
 */

export interface PhoneInfogaDork {
  category: "social_media" | "public_directories" | "documents_leaks" | "reputation_spam";
  title: string;
  query: string;
  searchUrl: string;
}

export interface PhoneInfogaFootprint {
  e164: string;
  formatted: string;
  messagingLinks: {
    whatsapp: string;
    telegram: string;
    viber: string;
    sms: string;
    tel: string;
  };
  dorks: PhoneInfogaDork[];
}

export function generatePhoneInfogaFootprint(e164: string, formatted?: string): PhoneInfogaFootprint {
  const digits = e164.replace(/\D/g, "");
  const fmt = formatted || e164;
  const buildSearchUrl = (q: string) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;

  const messagingLinks = {
    whatsapp: `https://wa.me/${digits}`,
    telegram: `https://t.me/+${digits}`,
    viber: `viber://chat?number=%2B${digits}`,
    sms: `sms:${e164}`,
    tel: `tel:${e164}`,
  };

  const dorks: PhoneInfogaDork[] = [
    // Social Media Footprints
    {
      category: "social_media",
      title: "Facebook Profile / Post Search",
      query: `site:facebook.com "${fmt}" OR "${e164}" OR "${digits}"`,
      searchUrl: buildSearchUrl(`site:facebook.com "${fmt}" OR "${e164}" OR "${digits}"`),
    },
    {
      category: "social_media",
      title: "LinkedIn Professional Profile Search",
      query: `site:linkedin.com/in/ "${fmt}" OR "${e164}"`,
      searchUrl: buildSearchUrl(`site:linkedin.com/in/ "${fmt}" OR "${e164}"`),
    },
    {
      category: "social_media",
      title: "Twitter / X Post & Bio Footprint",
      query: `site:x.com OR site:twitter.com "${fmt}" OR "${e164}"`,
      searchUrl: buildSearchUrl(`site:x.com OR site:twitter.com "${fmt}" OR "${e164}"`),
    },
    {
      category: "social_media",
      title: "Instagram Bio & Post Footprint",
      query: `site:instagram.com "${fmt}" OR "${e164}"`,
      searchUrl: buildSearchUrl(`site:instagram.com "${fmt}" OR "${e164}"`),
    },

    // Public Directories & Caller ID
    {
      category: "public_directories",
      title: "Truecaller Search Index",
      query: `site:truecaller.com "${e164}" OR "${digits}"`,
      searchUrl: buildSearchUrl(`site:truecaller.com "${e164}" OR "${digits}"`),
    },
    {
      category: "public_directories",
      title: "Sync.me Contact Directory",
      query: `site:sync.me "${digits}"`,
      searchUrl: buildSearchUrl(`site:sync.me "${digits}"`),
    },
    {
      category: "public_directories",
      title: "Whitepages / Public Phone Directory",
      query: `site:whitepages.com OR site:fastpeoplesearch.com "${fmt}" OR "${e164}"`,
      searchUrl: buildSearchUrl(`site:whitepages.com OR site:fastpeoplesearch.com "${fmt}" OR "${e164}"`),
    },

    // Documents & Leaks
    {
      category: "documents_leaks",
      title: "Pastebin & Public Paste Leaks",
      query: `site:pastebin.com OR site:ghostbin.com "${e164}" OR "${digits}"`,
      searchUrl: buildSearchUrl(`site:pastebin.com OR site:ghostbin.com "${e164}" OR "${digits}"`),
    },
    {
      category: "documents_leaks",
      title: "Indexed PDF Document Leaks",
      query: `filetype:pdf "${e164}" OR "${fmt}"`,
      searchUrl: buildSearchUrl(`filetype:pdf "${e164}" OR "${fmt}"`),
    },
    {
      category: "documents_leaks",
      title: "Indexed Excel / CSV Spreadsheets",
      query: `(filetype:xls OR filetype:xlsx OR filetype:csv) "${e164}" OR "${digits}"`,
      searchUrl: buildSearchUrl(`(filetype:xls OR filetype:xlsx OR filetype:csv) "${e164}" OR "${digits}"`),
    },

    // Reputation & Spam
    {
      category: "reputation_spam",
      title: "Tellows Caller Reputation & Reports",
      query: `site:tellows.com "${digits}"`,
      searchUrl: buildSearchUrl(`site:tellows.com "${digits}"`),
    },
    {
      category: "reputation_spam",
      title: "WhoCallsMe Consumer Reports",
      query: `site:whocallsme.com "${digits}"`,
      searchUrl: buildSearchUrl(`site:whocallsme.com "${digits}"`),
    },
  ];

  return {
    e164,
    formatted: fmt,
    messagingLinks,
    dorks,
  };
}
