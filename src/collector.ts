/**
 * Unified Collector & Plugin Registry Architecture
 * Implements a pluggable, modular collector framework.
 * Allows new collectors to register dynamically without modifying core dispatch logic.
 */

import { analyzeDomain } from "./domain.ts";
import { analyzeIP } from "./ip.ts";
import { analyzeEmail } from "./email.ts";
import { analyzePhoneNumber } from "./phone.ts";
import { searchUsername } from "./providers.ts";
import { analyzeCrypto } from "./crypto.ts";
import { analyzeMetadata } from "./metadata.ts";
import { type SearchType } from "./search.ts";

export interface CollectorPlugin {
  id: string;
  name: string;
  version: string;
  targetTypes: SearchType[];
  description: string;
  health: () => Promise<{ ok: boolean; latencyMs?: number; message?: string }>;
  execute: (query: string, options?: any) => Promise<CollectorExecutionResult>;
}

export interface CollectorExecutionResult {
  query: string;
  type: SearchType;
  label: string;
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
  evidence: {
    provider: string;
    category?: string | null;
    profile_url?: string | null;
    domain?: string | null;
    status: "observed" | "candidate" | "inconclusive" | "not_found";
    verified?: boolean;
    http_status?: number | null;
    confidence?: "high" | "medium" | "low" | "none" | null;
    identity_name?: string | null;
    identifier_display?: string | null;
    fields_count?: number;
    extra_fields?: Record<string, string>;
    detail?: string | null;
    checked_at: string;
  }[];
}

class CollectorRegistry {
  private plugins = new Map<string, CollectorPlugin>();

  register(plugin: CollectorPlugin) {
    this.plugins.set(plugin.id, plugin);
  }

  listPlugins(): { id: string; name: string; version: string; targetTypes: SearchType[]; description: string }[] {
    return Array.from(this.plugins.values()).map(p => ({
      id: p.id,
      name: p.name,
      version: p.version,
      targetTypes: p.targetTypes,
      description: p.description,
    }));
  }

  async checkHealth(): Promise<Record<string, { ok: boolean; latencyMs?: number; message?: string }>> {
    const results: Record<string, any> = {};
    for (const [id, plugin] of this.plugins.entries()) {
      try {
        const start = Date.now();
        const h = await plugin.health();
        results[id] = { ...h, latencyMs: Date.now() - start };
      } catch (err: any) {
        results[id] = { ok: false, message: err.message };
      }
    }
    return results;
  }

  getPluginForType(type: SearchType): CollectorPlugin | undefined {
    return Array.from(this.plugins.values()).find(p => p.targetTypes.includes(type));
  }

  async dispatch(query: string, type: SearchType, options?: any): Promise<CollectorExecutionResult> {
    const plugin = this.getPluginForType(type);
    if (!plugin) {
      throw new Error(`No registered collector plugin for target type "${type}".`);
    }
    return await plugin.execute(query, options);
  }
}

export const collectorManager = new CollectorRegistry();

// 1. Domain Collector Plugin
collectorManager.register({
  id: "collector-domain",
  name: "Domain & DNS Intelligence",
  version: "1.0.0",
  targetTypes: ["domain"],
  description: "Queries Google & Cloudflare DoH, RDAP/WHOIS registrar records, and crt.sh Certificate Transparency.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzeDomain(query);
    return {
      query: d.domain,
      type: "domain",
      label: d.domain,
      entities: {
        names: [d.domain],
        profile_pictures: [],
        banners: [],
        usernames: [],
        emails: [],
        phones: [],
      },
      evidence: d.evidence.map(e => ({
        ...e,
        verified: e.status === "observed",
      })),
    };
  },
});

// 2. IP Collector Plugin
collectorManager.register({
  id: "collector-ip",
  name: "IP Geolocation & Network Intelligence",
  version: "1.0.0",
  targetTypes: ["ip"],
  description: "Resolves GeoIP coordinates, ASN, ISP, Cloud provider footprint, and reverse DNS PTR records.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzeIP(query);
    return {
      query: d.ip,
      type: "ip",
      label: d.ip,
      entities: d.entities,
      evidence: d.platforms.map(p => ({
        provider: p.name,
        category: p.category,
        profile_url: p.url,
        domain: p.icon,
        status: p.status,
        verified: p.verified === true,
        http_status: p.httpStatus ?? null,
        confidence: p.confidence || (p.verified ? "high" : p.status === "candidate" ? "medium" : "none"),
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      })),
    };
  },
});

// 3. Email Collector Plugin
collectorManager.register({
  id: "collector-email",
  name: "Reverse Email & Identity Engine",
  version: "1.1.0",
  targetTypes: ["email"],
  description: "Public Gravatar, exact-match GitHub commit, OpenPGP, and domain MX observations.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzeEmail(query);
    return {
      query: d.email,
      type: "email",
      label: d.email,
      entities: d.entities,
      evidence: d.platforms.map(p => ({
        provider: p.name,
        category: p.category,
        profile_url: p.url,
        domain: p.icon,
        status: p.status,
        verified: p.verified === true,
        http_status: p.httpStatus ?? null,
        confidence: p.confidence || (p.verified ? "high" : p.status === "candidate" ? "medium" : "none"),
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      })),
    };
  },
});

// 4. Phone Collector Plugin
collectorManager.register({
  id: "collector-phone",
  name: "Telecom & Mobile Subscriber Intelligence",
  version: "1.1.0",
  targetTypes: ["phone"],
  description: "Normalizes phone-number format only; carrier, subscriber, and platform registrations require independent live sources.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzePhoneNumber(query);
    return {
      query: d.formatted,
      type: "phone",
      label: d.formatted,
      entities: d.entities,
      evidence: d.platforms.map(p => ({
        provider: p.name,
        category: p.category,
        profile_url: p.url,
        domain: p.icon,
        status: p.status,
        verified: p.verified === true,
        http_status: p.httpStatus ?? null,
        confidence: p.confidence || (p.verified ? "high" : p.status === "candidate" ? "medium" : "none"),
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      })),
    };
  },
});

// 5. Username Collector Plugin
collectorManager.register({
  id: "collector-username",
  name: "Multi-Platform Username Reconnaissance",
  version: "1.2.0",
  targetTypes: ["username"],
  description: "Sherlock and Maigret style reconnaissance scanning 34+ public platforms with avatar and display name extraction.",
  health: async () => ({ ok: true }),
  execute: async (query, options) => {
    const depth = options?.depth || 0;
    const results = await searchUsername(query, depth);

    const discoveredNames = new Set<string>();
    const discoveredAvatars = new Set<string>();
    const INVALID_NAMES = new Set([
      "bitbucket", "github", "gitlab", "steam community", "medium", "substack", "reddit",
      "page not found", "not found", "404", "sign in", "log in", "undefined", "null", "deviantart"
    ]);

    for (const r of results) {
      if (r.status === "candidate") {
        if (r.identity_name && r.identity_name !== query) {
          const lower = r.identity_name.toLowerCase().trim();
          if (!INVALID_NAMES.has(lower) && !lower.startsWith("http") && lower.length >= 2) {
            discoveredNames.add(r.identity_name);
          }
        }
        if (r.extra_fields?.Avatar) {
          discoveredAvatars.add(r.extra_fields.Avatar);
        }
      }
    }

    return {
      query,
      type: "username",
      label: query,
      entities: {
        names: Array.from(discoveredNames),
        profile_pictures: Array.from(discoveredAvatars),
        banners: [],
        usernames: [query],
        emails: [],
        phones: [],

      },
      evidence: results,
    };
  },
});

// 6. Cryptocurrency Collector Plugin
collectorManager.register({
  id: "collector-crypto",
  name: "Cryptocurrency & Blockchain Ledger Engine",
  version: "1.0.0",
  targetTypes: ["crypto"],
  description: "Validates Bitcoin, Ethereum, Solana, and Tron addresses with live balance and explorer hooks.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzeCrypto(query);
    return {
      query: d.address,
      type: "crypto",
      label: `${d.blockchain}: ${d.address.slice(0, 8)}...${d.address.slice(-6)}`,
      entities: d.entities,
      evidence: d.platforms.map(p => ({
        provider: p.name,
        category: p.category,
        profile_url: p.url,
        domain: p.icon,
        status: p.status,
        verified: p.verified === true,
        http_status: null,
        confidence: p.verified ? "high" : p.status === "candidate" ? "medium" : "none",
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      })),
    };
  },
});

// 7. Metadata & Forensics Collector Plugin
collectorManager.register({
  id: "collector-metadata",
  name: "Document & EXIF Forensic Metadata Engine",
  version: "1.0.0",
  targetTypes: ["metadata"],
  description: "Extracts image EXIF GPS coordinates, camera hardware profiles, PDF author metadata, and embedded indicators.",
  health: async () => ({ ok: true }),
  execute: async (query) => {
    const d = await analyzeMetadata(query);
    return {
      query: d.input.slice(0, 40) + "...",
      type: "metadata",
      label: `Metadata: ${d.kind.toUpperCase()}`,
      entities: d.entities,
      evidence: d.platforms.map(p => ({
        provider: p.name,
        category: p.category,
        profile_url: p.url,
        domain: p.icon,
        status: p.status,
        verified: p.verified === true,
        http_status: null,
        confidence: p.verified ? "high" : p.status === "candidate" ? "medium" : "none",
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      })),
    };
  },
});
