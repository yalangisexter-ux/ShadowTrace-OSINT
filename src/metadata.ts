/**
 * Metadata triage for supplied content.
 *
 * This endpoint currently accepts text or a data URL, not multipart uploads.
 * It never invents EXIF, GPS, camera, author, or document timestamps and does
 * not fetch arbitrary URLs from the Worker.
 */
export interface MetadataResult {
  input: string;
  kind: "image" | "document" | "raw";
  mimeType?: string;
  fileSize?: number;
  sha256?: string;
  embedded: { emails: string[]; urls: string[]; phones: string[] };
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
    status: "observed" | "candidate" | "inconclusive";
    verified?: boolean;
    identifierDisplay?: string;
    fieldsCount?: number;
    extraFields?: Record<string, string>;
    detail: string;
    icon: string;
  }[];
}

const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const URL_REGEX = /https?:\/\/[^\s"'<>]+/g;
const PHONE_REGEX = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

function decodeDataUrl(value: string): { mimeType: string; bytes: Uint8Array } | null {
  const comma = value.indexOf(",");
  if (!value.startsWith("data:") || comma < 0) return null;
  const metadata = value.slice(5, comma);
  const payload = value.slice(comma + 1);
  const parts = metadata.split(";");
  const mimeType = parts[0] || "text/plain";
  try {
    if (parts.includes("base64")) {
      const binary = atob(payload);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return { mimeType, bytes };
    }
    return { mimeType, bytes: new TextEncoder().encode(decodeURIComponent(payload)) };
  } catch {
    return null;
  }
}

export async function analyzeMetadata(input: string): Promise<MetadataResult> {
  const clean = input.trim();
  const isHttpUrl = /^https?:\/\//i.test(clean);
  const decoded = decodeDataUrl(clean);
  const rawBytes = decoded?.bytes ?? (!isHttpUrl && !clean.startsWith("data:") ? new TextEncoder().encode(clean) : null);
  const mimeType = decoded?.mimeType;
  const kind: MetadataResult["kind"] =
    mimeType?.startsWith("image/") || /\.(jpg|jpeg|png|webp|tiff|gif)(\?|$)/i.test(clean) ? "image" :
    mimeType === "application/pdf" || /\.(pdf|doc|docx|odt)(\?|$)/i.test(clean) ? "document" : "raw";

  let sha256: string | undefined;
  let fileSize: number | undefined;
  let extractedText = "";
  if (rawBytes) {
    const digest = await crypto.subtle.digest("SHA-256", rawBytes);
    sha256 = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
    fileSize = rawBytes.byteLength;
    extractedText = new TextDecoder("utf-8").decode(rawBytes);
  }

  const embedded = {
    emails: Array.from(new Set(extractedText.match(EMAIL_REGEX) || [])),
    urls: Array.from(new Set(extractedText.match(URL_REGEX) || [])),
    phones: Array.from(new Set(extractedText.match(PHONE_REGEX) || [])),
  };

  const platforms: MetadataResult["platforms"] = [];
  if (sha256) {
    platforms.push({
      name: "SUPPLIED CONTENT FINGERPRINT",
      category: "Evidence integrity",
      url: "",
      status: "observed",
      verified: true,
      identifierDisplay: `SHA-256: ${sha256}`,
      fieldsCount: 2,
      extraFields: {
        "SHA-256": sha256,
        "Byte length": String(fileSize ?? 0),
        "MIME type": mimeType || "text/plain / unspecified",
      },
      detail: "Fingerprint calculated from the exact content supplied to this endpoint. No EXIF or document properties are inferred.",
      icon: "local-input",
    });
  } else if (isHttpUrl) {
    platforms.push({
      name: "REMOTE FILE NOT FETCHED",
      category: "Metadata extraction",
      url: clean,
      status: "inconclusive",
      verified: false,
      identifierDisplay: "Upload file bytes to inspect metadata",
      detail: "Only a URL was supplied. The Worker does not fetch arbitrary URLs; no file metadata has been extracted.",
      icon: "remote-url",
    });
  } else {
    platforms.push({
      name: "UNREADABLE DATA URL",
      category: "Metadata extraction",
      url: "",
      status: "inconclusive",
      verified: false,
      identifierDisplay: "Unable to decode supplied data URL",
      detail: "The data URL was malformed or could not be decoded. No metadata is reported.",
      icon: "input",
    });
  }

  if (embedded.emails.length || embedded.urls.length || embedded.phones.length) {
    platforms.push({
      name: "EMBEDDED TEXT INDICATORS",
      category: "Entity extraction",
      url: "",
      status: "observed",
      verified: true,
      identifierDisplay: `${embedded.emails.length} email(s) · ${embedded.urls.length} URL(s) · ${embedded.phones.length} phone-like string(s)`,
      fieldsCount: 3,
      extraFields: {
        ...(embedded.emails.length ? { "Emails": embedded.emails.join(", ") } : {}),
        ...(embedded.urls.length ? { "URLs": embedded.urls.slice(0, 20).join(", ") } : {}),
        ...(embedded.phones.length ? { "Phone-like strings": embedded.phones.join(", ") } : {}),
      },
      detail: "Indicators were extracted from the decoded text representation. Each item requires contextual validation.",
      icon: "text-extraction",
    });
  }

  return {
    input: clean.slice(0, 200),
    kind,
    mimeType,
    fileSize,
    sha256,
    embedded,
    entities: {
      names: [],
      profile_pictures: [],
      banners: [],
      usernames: [],
      emails: embedded.emails,
      phones: embedded.phones,
    },
    platforms,
  };
}
