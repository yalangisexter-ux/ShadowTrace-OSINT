/**
 * Phone number parsing only.
 *
 * A phone number's prefix does not prove its current carrier, subscriber,
 * WhatsApp/Telegram registration, Truecaller identity, or UPI handles.
 * Those require provider-authorized live evidence and are deliberately not
 * inferred here. Number portability makes old prefix-to-carrier tables unsafe.
 */
export interface PhoneResult {
  number: string;
  formatted: string;
  e164: string;
  country: string;
  countryCode: string;
  region: string;
  carrier: string;
  lineType: "Mobile" | "Fixed Line" | "VoIP" | "Toll Free" | "Unknown";
  timezone: string;
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
    confidence?: "high" | "medium" | "low" | "none";
    httpStatus?: number | null;
    identityName?: string;
    identifierDisplay?: string;
    fieldsCount?: number;
    extraFields?: Record<string, string>;
    detail: string;
    icon: string;
  }[];
}

function digitsOnly(value: string): string {
  return value.replace(/\D/g, "");
}

export async function analyzePhoneNumber(input: string): Promise<PhoneResult> {
  const cleaned = input.trim();
  const digits = digitsOnly(cleaned);
  if (digits.length < 7 || digits.length > 15 || !/^[1-9]/.test(digits)) {
    throw new Error("Enter a phone number with 7–15 digits, including its country code where possible.");
  }

  let country = "Unknown";
  let countryCode = "";
  let e164 = cleaned.startsWith("+") ? `+${digits}` : `+${digits}`;
  let formatted = e164;
  let region = "Not reliably inferable from a phone number";
  const carrier = "Unknown — current carrier cannot be established from the number alone";
  const lineType: PhoneResult["lineType"] = "Unknown";
  let timezone = "Unknown";

  if ((digits.length === 10 && /^[6-9]/.test(digits)) ||
      (digits.length === 12 && digits.startsWith("91") && /^[6-9]/.test(digits.slice(2)))) {
    const national = digits.length === 12 ? digits.slice(2) : digits;
    country = "India";
    countryCode = "+91";
    e164 = `+91${national}`;
    formatted = `+91 ${national.slice(0, 5)} ${national.slice(5)}`;
    timezone = "Asia/Kolkata";
    region = "Telecom circle not determined; number portability may change the original operator";
  } else if (digits.length === 11 && digits.startsWith("1")) {
    const national = digits.slice(1);
    country = "United States / Canada";
    countryCode = "+1";
    e164 = `+1${national}`;
    formatted = `+1 (${national.slice(0, 3)}) ${national.slice(3, 6)}-${national.slice(6)}`;
    region = `NANP area code ${national.slice(0, 3)} (not a reliable current location)`;
  } else if (digits.startsWith("44") && digits.length >= 10) {
    country = "United Kingdom";
    countryCode = "+44";
    e164 = `+${digits}`;
    formatted = `+44 ${digits.slice(2)}`;
    timezone = "Europe/London";
    region = "Not reliably inferable from the number";
  } else if (digits.startsWith("33") && digits.length >= 10) {
    country = "France";
    countryCode = "+33";
    e164 = `+${digits}`;
    formatted = `+33 ${digits.slice(2)}`;
    timezone = "Europe/Paris";
    region = "Not reliably inferable from the number";
  } else if (digits.startsWith("1") && digits.length === 10) {
    country = "United States / Canada";
    countryCode = "+1";
    e164 = `+1${digits}`;
    formatted = `+1 (${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
    region = `NANP area code ${digits.slice(0, 3)} (not a reliable current location)`;
  } else {
    countryCode = cleaned.startsWith("+") ? `+${digits.slice(0, Math.min(3, digits.length))}` : "";
  }

  return {
    number: cleaned,
    formatted,
    e164,
    country,
    countryCode,
    region,
    carrier,
    lineType,
    timezone,
    entities: {
      names: [],
      profile_pictures: [],
      banners: [],
      usernames: [],
      emails: [],
      phones: [e164],
    },
    // No cards are emitted for unqueried directories or generated search URLs.
    platforms: [],
  };
}
