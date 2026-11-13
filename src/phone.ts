/**
 * Telecom & Digital Phone Footprint Intelligence Engine
 * ITU-T / E.164 normalization, carrier lookup, circle detection,
 * WhatsApp/Telegram/Truecaller deep hooks, and UPI financial handles.
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
  platforms: {
    name: string;
    category: string;
    url: string;
    status: "verified" | "candidate" | "inconclusive";
    detail: string;
    icon: string;
  }[];
}

// India telecom circle prefixes (common GSM allocations)
const INDIA_CIRCLES: Record<string, { region: string; carrier: string }> = {
  "9010": { region: "Andhra Pradesh & Telangana", carrier: "Bharti Airtel" },
  "9848": { region: "Andhra Pradesh & Telangana", carrier: "Bharti Airtel" },
  "9849": { region: "Andhra Pradesh & Telangana", carrier: "Bharti Airtel" },
  "9949": { region: "Andhra Pradesh & Telangana", carrier: "Bharti Airtel" },
  "8978": { region: "Andhra Pradesh & Telangana", carrier: "Vodafone Idea" },
  "9000": { region: "Andhra Pradesh & Telangana", carrier: "Vodafone Idea" },
  "7093": { region: "Andhra Pradesh & Telangana", carrier: "Reliance Jio" },
  "8374": { region: "Andhra Pradesh & Telangana", carrier: "Reliance Jio" },
  "9820": { region: "Mumbai", carrier: "Vodafone Idea" },
  "9821": { region: "Delhi & NCR", carrier: "Vodafone Idea" },
  "9811": { region: "Delhi & NCR", carrier: "Vodafone Idea" },
  "9810": { region: "Delhi & NCR", carrier: "Bharti Airtel" },
  "9845": { region: "Karnataka (Bangalore)", carrier: "Bharti Airtel" },
  "9844": { region: "Karnataka", carrier: "Vodafone Idea" },
  "9840": { region: "Tamil Nadu (Chennai)", carrier: "Bharti Airtel" },
  "9841": { region: "Tamil Nadu", carrier: "Vodafone Idea" },
  "9830": { region: "Kolkata", carrier: "Vodafone Idea" },
  "9831": { region: "Kolkata", carrier: "Bharti Airtel" },
  "9829": { region: "Rajasthan", carrier: "Bharti Airtel" },
  "9826": { region: "Madhya Pradesh", carrier: "Bharti Airtel" },
  "9412": { region: "Uttar Pradesh (West)", carrier: "BSNL Mobile" },
  "9415": { region: "Uttar Pradesh (East)", carrier: "BSNL Mobile" },
};

export function analyzePhoneNumber(input: string): PhoneResult {
  const cleaned = input.trim();
  const digits = cleaned.replace(/\D/g, "");

  let country = "International";
  let countryCode = "+";
  let formatted = cleaned;
  let e164 = "";
  let region = "Global Network";
  let carrier = "Mobile Network Operator";
  let lineType: "Mobile" | "Fixed Line" | "VoIP" | "Toll Free" | "Unknown" = "Unknown";
  let timezone = "UTC";

  // 1. India (+91)
  if ((digits.length === 10 && /^[6-9]/.test(digits)) ||
      (digits.length === 12 && digits.startsWith("91") && /^[6-9]/.test(digits.slice(2)))) {
    
    const national10 = digits.length === 12 ? digits.slice(2) : digits;
    country = "India";
    countryCode = "+91";
    e164 = `+91${national10}`;
    formatted = `+91 ${national10.slice(0, 5)} ${national10.slice(5)}`;
    lineType = "Mobile";
    timezone = "Asia/Kolkata (IST, UTC+5:30)";

    const prefix4 = national10.slice(0, 4);
    if (INDIA_CIRCLES[prefix4]) {
      region = INDIA_CIRCLES[prefix4].region;
      carrier = `${INDIA_CIRCLES[prefix4].carrier} (Original circle series)`;
    } else {
      region = "India National Telecom Network";
      carrier = "GSM Wireless Operator (Jio / Airtel / Vi / BSNL)";
    }
  }
  // 2. North America (+1 US/Canada)
  else if ((digits.length === 10 && /^[2-9]/.test(digits)) ||
           (digits.length === 11 && digits.startsWith("1"))) {
    const national10 = digits.length === 11 ? digits.slice(1) : digits;
    country = "United States / Canada";
    countryCode = "+1";
    e164 = `+1${national10}`;
    formatted = `+1 (${national10.slice(0, 3)}) ${national10.slice(3, 6)}-${national10.slice(6)}`;
    lineType = "Mobile";
    region = `North American Area Code ${national10.slice(0, 3)}`;
    carrier = "Cellular / Landline Carrier";
    timezone = "US/Canada (EST/CST/MST/PST)";
  }
  // 3. United Kingdom (+44)
  else if (digits.startsWith("44") && digits.length >= 11) {
    country = "United Kingdom";
    countryCode = "+44";
    e164 = `+${digits}`;
    formatted = `+44 ${digits.slice(2, 6)} ${digits.slice(6)}`;
    lineType = "Mobile";
    region = "United Kingdom Telecom Network";
    carrier = "UK Mobile Carrier (EE / O2 / Vodafone / Three)";
    timezone = "Europe/London (GMT/BST)";
  }
  // 4. Australia (+61)
  else if (digits.startsWith("61") && digits.length >= 10) {
    country = "Australia";
    countryCode = "+61";
    e164 = `+${digits}`;
    formatted = `+61 ${digits.slice(2)}`;
    lineType = "Mobile";
    region = "Australia Telecom Network";
    carrier = "Telstra / Optus / Vodafone";
    timezone = "Australia (AEST, UTC+10)";
  }
  // 5. United Arab Emirates (+971)
  else if (digits.startsWith("971") && digits.length >= 11) {
    country = "United Arab Emirates";
    countryCode = "+971";
    e164 = `+${digits}`;
    formatted = `+971 ${digits.slice(3)}`;
    lineType = "Mobile";
    region = "UAE Telecom Network";
    carrier = "e& (Etisalat) / du";
    timezone = "Asia/Dubai (GST, UTC+4)";
  }
  else {
    e164 = `+${digits}`;
    formatted = `+${digits}`;
    countryCode = "+" + digits.slice(0, 3);
  }

  // Messaging & Identity Hooks
  const rawCleanedDigits = e164.replace(/\D/g, "");
  const platforms: PhoneResult["platforms"] = [
    {
      name: "WhatsApp Messenger",
      category: "Messaging",
      url: `https://wa.me/${rawCleanedDigits}`,
      status: "candidate",
      detail: `Direct messaging hook for ${formatted}. Tap to verify active WhatsApp account / profile picture.`,
      icon: "whatsapp.com"
    },
    {
      name: "Telegram Messenger",
      category: "Messaging",
      url: `https://t.me/+${rawCleanedDigits}`,
      status: "candidate",
      detail: `Direct user hook on Telegram network for ${formatted}.`,
      icon: "telegram.org"
    },
    {
      name: "Truecaller Directory",
      category: "Identity",
      url: country === "India" 
        ? `https://www.truecaller.com/search/in/${digits.slice(-10)}` 
        : `https://www.truecaller.com/search/global/${rawCleanedDigits}`,
      status: "candidate",
      detail: `Query community caller ID, associated identity names, and spam reputation for ${formatted}.`,
      icon: "truecaller.com"
    }
  ];

  // If Indian number, add UPI (Unified Payments Interface) handle checks
  if (country === "India") {
    const national10 = digits.slice(-10);
    platforms.push(
      {
        name: "Paytm Payments (UPI)",
        category: "Financial",
        url: `https://paytm.com`,
        status: "candidate",
        detail: `Associated VPA: ${national10}@paytm. Common default UPI handle for this mobile number.`,
        icon: "paytm.com"
      },
      {
        name: "Google Pay (UPI / Axis)",
        category: "Financial",
        url: `https://pay.google.com`,
        status: "candidate",
        detail: `Associated VPA: ${national10}@okaxis or ${national10}@oksbi.`,
        icon: "google.com"
      },
      {
        name: "PhonePe (UPI / YBL)",
        category: "Financial",
        url: `https://phonepe.com`,
        status: "candidate",
        detail: `Associated VPA: ${national10}@ybl / ${national10}@ibl.`,
        icon: "phonepe.com"
      }
    );
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
    platforms,
  };
}
