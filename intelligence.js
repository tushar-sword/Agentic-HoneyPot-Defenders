/**
 * intelligence.js
 * Extracts actionable scam intelligence from scammer messages.
 */

const SUSPICIOUS_KEYWORDS = [
  "urgent", "verify", "blocked", "suspended", "account", "upi", "otp",
  "click", "download", "immediately", "kyc", "lottery", "refund", "loan",
  "prize", "reward", "confirm", "expires", "limited", "congratulations",
  "winner", "claim", "payment", "transfer", "security"
];

// Known UPI PSP handles — these are UPI, not email
const UPI_PSP_HANDLES = new Set([
  "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "ybl", "ibl",
  "axisbank", "hdfcbank", "icici", "sbi", "upi", "fbl", "rbl",
  "apl", "barodampay", "cbin", "cboi", "centralbank", "cnrb",
  "cosb", "dbs", "dcb", "ezeepay", "freecharge", "idbi", "idfc",
  "indus", "jiomoney", "kotak", "mahb", "myicici", "nsdl",
  "pingpay", "postbank", "pnb", "rajgovhdfcbank", "sib", "timecosmos",
  "ubi", "unionbank", "utbi", "ucobank", "vijb", "waaxis", "wahdfcbank",
  "waicici", "wasbi", "jupiteraxis", "slice", "fi", "niyoicici",
  "naviaxis", "bhim", "abfspay", "airtel", "airtelpaymentsbank",
  "amazonpay", "gpay", "phonepe", "whatsapp", "superyes", "tapicici",
  "fakeupi", "fakebank", "fraudpay", "scampay"
]);

// Real TLDs that indicate an email (not a UPI)
const EMAIL_TLDS = new Set([
  "com", "in", "org", "net", "edu", "gov", "co", "io", "info",
  "biz", "me", "uk", "us", "au", "de", "fr", "jp", "cn", "ru",
  "gmail", "yahoo", "hotmail", "outlook", "icloud", "rediffmail"
]);

// Personal email domains — these are emails, never UPI
const PERSONAL_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "yahoo.in", "hotmail.com", "outlook.com",
  "icloud.com", "rediffmail.com", "ymail.com", "live.com", "msn.com",
  "protonmail.com", "tutanota.com"
]);

export function extractIntelligence(text, memory) {
  if (!text || !memory?.extractedIntelligence) return;

  const intel = memory.extractedIntelligence;

  extractPhoneNumbers(text, intel);
  extractUPIandEmail(text, intel);
  extractBankAccounts(text, intel);
  extractPhishingLinks(text, intel);
  extractCaseIds(text, intel);
  extractPolicyNumbers(text, intel);
  extractOrderNumbers(text, intel);
  extractSuspiciousKeywords(text, intel);
}

/* ──────────────────────────────────────────────
   PHONE NUMBERS
────────────────────────────────────────────── */

function extractPhoneNumbers(text, intel) {
  const phoneRegex = /(?<!\d)(\+91[\s\-]?|0)?[6-9]\d{9}(?!\d)/g;

  let match;
  while ((match = phoneRegex.exec(text)) !== null) {
    const formatted = formatIndianPhone(match[0]);
    if (formatted) {
      const dedupKey = formatted.replace(/\D/g, "");
      const alreadyStored = intel.phoneNumbers.some(p => p.replace(/\D/g, "") === dedupKey);
      if (!alreadyStored) {
        intel.phoneNumbers.push(formatted);
      }
    }
  }
}

function formatIndianPhone(raw) {
  const digits = raw.replace(/\D/g, "");
  let mobile10;

  if (digits.length === 10 && /^[6-9]/.test(digits)) {
    mobile10 = digits;
  } else if (digits.length === 11 && digits.startsWith("0")) {
    mobile10 = digits.slice(1);
  } else if (digits.length === 12 && digits.startsWith("91")) {
    mobile10 = digits.slice(2);
  } else {
    return null;
  }

  if (!/^[6-9]\d{9}$/.test(mobile10)) return null;
  return `+91-${mobile10}`;
}

/* ──────────────────────────────────────────────
   UPI IDs vs EMAIL — CLEAR SEPARATION
   
   UPI format:  localpart@pspHandle
   - pspHandle is a known PSP (ybl, oksbi, paytm, etc.)
   - OR handle has NO dot and is not a known TLD
   
   Email format: localpart@domain.tld
   - domain has a dot followed by a known TLD
   - OR domain is a known personal email provider
────────────────────────────────────────────── */

function extractUPIandEmail(text, intel) {
  // Match anything that looks like user@something
  const atRegex = /\b([a-zA-Z0-9._+\-]{2,})@([a-zA-Z0-9.\-]+)\b/g;

  let match;
  while ((match = atRegex.exec(text)) !== null) {
    const full = match[0].toLowerCase();
    const localPart = match[1].toLowerCase();
    const domainPart = match[2].toLowerCase();

    // Skip if it's inside a URL (handled by phishing link extractor)
    const precedingChar = text[match.index - 1];
    if (precedingChar === "/" || precedingChar === ":") continue;

    const classification = classifyAtString(localPart, domainPart, full);

    if (classification === "email") {
      // Don't add if already stored as UPI
      if (!intel.upiIds.some(u => u === full)) {
        addUnique(intel.emailAddresses, full);
      }
    } else if (classification === "upi") {
      // Don't add if already stored as email
      if (!intel.emailAddresses.some(e => e === full)) {
        addUnique(intel.upiIds, full);
      }
    }
    // classification === "skip" → ignore
  }
}

function classifyAtString(localPart, domainPart, full) {
  // If domain contains a dot, check the TLD
  if (domainPart.includes(".")) {
    const parts = domainPart.split(".");
    const tld = parts[parts.length - 1];
    const secondLevel = parts.slice(0, -1).join(".");

    // Known personal email → definitely email
    if (PERSONAL_EMAIL_DOMAINS.has(domainPart)) return "email";

    // Known TLD → email
    if (EMAIL_TLDS.has(tld)) return "email";

    // Has dot but unrecognised TLD — treat as email (safer assumption)
    return "email";
  }

  // No dot in domain — check if it's a known UPI PSP handle
  if (UPI_PSP_HANDLES.has(domainPart)) return "upi";

  // Domain is a short word with no dot — could be UPI handle like "fakebank"
  // Treat as UPI only if localpart looks like a UPI ID (no spaces, reasonable length)
  if (domainPart.length >= 2 && domainPart.length <= 20 && /^[a-z0-9.\-_]+$/.test(domainPart)) {
    return "upi";
  }

  return "skip";
}

/* ──────────────────────────────────────────────
   BANK ACCOUNTS
────────────────────────────────────────────── */

function extractBankAccounts(text, intel) {
  const bankRegex = /\b\d{11,18}\b/g;
  const matches = text.match(bankRegex) || [];

  for (const acc of matches) {
    if (!isLikelyPhone(acc)) {
      addUnique(intel.bankAccounts, acc);
    }
  }
}

/* ──────────────────────────────────────────────
   PHISHING LINKS
   Must start with http/https — clearly a URL, not an email.
────────────────────────────────────────────── */

function extractPhishingLinks(text, intel) {
  const linkRegex = /https?:\/\/[^\s"'<>)\]]+/g;
  const matches = text.match(linkRegex) || [];

  for (const link of matches) {
    const clean = link.replace(/[.,;)\]>]+$/, "");
    if (clean.length > 10) {
      addUnique(intel.phishingLinks, clean);
    }
  }
}

/* ──────────────────────────────────────────────
   CASE IDs / REFERENCE IDs
   Patterns: CAS-12345, CASE/123456, REF-XXXXXX,
   SBI-12345, TKT-XXXX, INC-XXXX, SR-XXXX
────────────────────────────────────────────── */

function extractCaseIds(text, intel) {
  // Pattern A: short keyword prefix glued (with optional - or /) to a value containing 4+ digits
  // e.g. REF2026001, REF-2026001, CASE-12345, TKT/7890, SR-4521, GR98765
  const pA = /\b((?:REF|CASE|CAS|TKT|INC|SR|GR|CLAIM)[\-\/]?[A-Z0-9]*\d{4,}[A-Z0-9]*)\b/gi;
  for (const m of text.matchAll(pA)) {
    const val = m[1].trim();
    if (/\d{4,}/.test(val)) addUnique(intel.caseIds, val.toUpperCase());
  }

  // Pattern B: longer keyword word + optional "ID/NO/NUMBER" label + value with 4+ digits
  // e.g. "reference ID REF2026001", "COMPLAINT number 12345", "GRIEVANCE ID: GR-9876"
  const pB = /\b(?:REFERENCE|COMPLAINT|TICKET|INCIDENT|GRIEVANCE)[\s]+(?:ID|NUMBER|NO|#)?[\s\-#:\/]*([A-Z]{0,5}\d{4,}[A-Z0-9]*)\b/gi;
  for (const m of text.matchAll(pB)) {
    const val = m[1].trim();
    if (/\d{4,}/.test(val)) addUnique(intel.caseIds, val.toUpperCase());
  }
}

/* ──────────────────────────────────────────────
   POLICY NUMBERS
   Patterns: POL-XXXXXX, POLICY/123456,
   LIC-XXXXX, INS-XXXXX
────────────────────────────────────────────── */

function extractPolicyNumbers(text, intel) {
  // Require full keyword (no short "INS", "POL" alone — too ambiguous)
  // Captured value MUST contain 4+ digits to avoid words like "TANTLY"
  const policyPatterns = [
    // POLICY or INSURANCE + separator + value-with-digits
    /\b(?:POLICY(?:[\s\-]?(?:NO|NUMBER|ID))?|INSURANCE(?:[\s\-]?(?:NO|NUMBER|ID))?)[\s\-#:\/]+([A-Z0-9]*\d{4,}[A-Z0-9]*)\b/gi,
    // LIC/major insurer brands + digits only
    /\b(?:LIC|HDFC[\s\-]LIFE|SBI[\s\-]LIFE|TATA[\s\-]AIA)[\s\-]?(\d{8,15})\b/gi,
  ];

  for (const pattern of policyPatterns) {
    for (const m of text.matchAll(pattern)) {
      const num = (m[1] || m[0]).trim().toUpperCase();
      // Must contain 4+ digits — rejects pure-letter false positives
      if (/\d{4,}/.test(num)) {
        addUnique(intel.policyNumbers, num);
      }
    }
  }
}

/* ──────────────────────────────────────────────
   ORDER NUMBERS
   Patterns: ORD-XXXXXX, ORDER#12345,
   #OD12345678, Amazon/Flipkart style
────────────────────────────────────────────── */

function extractOrderNumbers(text, intel) {
  // Only full keywords + digit-containing values — no short ambiguous prefixes like "IN", "B0"
  const orderPatterns = [
    // ORDER, BOOKING, SHIPMENT, TRACKING + separator + value-with-digits
    /\b(?:ORDER(?:[\s\-]?(?:NO|ID|NUMBER))?|BOOKING(?:[\s\-]?(?:NO|ID|NUMBER))?|SHIPMENT(?:[\s\-]?(?:NO|ID))?|TRACKING(?:[\s\-]?(?:NO|ID))?)[\s\-#:\/]+([A-Z0-9]*\d{4,}[A-Z0-9]*)\b/gi,
    // Flipkart OD prefix — must be OD + 8+ chars with digits
    /\bOD\d[A-Z0-9]{7,15}\b/g,
  ];

  for (const pattern of orderPatterns) {
    for (const m of text.matchAll(pattern)) {
      const num = (m[1] || m[0]).trim().toUpperCase();
      // Must contain 4+ digits — rejects pure-letter false positives
      if (/\d{4,}/.test(num)) {
        addUnique(intel.orderNumbers, num);
      }
    }
  }
}

/* ──────────────────────────────────────────────
   SUSPICIOUS KEYWORDS
────────────────────────────────────────────── */

function extractSuspiciousKeywords(text, intel) {
  const lowerText = text.toLowerCase();
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (lowerText.includes(keyword)) {
      addUnique(intel.suspiciousKeywords, keyword);
    }
  }
}

/* ──────────────────────────────────────────────
   HELPERS
────────────────────────────────────────────── */

function isLikelyPhone(numStr) {
  const d = numStr.replace(/\D/g, "");
  if (d.length === 10 && /^[6-9]/.test(d)) return true;
  if (d.length === 12 && d.startsWith("91") && /^[6-9]/.test(d.slice(2))) return true;
  if (d.length === 11 && d.startsWith("0") && /^[6-9]/.test(d.slice(1))) return true;
  return false;
}

function looksLikeNoise(str) {
  // Reject strings that are all the same character or too generic
  if (/^(.)\1+$/.test(str)) return true;
  if (/^\d{1,3}$/.test(str)) return true;
  return false;
}

function addUnique(array, value) {
  if (!Array.isArray(array) || !value) return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  const lower = trimmed.toLowerCase();
  if (array.some(existing => existing.toLowerCase() === lower)) return false;
  array.push(trimmed);
  return true;
}