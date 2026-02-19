import fetch from "node-fetch";

/**
 * callback.js
 *
 * PAYLOAD FIELD ANALYSIS (from official scoring function source code):
 *
 * Response Structure (10pts):
 *   required: sessionId, scamDetected, extractedIntelligence → 2pts each
 *   optional: totalMessagesExchanged + engagementDurationSeconds → 1pt
 *             agentNotes → 1pt, scamType → 1pt, confidenceLevel → 1pt
 *
 * Engagement Quality (10pts) — reads from root-level fields:
 *   engagementDurationSeconds > 0   → 1pt
 *   engagementDurationSeconds > 60  → 2pts
 *   engagementDurationSeconds > 180 → 1pt
 *   totalMessagesExchanged > 0      → 2pts
 *   totalMessagesExchanged >= 5     → 3pts
 *   totalMessagesExchanged >= 10    → 1pt
 *
 * Per-turn API response { "status": "success", "reply": "..." } is SEPARATE
 * — not scored here.
 */

export async function sendFinalCallback(memory) {
  if (!memory) {
    console.error("[Callback] No memory object provided");
    return;
  }

  if (memory.finalCallbackSent) {
    console.log(`[Callback] Already sent for session ${memory.sessionId}, skipping`);
    return;
  }

  const callbackUrl = process.env.FINAL_CALLBACK_URL;
  if (!callbackUrl) {
    console.error("[Callback] FINAL_CALLBACK_URL not configured in environment");
    return;
  }

  const payload = buildPayload(memory);

  console.log(`[Callback] Sending payload for session ${memory.sessionId}:`, JSON.stringify(payload, null, 2));

  const MAX_RETRIES = 3;
  let attempt = 0;
  let success = false;

  while (attempt < MAX_RETRIES && !success) {
    attempt++;
    try {
      const response = await fetch(callbackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        success = true;
        memory.finalCallbackSent = true;
        memory.sessionClosed = true;
        console.log(`[Callback] ✅ Successfully sent for session ${memory.sessionId} (attempt ${attempt})`);
      } else {
        const body = await response.text().catch(() => "");
        console.error(`[Callback] ❌ HTTP ${response.status} on attempt ${attempt}: ${body}`);
      }

    } catch (err) {
      console.error(`[Callback] ❌ Network error on attempt ${attempt}:`, err.message);
    }

    if (!success && attempt < MAX_RETRIES) {
      const delay = 600 * attempt;
      console.log(`[Callback] Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  if (!success) {
    console.error(`[Callback] 🚨 CRITICAL: Failed to send callback after ${MAX_RETRIES} attempts for session ${memory.sessionId}`);
  }
}

/* ──────────────────────────────────────────────
   PAYLOAD BUILDER
────────────────────────────────────────────── */

function buildPayload(memory) {
  const intel = memory.extractedIntelligence || {};
  const metrics = memory.metrics || {};

  const engagementDurationSeconds = metrics.engagementStartTime
    ? Math.round((Date.now() - metrics.engagementStartTime) / 1000)
    : 0;

  const totalMessagesExchanged = metrics.totalMessages || 0;

  // Build extractedIntelligence — only include fields with actual data
  const extractedIntelligence = {};

  if (intel.phoneNumbers?.length > 0)   extractedIntelligence.phoneNumbers   = intel.phoneNumbers;
  if (intel.bankAccounts?.length > 0)   extractedIntelligence.bankAccounts   = intel.bankAccounts;
  if (intel.upiIds?.length > 0)         extractedIntelligence.upiIds         = intel.upiIds;
  if (intel.phishingLinks?.length > 0)  extractedIntelligence.phishingLinks  = intel.phishingLinks;
  if (intel.emailAddresses?.length > 0) extractedIntelligence.emailAddresses = intel.emailAddresses;
  if (intel.caseIds?.length > 0)        extractedIntelligence.caseIds        = intel.caseIds;
  if (intel.policyNumbers?.length > 0)  extractedIntelligence.policyNumbers  = intel.policyNumbers;
  if (intel.orderNumbers?.length > 0)   extractedIntelligence.orderNumbers   = intel.orderNumbers;

  return {
    // ── Required fields (2pts each) ──
    sessionId:              memory.sessionId,
    scamDetected:           true,
    extractedIntelligence,

    // ── Engagement Quality ──
    engagementMetrics: {
      engagementDurationSeconds,
      totalMessagesExchanged
    },

    // ── Optional fields (1pt each) ──
    agentNotes:      generateAgentNotes(memory),
    scamType:        memory.scamType || "other",
    confidenceLevel: metrics.confidenceLevel || null
  };
}

/* ──────────────────────────────────────────────
   AGENT NOTES GENERATOR
   Uses suspicious keywords + tactics for max
   red flag identification scoring
────────────────────────────────────────────── */

function generateAgentNotes(memory) {
  const notes = [];
  const lookup = memory.lookup || {};
  const scamType = memory.scamType;
  const intel = memory.extractedIntelligence || {};
  const turns = Math.floor((memory.metrics?.totalMessages || 0) / 2);

  const scamTypeDescriptions = {
    bank_fraud:        "Banking/financial institution impersonation scam",
    upi_fraud:         "UPI payment fraud with reverse payment trick",
    phishing_link:     "Phishing link-based credential/data theft attempt",
    kyc_fraud:         "KYC verification fraud targeting account details",
    job_scam:          "Fake job offer scam with upfront fee demand",
    lottery_scam:      "Lottery/prize claim scam with processing fee demand",
    electricity_bill:  "Electricity disconnection threat scam",
    govt_scheme:       "Fake government scheme/benefit scam",
    crypto_investment: "Cryptocurrency investment fraud",
    investment_fraud:  "Investment/stock market fraud scheme",
    customs_parcel:    "Fake customs/parcel clearance fee scam",
    tech_support:      "Tech support impersonation and remote access scam",
    loan_approval:     "Fake loan approval with upfront fee demand",
    income_tax:        "Income Tax Department impersonation scam",
    refund_scam:       "Fake refund scam targeting bank/UPI details",
    other:             "Unclassified scam pattern with financial fraud intent"
  };

  if (scamType && scamType !== "none") {
    notes.push(scamTypeDescriptions[scamType] || "Scam detected with financial fraud intent");
  }

  if (lookup.confidence >= 0.9) {
    notes.push("Detected with very high confidence");
  } else if (lookup.confidence >= 0.75) {
    notes.push("Detected with high confidence");
  } else if (lookup.confidence) {
    notes.push(`Detected with moderate confidence (${Math.round(lookup.confidence * 100)}%)`);
  }

  // Tactics observed
  const tactics = [];
  if (intel.phoneNumbers?.length > 0)  tactics.push("provided contact number for off-platform communication");
  if (intel.phishingLinks?.length > 0) tactics.push("shared malicious/phishing links");
  if (intel.upiIds?.length > 0 || intel.bankAccounts?.length > 0) tactics.push("requested or shared financial/payment details");
  if (intel.emailAddresses?.length > 0) tactics.push("provided email for ongoing contact");
  if (intel.caseIds?.length > 0)       tactics.push("referenced official-sounding case/reference IDs to appear legitimate");
  if (intel.policyNumbers?.length > 0) tactics.push("cited policy numbers to add credibility");
  if (intel.orderNumbers?.length > 0)  tactics.push("used order/shipment IDs as social proof");
  if (tactics.length > 0) {
    notes.push(`Scammer tactics: ${tactics.join("; ")}`);
  }

  // Red flags from suspicious keywords
  if (intel.suspiciousKeywords?.length > 0) {
    notes.push(`Red flags detected — suspicious keywords used: ${intel.suspiciousKeywords.join(", ")}`);
  }

  // Intel summary
  const totalIntel =
    (intel.phoneNumbers?.length || 0) + (intel.bankAccounts?.length || 0) +
    (intel.upiIds?.length || 0) + (intel.phishingLinks?.length || 0) +
    (intel.emailAddresses?.length || 0) + (intel.caseIds?.length || 0) +
    (intel.policyNumbers?.length || 0) + (intel.orderNumbers?.length || 0);

  notes.push(`Extracted ${totalIntel} intelligence items over ${turns} conversation turns`);

  if (lookup.reason) {
    notes.push(`Detection basis: ${lookup.reason}`);
  }

  return notes.join(". ") + ".";
}