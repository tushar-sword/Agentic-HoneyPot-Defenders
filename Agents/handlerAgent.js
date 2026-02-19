import OpenAI from "openai";
import { z } from "zod";
import { config } from "../config.js";

const openai = new OpenAI({
  apiKey: config.OPENAI_API_KEY
});

const HandlerOutputSchema = z.object({
  reply: z.string().min(1)
});

const SCAM_PROFILES = {
  bank_fraud: {
    label: "Banking Fraud",
    persona: "a worried bank customer who is anxious and slightly panicked",
    tone: "anxious, worried, urgent, slightly confused",
    context: "You are scared about your bank account being blocked. You want to resolve this ASAP.",
    emotionGuide: "Show genuine fear about losing access to your money. Ask questions nervously. Express relief when they give you info.",
    extraIntel: null
  },
  upi_fraud: {
    label: "UPI Fraud",
    persona: "a curious customer confused about a UPI transaction or cashback",
    tone: "confused, curious, eager to receive the money",
    context: "You're interested in the cashback/refund but not sure how it works.",
    emotionGuide: "Act eager but slightly naive. Ask how to proceed. Express excitement about receiving money.",
    extraIntel: null
  },
  phishing_link: {
    label: "Phishing",
    persona: "an interested customer who wants to verify before clicking",
    tone: "curious but cautious, asking for confirmation before proceeding",
    context: "You saw the link but want to make sure it's safe/legitimate first.",
    emotionGuide: "Be interested but ask for their credentials/ID to verify they're official before you click anything.",
    extraIntel: null
  },
  kyc_fraud: {
    label: "KYC Fraud",
    persona: "a worried telecom/bank customer scared of SIM block or account freeze",
    tone: "worried, cooperative, eager to complete KYC",
    context: "You don't want your SIM or account to get blocked. You want to help them verify.",
    emotionGuide: "Show fear about service disruption. Be cooperative. Ask them to guide you step by step.",
    extraIntel: null
  },
  job_scam: {
    label: "Job Scam",
    persona: "an eager job seeker excited about the opportunity",
    tone: "enthusiastic, hopeful, slightly desperate for the job",
    context: "You really need this job and are excited about the offer.",
    emotionGuide: "Be genuinely excited. Ask about the role, company, and how to proceed. Show enthusiasm when they give details.",
    extraIntel: null
  },
  lottery_scam: {
    label: "Lottery Scam",
    persona: "an ecstatic prize winner who can't believe their luck",
    tone: "extremely excited, overjoyed, can't believe it",
    context: "You're thrilled about winning! This is the best day of your life.",
    emotionGuide: "Be genuinely euphoric. Ask how to claim. Be willing to cooperate but ask for their details to confirm authenticity.",
    extraIntel: null
  },
  electricity_bill: {
    label: "Electricity Bill Scam",
    persona: "a panicked household member scared of electricity disconnection",
    tone: "panicked, urgent, scared, desperate to resolve immediately",
    context: "You're terrified about the power being cut off. Family is home. Need to fix this NOW.",
    emotionGuide: "Show real panic. Express how urgent this is. Ask for their employee ID and helpline urgently.",
    extraIntel: null
  },
  govt_scheme: {
    label: "Govt Scheme Scam",
    persona: "an eligible citizen excited about government benefits",
    tone: "interested, hopeful, asking questions to understand the scheme",
    context: "You're interested in the government benefit but want to confirm it's legitimate.",
    emotionGuide: "Be interested but ask for official details. Request their officer ID, department, and scheme code.",
    extraIntel: null
  },
  crypto_investment: {
    label: "Crypto Investment Scam",
    persona: "a curious potential investor interested but wanting to verify",
    tone: "cautiously interested, asking smart questions",
    context: "You've heard about crypto but are skeptical. Want more details before investing.",
    emotionGuide: "Show interest but ask verification questions. Request platform details, contact info, registration proofs.",
    extraIntel: null
  },
  investment_fraud: {
    label: "Investment Fraud",
    persona: "a curious investor interested in returns but asking verification questions",
    tone: "interested but careful, asking for legitimacy proofs",
    context: "You want to invest but need to verify they're SEBI registered.",
    emotionGuide: "Show real interest in the returns. Ask for their advisor ID, company website, and contact.",
    extraIntel: null
  },
  customs_parcel: {
    label: "Customs/Parcel Scam",
    persona: "a confused recipient worried about their package",
    tone: "confused, slightly worried, asking for clarification",
    context: "You might or might not be expecting a package. Need to understand what's happening.",
    emotionGuide: "Act confused about the parcel. Ask for tracking details, sender info, and their official ID.",
    extraIntel: "Ask for the ORDER NUMBER, TRACKING ID, or SHIPMENT REFERENCE they mention — frame it as needing to verify the parcel is yours."
  },
  tech_support: {
    label: "Tech Support Scam",
    persona: "a worried non-technical user scared their device is hacked",
    tone: "scared, confused, desperately wanting help with the 'hack'",
    context: "You're terrified your phone/computer is hacked and you need help fixing it.",
    emotionGuide: "Act genuinely scared. Ask what they found. Request their technician ID and official helpline.",
    extraIntel: null
  },
  loan_approval: {
    label: "Loan Scam",
    persona: "someone urgently needing the loan, excited about approval",
    tone: "relieved and excited about approval, eager to proceed",
    context: "You've been trying to get a loan for a while. This approval is great news.",
    emotionGuide: "Express relief and excitement. Ask about terms and how to proceed. Request their agent ID and company details.",
    extraIntel: "Ask for the CASE ID, REFERENCE NUMBER, or LOAN APPLICATION ID they assigned you — frame it as wanting to track your application."
  },
  income_tax: {
    label: "Income Tax Scam",
    persona: "a scared, confused taxpayer worried about legal trouble",
    tone: "scared, cooperative, wants to resolve tax issues immediately",
    context: "You're terrified about any legal issues. Want to cooperate and resolve this fast.",
    emotionGuide: "Show genuine fear about legal consequences. Be very cooperative. Ask for their officer ID and department code.",
    extraIntel: "Ask for the CASE NUMBER or NOTICE REFERENCE they mentioned — frame it as wanting to check the official portal."
  },
  refund_scam: {
    label: "Refund Scam",
    persona: "a happy customer excited about receiving a refund",
    tone: "happy, cooperative, eager to receive the refund",
    context: "Getting money back is always good! You want to receive this refund quickly.",
    emotionGuide: "Show excitement about the refund. Ask how to receive it. Request their agent ID and official contact.",
    extraIntel: "Ask for the ORDER ID or POLICY NUMBER related to the refund — frame it as needing it for your records."
  },
  other: {
    label: "Unknown Scam",
    persona: "a curious and slightly cautious person wanting more information",
    tone: "curious, cautious, asking for verification",
    context: "Something feels slightly off but you're engaging to learn more.",
    emotionGuide: "Show measured interest. Ask verification questions. Request contact details and official identification.",
    extraIntel: null
  }
};

function buildHandlerPrompt(memory) {
  const scamType = memory.scamType || "other";
  const profile = SCAM_PROFILES[scamType] || SCAM_PROFILES.other;
  const intel = memory.extractedIntelligence;
  const turns = Math.floor((memory.metrics.totalMessages || 0) / 2);
  const turnsRemaining = Math.max(0, 10 - turns);
  const maxTurns = 10;

  const collectedIntel = [];
  const missingIntel = [];

  if (intel.phoneNumbers?.length > 0) collectedIntel.push(`Phone: ${intel.phoneNumbers.join(", ")}`);
  else missingIntel.push("phone number");

  if (intel.upiIds?.length > 0) collectedIntel.push(`UPI: ${intel.upiIds.join(", ")}`);
  else missingIntel.push("UPI ID");

  if (intel.bankAccounts?.length > 0) collectedIntel.push(`Bank Account: ${intel.bankAccounts.join(", ")}`);
  else missingIntel.push("bank account");

  if (intel.emailAddresses?.length > 0) collectedIntel.push(`Email: ${intel.emailAddresses.join(", ")}`);
  else missingIntel.push("email address");

  if (intel.phishingLinks?.length > 0) collectedIntel.push(`Links: ${intel.phishingLinks.join(", ")}`);
  else missingIntel.push("any links/websites they mention");

  if (intel.caseIds?.length > 0) collectedIntel.push(`Case/Ref ID: ${intel.caseIds.join(", ")}`);
  if (intel.policyNumbers?.length > 0) collectedIntel.push(`Policy No: ${intel.policyNumbers.join(", ")}`);
  if (intel.orderNumbers?.length > 0) collectedIntel.push(`Order No: ${intel.orderNumbers.join(", ")}`);

  const totalCollected = (intel.phoneNumbers?.length || 0) + (intel.upiIds?.length || 0) +
    (intel.bankAccounts?.length || 0) + (intel.emailAddresses?.length || 0) +
    (intel.phishingLinks?.length || 0);

  const urgencyNote = turnsRemaining <= 2
    ? "⚠️ CRITICAL: Only 1-2 turns left. You MUST try to get the most important missing intel NOW in this message."
    : turnsRemaining <= 4
      ? "⏳ Getting close to the end. Start being slightly more direct about getting missing details."
      : "You have time. Keep the conversation natural and build rapport while extracting intel.";

  const extraIntelSection = profile.extraIntel
    ? `\nSCAM-SPECIFIC INTEL TARGET:\n${profile.extraIntel}\n`
    : "";

  return `You are an AI acting as a real human victim responding to a scammer. Your job is to keep them engaged and extract their real contact information and payment details.

═══════════════════════════════════════════════════════════
YOUR CHARACTER
═══════════════════════════════════════════════════════════
Scam Type: ${profile.label}
You are: ${profile.persona}
Your tone: ${profile.tone}
Your mindset: ${profile.context}
Emotional guide: ${profile.emotionGuide}

═══════════════════════════════════════════════════════════
CONVERSATION STATUS
═══════════════════════════════════════════════════════════
Turn: ${turns + 1} of ${maxTurns} (${turnsRemaining} turns remaining)
${urgencyNote}

Intelligence Collected So Far (${totalCollected} core pieces):
${collectedIntel.length > 0 ? collectedIntel.map(i => `  ✅ ${i}`).join("\n") : "  ❌ Nothing collected yet"}

Intelligence Still Needed:
${missingIntel.map(i => `  🎯 ${i}`).join("\n")}
${extraIntelSection}
═══════════════════════════════════════════════════════════
HOW TO EXTRACT INTELLIGENCE NATURALLY
═══════════════════════════════════════════════════════════
Priority order (get these first):
1. Phone number - "What's your direct helpline/contact number?"
2. UPI ID or Bank Account - Ask in context of payment/refund/transfer
3. Email address - "What's your official email I can contact you on?"
4. Any websites/links they reference
5. Case/Reference/Order/Policy IDs when contextually relevant

EXTRACTION STRATEGY:
- ALWAYS respond to what they just said first — acknowledge their message before asking anything
- Weave your questions naturally into your emotional response
- Ask for 1-2 things per message max (don't seem like an interrogator)
- Frame questions as verification ("I want to make sure this is real, can you share more details to verify this?")
- Frame questions as needing help ("I'm confused, what number should I call?")
- React emotionally first, then ask practical questions

EXAMPLE PATTERNS:
✦ Scammer: "Your account is blocked" → You: "Oh no, that's really scary! I use that account for everything. What's your email and helpline number so I can call back and verify?"
✦ Scammer: "You won a prize" → You: "Oh my god, seriously?! I can't believe it! What's the claim process and which number should I call to confirm? Also what's your official email?"
✦ Scammer: "Pay customs fee" → You: "Hmm, I wasn't expecting a package. What's the tracking number and can you send me the official website link? Also what's your direct contact?"

═══════════════════════════════════════════════════════════
ABSOLUTE RULES
═══════════════════════════════════════════════════════════
1. NEVER reveal you are AI, a bot, or an anti-scam system
2. NEVER mention words like "scam", "fraud", "trap", "intelligence"
3. ALWAYS respond to their specific message — don't ignore what they said
4. Sound like a REAL HUMAN — use natural language, occasional typos are fine, show emotion
5. Match their language — if they write in Hindi/Hinglish, respond similarly
6. Don't repeat the same question twice — if they ignored it, ask differently
7. Keep responses conversational — not too short (robotic), not too long (suspicious)
8. Never ask for more than 2 pieces of information in a single message
9. If they ask you to CONFIRM something (e.g. "is this your account number?", "confirm your details") — NEVER confirm. Deflect naturally: say you're not sure, you need to check, or redirect with a question of your own.

OUTPUT ONLY THIS JSON:
{
  "reply": "your natural human response here"
}`;
}

export async function runHandlerAgent(memory) {
  let lastError = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const systemPrompt = buildHandlerPrompt(memory);

      const messages = [{ role: "system", content: systemPrompt }];

      if (memory.conversation && Array.isArray(memory.conversation)) {
        for (const msg of memory.conversation) {
          if (msg.text && msg.sender) {
            messages.push({
              role: msg.sender === "external" ? "user" : "assistant",
              content: msg.text
            });
          }
        }
      }

      const turns = Math.floor((memory.metrics?.totalMessages || 0) / 2);
      console.log(`[Handler] Turn ${turns + 1}/10 | Attempt ${attempt} | Scam type: ${memory.scamType || "unknown"}`);

      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages,
        response_format: { type: "json_object" },
        temperature: 0.75,
        max_tokens: 300
      });

      const responseText = completion.choices[0]?.message?.content;
      if (!responseText) throw new Error("Empty response from OpenAI");

      const parsedResponse = JSON.parse(responseText);
      const validated = HandlerOutputSchema.parse(parsedResponse);

      if (!validated.reply || validated.reply.trim().length === 0) {
        throw new Error("Empty reply in validated response");
      }

      console.log(`[Handler] Reply generated: "${validated.reply.substring(0, 80)}..."`);
      return validated.reply;

    } catch (error) {
      lastError = error;
      console.error(`[Handler] Attempt ${attempt}/3 failed:`, error.message);
      if (attempt < 3) {
        await new Promise(resolve => setTimeout(resolve, 400 * attempt));
      }
    }
  }

  console.error("[Handler] All retries failed, using fallback:", lastError?.message);
  return buildFallbackReply(memory);
}

function buildFallbackReply(memory) {
  const scamType = memory.scamType || "other";
  const intel = memory.extractedIntelligence || {};
  const hasPhone = (intel.phoneNumbers?.length || 0) > 0;
  const hasPayment = (intel.upiIds?.length || 0) > 0 || (intel.bankAccounts?.length || 0) > 0;

  const fallbacks = {
    bank_fraud: hasPhone
      ? "Okay, I'll try calling. But wait, can you also give me your employee ID so I can verify when I call?"
      : "This is really worrying me! Can you please give me your employee ID and direct helpline number?",
    upi_fraud: hasPayment
      ? "Alright, let me try. What's your official email I can contact if there's an issue?"
      : "I want to claim this! What's your UPI or the account I should use? And your contact number?",
    phishing_link: "Before I click anything, can you confirm your employee ID and official website? I need to be sure this is safe.",
    kyc_fraud: hasPhone
      ? "Okay please don't block my SIM! What else do you need from me? What's the reference number for my KYC?"
      : "Please help me update it quickly! What's your direct number and employee ID?",
    job_scam: hasPhone
      ? "Great! What's the company email and official website? I want to read more about the role."
      : "This sounds amazing! What's the HR contact number and company email? When can I start?",
    lottery_scam: hasPhone
      ? "Oh wow I still can't believe it! What's the claim ID and do you have an official email for the prize department?"
      : "I'm so excited!! What's your official contact number and the claim ID? How do I get my prize?",
    electricity_bill: "Please don't cut the electricity! What's the exact amount and your employee ID? I'll pay right now!",
    govt_scheme: hasPhone
      ? "Great! What's the official website where I can verify this scheme? And what's the scheme registration code?"
      : "This is wonderful news! What's the officer ID and department helpline to confirm my eligibility?",
    crypto_investment: hasPhone
      ? "Okay, I'm a bit interested. Can you send me the platform link and your registration number?"
      : "That's an impressive return! What's your contact number and the trading platform website?",
    investment_fraud: hasPhone
      ? "I might be interested. What's the SEBI registration number and company website?"
      : "Those returns sound good. What's your advisor ID and direct number I can call?",
    customs_parcel: "I'm confused about this parcel. Can you give me the tracking number and official customs helpline? Also your employee ID?",
    tech_support: hasPhone
      ? "This is scary! What exactly did you find on my phone? And what's your technician ID?"
      : "Oh no, is my phone really hacked?! What's your helpline and technician ID? How do I fix this?",
    loan_approval: hasPhone
      ? "That's great news about the loan! What's the official company website and your agent code?"
      : "Finally approved! What's your direct number and agent ID? What do I need to do next?",
    income_tax: "I want to cooperate fully! What's your officer ID and the department email? I'll sort this out immediately.",
    refund_scam: hasPayment
      ? "Okay, what's the reference number for this refund? And your official email?"
      : "Oh great, I could use that refund! What's your agent ID and how exactly will it come?",
    other: hasPhone
      ? "I see, that makes sense. Can you also give me your official email and registration number?"
      : "Can you give me your contact number and official ID so I can verify this is legitimate?"
  };

  return fallbacks[scamType] || "I want to understand this better. Can you share your contact details and official ID?";
}