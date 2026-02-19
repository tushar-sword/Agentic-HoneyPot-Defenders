/**
 * memoryStore.js
 * In-memory session store for active honeypot conversations.
 */

const sessions = new Map();

export function getMemory(sessionId) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, createNewMemory(sessionId));
    console.log(`[MemoryStore] New session created: ${sessionId}`);
  }
  return sessions.get(sessionId);
}

export function deleteMemory(sessionId) {
  const existed = sessions.has(sessionId);
  sessions.delete(sessionId);
  if (existed) {
    console.log(`[MemoryStore] Session deleted: ${sessionId}`);
  }
  return existed;
}

export function getActiveSessions() {
  return sessions.size;
}

function createNewMemory(sessionId) {
  return {
    sessionId,
    metadata: null,
    conversation: [],

    // Scam detection state
    scamDetected: false,
    handlerActivated: false,
    finalCallbackSent: false,
    sessionClosed: false,

    // Lookup agent result
    lookup: null,
    scamType: null,

    // Intelligence collected from scammer
    extractedIntelligence: {
      phoneNumbers: [],
      bankAccounts: [],
      upiIds: [],
      phishingLinks: [],
      emailAddresses: [],
      caseIds: [],
      policyNumbers: [],
      orderNumbers: [],
      suspiciousKeywords: []
    },

    // Session metrics
    metrics: {
      totalMessages: 0,
      confidenceLevel: null,      // Set when scam is detected by lookup agent
      engagementStartTime: null,  // Set when scam is first detected
      lastMessageTime: null
    }
  };
}