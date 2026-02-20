
export function shouldEnd(memory) {
  if (!memory || !memory.scamDetected) return false;

  const messageCount = memory.metrics?.totalMessages || 0;
  const turns = Math.floor(messageCount / 2);
  const intel = memory.extractedIntelligence || {};

  const totalIntelTypes =
    (intel.phoneNumbers?.length > 0 ? 1 : 0) +
    (intel.upiIds?.length > 0 ? 1 : 0) +
    (intel.bankAccounts?.length > 0 ? 1 : 0) +
    (intel.phishingLinks?.length > 0 ? 1 : 0) +
    (intel.emailAddresses?.length > 0 ? 1 : 0) +
    (intel.caseIds?.length > 0 ? 1 : 0) +
    (intel.policyNumbers?.length > 0 ? 1 : 0) +
    (intel.orderNumbers?.length > 0 ? 1 : 0);

  // ONLY condition: max 10 turns reached
  if (turns >= 10) {
    console.log(`[EXIT] Max turns reached (${turns} turns, ${totalIntelTypes} intel types collected)`);
    return true;
  }

  return false;
}
