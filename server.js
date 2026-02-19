import express from "express";
import dotenv from "dotenv";

import { getMemory } from "./memoryStore.js";
import { runLookupAgent } from "./Agents/lookupAgent.js";
import { runHandlerAgent } from "./Agents/handlerAgent.js";
import { extractIntelligence } from "./intelligence.js";
import { shouldEnd } from "./stopConditions.js";
import { sendFinalCallback } from "./callback.js";

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;


//validate api key
function validateApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Missing x-api-key header"
    });
  }

  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Invalid API key"
    });
  }

  next();
}

//req validation

function validateHoneypotRequest(body) {
  const errors = [];

  if (!body.sessionId || typeof body.sessionId !== "string" || !body.sessionId.trim()) {
    errors.push("sessionId is required and must be a non-empty string");
  }

  if (!body.message || typeof body.message !== "object") {
    errors.push("message object is required");
  } else {
    if (!body.message.text || typeof body.message.text !== "string" || !body.message.text.trim()) {
      errors.push("message.text is required and must be a non-empty string");
    }
  }

  return errors;
}

//main endpoint

app.post("/honeypot", validateApiKey, async (req, res) => {
  const requestStart = Date.now();

  try {
    const { sessionId, message, metadata } = req.body;

    // Validate request body
    const validationErrors = validateHoneypotRequest(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        error: "Invalid request body",
        details: validationErrors
      });
    }

    const cleanSessionId = sessionId.trim();
    const memory = getMemory(cleanSessionId);

    console.log(`\n[Session ${cleanSessionId}] Incoming message from: ${message.sender || "unknown"}`);

    // Store metadata on first message
    if (metadata && typeof metadata === "object" && !memory.metadata) {
      memory.metadata = metadata;
    }

    // Normalize sender — external is anyone who isn't our agent ("user" is our agent)
    const sender = message.sender === "user" ? "user" : "external";

    // Append incoming message to conversation
    memory.conversation.push({
      sender,
      text: message.text.trim(),
      timestamp: message.timestamp || new Date().toISOString()
    });

    // Update message metrics
    memory.metrics.totalMessages++;
    memory.metrics.lastMessageTime = Date.now();

    // If callback already sent, don't process further
    if (memory.finalCallbackSent) {
      console.log(`[Session ${cleanSessionId}] Callback already sent, rejecting further messages`);
      return res.json({
        status: "success",
        scamDetected: true,
        sessionClosed: true,
        reply: null
      });
    }

    let agentReply = null;

    // ── PHASE 1: LOOKUP AGENT
    if (!memory.handlerActivated) {
      console.log(`[Session ${cleanSessionId}] Running Lookup Agent...`);

      let lookupResult;
      try {
        lookupResult = await runLookupAgent(memory);
      } catch (lookupError) {
        console.error(`[Session ${cleanSessionId}] Lookup Agent threw unexpectedly:`, lookupError.message);
        lookupResult = {
          scamDetected: false,
          handoffToHandler: false,
          intent: "uncertain",
          confidence: 0,
          reason: "Lookup agent error",
          scamType: "none"
        };
      }

      console.log(`[Session ${cleanSessionId}] Lookup result:`, {
        scamDetected: lookupResult.scamDetected,
        scamType: lookupResult.scamType,
        confidence: lookupResult.confidence
      });

      if (lookupResult.scamDetected && lookupResult.handoffToHandler) {
        memory.scamDetected = true;
        memory.handlerActivated = true;
        memory.lookup = lookupResult;

        // Start engagement timer on first scam detection
        if (!memory.metrics.engagementStartTime) {
          memory.metrics.engagementStartTime = Date.now();
        }

        console.log(`[Session ${cleanSessionId}] 🚨 Scam detected! Type: ${memory.scamType} — handing off to Handler Agent`);
      }
    }

    // ── PHASE 2: HANDLER AGENT ──
    if (memory.handlerActivated && sender === "external") {
      // Extract intelligence from the scammer's message
      try {
        extractIntelligence(message.text, memory);
      } catch (intelError) {
        console.error(`[Session ${cleanSessionId}] Intelligence extraction error:`, intelError.message);
      }

      const intel = memory.extractedIntelligence;
      const currentIntelCount =
        (intel.phoneNumbers?.length || 0) +
        (intel.upiIds?.length || 0) +
        (intel.bankAccounts?.length || 0) +
        (intel.emailAddresses?.length || 0) +
        (intel.phishingLinks?.length || 0) +
        (intel.caseIds?.length || 0) +
        (intel.policyNumbers?.length || 0) +
        (intel.orderNumbers?.length || 0);

      console.log(`[Session ${cleanSessionId}] Intel collected so far: ${currentIntelCount} pieces`);

      // Generate agent reply
      try {
        agentReply = await runHandlerAgent(memory);
      } catch (handlerError) {
        console.error(`[Session ${cleanSessionId}] Handler Agent threw unexpectedly:`, handlerError.message);
        agentReply = null;
      }

      if (agentReply) {
        memory.conversation.push({
          sender: "user", // our agent
          text: agentReply,
          timestamp: new Date().toISOString()
        });

        // Count our reply
        memory.metrics.totalMessages++;
        memory.metrics.lastMessageTime = Date.now();

        console.log(`[Session ${cleanSessionId}] Agent reply: "${agentReply.substring(0, 80)}..."`);
      }
    }

    // ── PHASE 3: CHECK STOP CONDITIONS ──
    if (memory.scamDetected && !memory.finalCallbackSent && shouldEnd(memory)) {
      const turns = Math.floor(memory.metrics.totalMessages / 2);
      console.log(`[Session ${cleanSessionId}] Stop condition met at turn ${turns} — sending callback`);

      // Fire-and-forget callback, don't block response
      sendFinalCallback(memory).catch(err => {
        console.error(`[Session ${cleanSessionId}] Callback error (non-fatal):`, err.message);
      });
    }

    const processingTimeMs = Date.now() - requestStart;
    console.log(`[Session ${cleanSessionId}] Request processed in ${processingTimeMs}ms`);

    return res.json({
      status: "success",
      scamDetected: memory.scamDetected,
      sessionClosed: memory.sessionClosed || false,
      reply: agentReply
    });

  } catch (err) {
    const processingTimeMs = Date.now() - requestStart;
    console.error(`[Honeypot] Unhandled error after ${processingTimeMs}ms:`, err);

    return res.status(500).json({
      error: "Internal Server Error",
      message: process.env.NODE_ENV === "development" ? err.message : "Something went wrong"
    });
  }
});


// Home Page
app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Agentic Honeypot | The Defenders</title>

<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: "Segoe UI", sans-serif;
  }

  body {
    min-height: 100vh;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
  }

  .glass {
    width: 90%;
    max-width: 900px;
    padding: 40px;
    border-radius: 20px;
    background: rgba(255, 255, 255, 0.08);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    text-align: center;
  }

  h1 {
    font-size: 2.8rem;
    margin-bottom: 10px;
  }

  h2 {
    font-weight: 400;
    color: #cfd9df;
    margin-bottom: 30px;
  }

  p {
    font-size: 1.1rem;
    line-height: 1.6;
    color: #e5e5e5;
    margin-bottom: 25px;
  }

  .badge {
    display: inline-block;
    margin-top: 10px;
    padding: 8px 16px;
    border-radius: 30px;
    background: rgba(255,255,255,0.15);
    font-size: 0.9rem;
  }

  .routes {
    margin-top: 30px;
    text-align: left;
  }

  .route {
    background: rgba(0,0,0,0.3);
    padding: 15px;
    border-radius: 12px;
    margin-bottom: 12px;
    font-family: monospace;
  }

  footer {
    margin-top: 30px;
    font-size: 0.9rem;
    opacity: 0.8;
  }
</style>
</head>

<body>
  <div class="glass">
    <h1>🛡️ Agentic Honeypot</h1>
    <h2>Built by <strong>The Defenders</strong></h2>

    <p>
      An <strong>AI-powered scam engagement honeypot</strong> that detects,
      traps, and extracts intelligence from malicious actors using
      autonomous agents.
    </p>

    <div class="badge">GUVI Hackathon Finals</div>

    <div class="routes">
      <div class="route">
        <strong>GET /</strong> → Project overview & status
      </div>
      <div class="route">
        <strong>POST /honeypot</strong> → Agentic Honeypot API (Requires x-api-key)
      </div>
    </div>

    <footer>
      🚀 Real-time scam detection & intelligence extraction
    </footer>
  </div>
</body>
</html>
  `);
});


//health
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: Math.round(process.uptime())
  });
});

//404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Not Found",
    message: `Route ${req.method} ${req.path} does not exist`
  });
});

//global error handler
app.use((err, req, res, next) => {
  console.error("[Global Error Handler]", err);
  res.status(500).json({
    error: "Internal Server Error",
    message: process.env.NODE_ENV === "development" ? err.message : "An unexpected error occurred"
  });
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("[UnhandledRejection] at:", promise, "reason:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("[UncaughtException]", err);
  process.exit(1);
});

//start server
app.listen(PORT, () => {
  console.log(`🛡️  Honeypot API running on port ${PORT}`);
  console.log(`📡  POST /honeypot — Main honeypot endpoint`);
  console.log(`❤️   GET  /health  — Health check`);
});