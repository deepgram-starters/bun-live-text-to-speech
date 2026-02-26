/**
 * Bun Live Text-to-Speech Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live TTS API using Bun.serve().
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   WS   /api/live-text-to-speech    - WebSocket proxy to Deepgram TTS (auth required)
 */

import { readFileSync } from "fs";
import { join } from "path";
import { sign, verify } from "jsonwebtoken";
import TOML from "@iarna/toml";

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Default text-to-speech model to use when none is specified
 * Options: "aura-asteria-en", "aura-2-thalia-en", "aura-2-andromeda-en", etc.
 * See: https://developers.deepgram.com/docs/text-to-speech-models
 */
const DEFAULT_MODEL = "aura-asteria-en";

/**
 * Deepgram Live TTS WebSocket URL
 */
const DEEPGRAM_TTS_URL = "wss://api.deepgram.com/v1/speak";

/**
 * Server configuration - These can be overridden via environment variables
 */
interface ServerConfig {
  deepgramApiKey: string;
  port: number;
  host: string;
}

// Validate required environment variables
if (!process.env.DEEPGRAM_API_KEY) {
  console.error("\nERROR: DEEPGRAM_API_KEY environment variable is required");
  console.error("Please copy sample.env to .env and add your API key\n");
  process.exit(1);
}

const CONFIG: ServerConfig = {
  deepgramApiKey: process.env.DEEPGRAM_API_KEY,
  port: parseInt(process.env.PORT || "8081"),
  host: process.env.HOST || "0.0.0.0",
};

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");

const JWT_EXPIRY = "1h";

/**
 * Validates JWT from WebSocket subprotocol: access_token.<jwt>
 * Returns the token string if valid, null if invalid.
 */
function validateWsToken(protocols: string | undefined): string | null {
  if (!protocols) return null;
  const list = protocols.split(",").map((s) => s.trim());
  const tokenProto = list.find((p) => p.startsWith("access_token."));
  if (!tokenProto) return null;
  const token = tokenProto.slice("access_token.".length);
  try {
    verify(token, SESSION_SECRET);
    return tokenProto;
  } catch {
    return null;
  }
}

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

/**
 * Get CORS headers for API responses
 */
function getCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

// ============================================================================
// TYPES - TypeScript interfaces for WebSocket communication
// ============================================================================

interface ErrorMessage {
  type: "Error";
  description: string;
  code: string;
}

/**
 * Per-connection data attached to each client WebSocket
 */
interface WsData {
  url: string;
  protocol: string;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Build Deepgram WebSocket URL with query parameters from the client request
 */
function buildDeepgramUrl(clientUrl: URL): string {
  const model = clientUrl.searchParams.get("model") || DEFAULT_MODEL;
  const encoding = clientUrl.searchParams.get("encoding") || "linear16";
  const sampleRate = clientUrl.searchParams.get("sample_rate") || "24000";
  const container = clientUrl.searchParams.get("container") || "none";

  const deepgramUrl = new URL(DEEPGRAM_TTS_URL);
  deepgramUrl.searchParams.set("model", model);
  deepgramUrl.searchParams.set("encoding", encoding);
  deepgramUrl.searchParams.set("sample_rate", sampleRate);
  deepgramUrl.searchParams.set("container", container);

  console.log(
    `Connecting to Deepgram TTS: model=${model}, encoding=${encoding}, sample_rate=${sampleRate}`
  );

  return deepgramUrl.toString();
}

/**
 * Send error message to client WebSocket
 */
function sendError(
  ws: { send: (data: string | Buffer) => void; readyState: number },
  message: string,
  code: string = "UNKNOWN_ERROR"
) {
  if (ws.readyState === WebSocket.OPEN) {
    const errorMsg: ErrorMessage = {
      type: "Error",
      description: message,
      code,
    };
    ws.send(JSON.stringify(errorMsg));
  }
}

// ============================================================================
// API ROUTE HANDLERS
// ============================================================================

/**
 * GET /api/session - Issues a signed JWT for session authentication.
 */
function handleSession(): Response {
  const token = sign(
    { iat: Math.floor(Date.now() / 1000) },
    SESSION_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
  return Response.json({ token }, { headers: getCorsHeaders() });
}

/**
 * GET /api/metadata - Returns metadata from deepgram.toml
 */
function handleMetadata(): Response {
  try {
    const tomlPath = join(import.meta.dir, "deepgram.toml");
    const tomlContent = readFileSync(tomlPath, "utf-8");
    const config = TOML.parse(tomlContent);

    if (!config.meta) {
      return Response.json(
        {
          error: "INTERNAL_SERVER_ERROR",
          message: "Missing [meta] section in deepgram.toml",
        },
        { status: 500, headers: getCorsHeaders() }
      );
    }

    return Response.json(config.meta, { headers: getCorsHeaders() });
  } catch (error) {
    console.error("Error reading metadata:", error);
    return Response.json(
      {
        error: "INTERNAL_SERVER_ERROR",
        message: "Failed to read metadata from deepgram.toml",
      },
      { status: 500, headers: getCorsHeaders() }
    );
  }
}

/**
 * Handle CORS preflight OPTIONS requests
 */
function handlePreflight(): Response {
  return new Response(null, { status: 204, headers: getCorsHeaders() });
}

/**
 * GET /health
 * Simple health check endpoint.
 * @returns JSON response with { status: "ok" }
 */
function handleHealth(): Response {
  return Response.json({ status: "ok" }, { headers: getCorsHeaders() });
}

// ============================================================================
// TRACK ACTIVE CONNECTIONS
// ============================================================================

const activeConnections = new Set<WebSocket>();

// ============================================================================
// BUN SERVER - HTTP + WebSocket
// ============================================================================

const server = Bun.serve<WsData>({
  port: CONFIG.port,
  hostname: CONFIG.host,

  /**
   * HTTP request handler - routes API requests and upgrades WebSocket connections
   */
  fetch(req, server) {
    const url = new URL(req.url);

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      return handlePreflight();
    }

    // Session endpoint (unprotected)
    if (req.method === "GET" && url.pathname === "/api/session") {
      return handleSession();
    }

    // Metadata endpoint (unprotected)
    if (req.method === "GET" && url.pathname === "/api/metadata") {
      return handleMetadata();
    }

    // Health check endpoint (unprotected)
    if (req.method === "GET" && url.pathname === "/health") {
      return handleHealth();
    }

    // WebSocket endpoint: /api/live-text-to-speech (auth via subprotocol)
    if (url.pathname === "/api/live-text-to-speech") {
      const upgrade = req.headers.get("upgrade") || "";
      if (upgrade.toLowerCase() !== "websocket") {
        return new Response("Expected WebSocket", {
          status: 426,
          headers: getCorsHeaders(),
        });
      }

      // Validate JWT from subprotocol
      const protocols = req.headers.get("sec-websocket-protocol") || undefined;
      const validProto = validateWsToken(protocols);

      if (!validProto) {
        console.log("WebSocket auth failed: invalid or missing token");
        return new Response("Unauthorized", {
          status: 401,
          headers: getCorsHeaders(),
        });
      }

      // Upgrade the connection — Bun handles the WebSocket handshake
      const success = server.upgrade(req, {
        data: {
          url: req.url,
          protocol: validProto,
        },
        headers: {
          "Sec-WebSocket-Protocol": validProto,
        },
      });

      if (success) {
        // Bun returns undefined on successful upgrade; we must return nothing
        return undefined as unknown as Response;
      }

      return new Response("WebSocket upgrade failed", {
        status: 500,
        headers: getCorsHeaders(),
      });
    }

    // 404 for all other routes
    return Response.json(
      { error: "Not Found", message: "Endpoint not found" },
      { status: 404, headers: getCorsHeaders() }
    );
  },

  /**
   * WebSocket handlers — Bun's native WebSocket API
   */
  websocket: {
    /**
     * Called when a client WebSocket connection is opened.
     * Establishes the upstream Deepgram WebSocket proxy.
     */
    open(clientWs) {
      console.log("Client connected to /api/live-text-to-speech");
      activeConnections.add(clientWs as unknown as WebSocket);

      const clientUrl = new URL(clientWs.data.url);
      const deepgramUrl = buildDeepgramUrl(clientUrl);

      // Connect to Deepgram TTS API with authorization header
      // Bun's WebSocket supports custom headers (non-standard extension)
      const deepgramWs = new WebSocket(deepgramUrl, {
        headers: {
          Authorization: `Token ${CONFIG.deepgramApiKey}`,
        },
      } as any);
      deepgramWs.binaryType = "arraybuffer";

      // Store reference for message forwarding
      (clientWs as any)._deepgramWs = deepgramWs;

      // Forward Deepgram messages to client
      deepgramWs.onopen = () => {
        console.log("Connected to Deepgram TTS API");
      };

      deepgramWs.onmessage = (event) => {
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(event.data);
        }
      };

      deepgramWs.onerror = (error) => {
        console.error("Deepgram WebSocket error:", error);
        sendError(
          clientWs as any,
          (error as any).message || "Deepgram connection error",
          "PROVIDER_ERROR"
        );
      };

      deepgramWs.onclose = (event) => {
        console.log(
          `Deepgram connection closed: ${event.code} ${event.reason}`
        );
        if (clientWs.readyState === WebSocket.OPEN) {
          const reservedCodes = [1004, 1005, 1006, 1015];
          const closeCode =
            typeof event.code === "number" &&
            event.code >= 1000 &&
            event.code <= 4999 &&
            !reservedCodes.includes(event.code)
              ? event.code
              : 1000;
          clientWs.close(closeCode, event.reason || undefined);
        }
      };
    },

    /**
     * Called when a message is received from the client.
     * Forwards to Deepgram (text commands for TTS).
     */
    message(clientWs, message) {
      const deepgramWs = (clientWs as any)._deepgramWs as WebSocket | undefined;
      if (deepgramWs && deepgramWs.readyState === WebSocket.OPEN) {
        deepgramWs.send(message);
      }
    },

    /**
     * Called when the client WebSocket connection is closed.
     * Cleans up the upstream Deepgram connection.
     */
    close(clientWs, code, reason) {
      console.log(`Client disconnected: ${code} ${reason}`);
      const deepgramWs = (clientWs as any)._deepgramWs as WebSocket | undefined;
      if (deepgramWs && deepgramWs.readyState === WebSocket.OPEN) {
        deepgramWs.close();
      }
      activeConnections.delete(clientWs as unknown as WebSocket);
    },
  },
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

/**
 * Graceful shutdown handler
 */
function gracefulShutdown(signal: string) {
  console.log(`\n${signal} signal received: starting graceful shutdown...`);

  // Close all active WebSocket connections
  console.log(
    `Closing ${activeConnections.size} active WebSocket connection(s)...`
  );
  activeConnections.forEach((ws) => {
    try {
      ws.close(1001, "Server shutting down");
    } catch (error) {
      console.error("Error closing WebSocket:", error);
    }
  });

  // Stop the server
  server.stop();
  console.log("Server stopped");
  console.log("Shutdown complete");
  process.exit(0);
}

// Handle shutdown signals
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught errors
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  gracefulShutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("UNHANDLED_REJECTION");
});

// ============================================================================
// SERVER START
// ============================================================================

console.log("\n" + "=".repeat(70));
console.log(
  `Backend API Server running at http://localhost:${server.port}`
);
console.log("");
console.log(`GET  /api/session`);
console.log(`WS   /api/live-text-to-speech (auth required)`);
console.log(`GET  /api/metadata`);
console.log(`GET  /health`);
console.log("=".repeat(70) + "\n");
