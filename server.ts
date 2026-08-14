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
import { DeepgramClient } from "@deepgram/sdk";

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

// A single SDK client is reused across connections; it manages the Deepgram
// WebSocket, auth, and message (de)serialization. DEEPGRAM_BASE_URL (e.g. a
// staging host) overrides the default production endpoint.
const baseUrl = process.env.DEEPGRAM_BASE_URL;
const deepgram = new DeepgramClient({
  apiKey: CONFIG.deepgramApiKey,
  ...(baseUrl
    ? {
        environment: {
          base: baseUrl
            .replace(/^wss:\/\//, "https://")
            .replace(/^ws:\/\//, "http://"),
          production: baseUrl,
          agent: baseUrl,
          agentRest: baseUrl
            .replace(/^wss:\/\//, "https://")
            .replace(/^ws:\/\//, "http://"),
        },
      }
    : {}),
});

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
  // The Deepgram TTS streaming connection (SDK speak.v1 socket).
  dgConn: any;
  // Whether the Deepgram connection has opened and is ready to receive input.
  dgReady: boolean;
  // Browser control messages that arrived before the Deepgram socket opened.
  pending: any[];
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Build Deepgram speak.v1 connection options from the client request.
 * `container` is not a typed SDK option, so it is passed through queryParams.
 */
function buildTtsOptions(clientUrl: URL) {
  const model = clientUrl.searchParams.get("model") || DEFAULT_MODEL;
  const encoding = clientUrl.searchParams.get("encoding") || "linear16";
  const sample_rate = clientUrl.searchParams.get("sample_rate") || "24000";
  const container = clientUrl.searchParams.get("container") || "none";

  console.log(
    `Connecting to Deepgram TTS: model=${model}, encoding=${encoding}, sample_rate=${sample_rate}`
  );

  return {
    model,
    encoding,
    sample_rate,
    queryParams: { container },
  };
}

/**
 * Route a browser control message to the matching Deepgram speak.v1 method.
 * The browser protocol is unchanged: Speak / Flush / Clear / Close.
 */
function dispatchTtsControl(dgConn: any, msg: any): void {
  try {
    switch (msg?.type) {
      case "Speak":
        // speak.v1 uses sendText (not sendSpeak) for the Speak message.
        dgConn.sendText({ type: "Speak", text: msg.text });
        break;
      case "Flush":
        dgConn.sendFlush({ type: "Flush" });
        break;
      case "Clear":
        dgConn.sendClear({ type: "Clear" });
        break;
      case "Close":
        dgConn.sendClose({ type: "Close" });
        break;
      default:
        console.warn(
          "Ignoring unknown client control message type:",
          msg?.type
        );
    }
  } catch (error) {
    console.error("Failed to forward control message to Deepgram:", error);
  }
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
          dgConn: null,
          dgReady: false,
          pending: [],
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
    async open(clientWs) {
      console.log("Client connected to /api/live-text-to-speech");
      activeConnections.add(clientWs as unknown as WebSocket);

      const clientUrl = new URL(clientWs.data.url);
      const options = buildTtsOptions(clientUrl);

      // Create the Deepgram TTS streaming connection via the SDK (not yet
      // connected). Auth is resolved from the API key by the SDK client.
      let dgConn: any;
      try {
        dgConn = await deepgram.speak.v1.createConnection(options);
      } catch (error) {
        console.error("Failed to create Deepgram TTS connection:", error);
        sendError(
          clientWs as any,
          error instanceof Error ? error.message : "Failed to reach Deepgram",
          "PROVIDER_ERROR"
        );
        return;
      }
      clientWs.data.dgConn = dgConn;

      dgConn.on("open", () => {
        console.log("Connected to Deepgram TTS API");
      });

      // Deepgram -> browser. Binary audio frames are forwarded as-is; JSON
      // control messages (Metadata / Flushed / Warning / ...) as text. This
      // preserves the exact frames the browser previously received.
      dgConn.on("message", (data: unknown) => {
        if (clientWs.readyState !== WebSocket.OPEN) return;
        if (typeof data === "string") {
          clientWs.send(data);
        } else if (typeof Blob !== "undefined" && data instanceof Blob) {
          // Bun's ServerWebSocket.send() coerces a Blob to the string
          // "[object Blob]"; unwrap it to bytes first.
          data.arrayBuffer().then((buf) => {
            if (clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(new Uint8Array(buf));
            }
          });
        } else if (
          data instanceof ArrayBuffer ||
          data instanceof Uint8Array ||
          Buffer.isBuffer(data)
        ) {
          clientWs.send(data as any);
        } else {
          clientWs.send(JSON.stringify(data));
        }
      });

      dgConn.on("error", (error: any) => {
        console.error("Deepgram WebSocket error:", error);
        sendError(
          clientWs as any,
          error?.message || "Deepgram connection error",
          "PROVIDER_ERROR"
        );
      });

      dgConn.on("close", () => {
        console.log("Deepgram connection closed");
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close(1000);
        }
      });

      // Open the connection, then flush anything the browser queued early.
      try {
        dgConn.connect();
        await dgConn.waitForOpen();
        clientWs.data.dgReady = true;
        for (const msg of clientWs.data.pending) {
          dispatchTtsControl(dgConn, msg);
        }
        clientWs.data.pending = [];
      } catch (error) {
        console.error("Deepgram connection did not open:", error);
        sendError(
          clientWs as any,
          "Deepgram connection failed to open",
          "PROVIDER_ERROR"
        );
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close(1011, "Deepgram connection failed to open");
        }
      }
    },

    /**
     * Called when a message is received from the client.
     * The browser sends JSON control frames (Speak / Flush / Clear / Close).
     */
    message(clientWs, message) {
      // TTS input is text-only; ignore any unexpected binary frames.
      if (typeof message !== "string") {
        return;
      }
      let msg: any;
      try {
        msg = JSON.parse(message);
      } catch {
        console.warn("Ignoring non-JSON text message from client");
        return;
      }
      if (!clientWs.data.dgReady) {
        clientWs.data.pending.push(msg);
        return;
      }
      dispatchTtsControl(clientWs.data.dgConn, msg);
    },

    /**
     * Called when the client WebSocket connection is closed.
     * Cleans up the upstream Deepgram connection.
     */
    close(clientWs, code, reason) {
      console.log(`Client disconnected: ${code} ${reason}`);
      try {
        clientWs.data.dgConn?.close();
      } catch {
        // already closed
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
