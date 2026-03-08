import express from "express";
import cors from "cors";
import { randomUUID } from "crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { logMessage } from "./logging.js";
import { packageVersion } from "./index.js";

// HTTP Basic Authentication middleware
function basicAuthMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const authUsername = process.env.AUTH_USERNAME;
  const authPassword = process.env.AUTH_PASSWORD;

  // If no auth credentials are configured, skip authentication
  if (!authUsername || !authPassword) {
    next();
    return;
  }

  // Get Authorization header
  const authHeader = req.headers.authorization;

  // Check if request is for health endpoint (skip auth for health checks)
  if (req.path === "/health") {
    next();
    return;
  }

  // Skip auth for favicon and icon requests
  if (req.path === "/favicon.ico" || req.path === "/icon") {
    next();
    return;
  }

  // Skip auth for OPTIONS requests (CORS preflight)
  if (req.method === "OPTIONS") {
    next();
    return;
  }

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.status(401).json({
      error: {
        code: -32001,
        message: "Authentication required",
      },
    });
    return;
  }

  // Decode base64 credentials
  const base64Credentials = authHeader.substring(6);
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii",
  );
  const [username, password] = credentials.split(":");

  // Validate credentials
  if (username !== authUsername || password !== authPassword) {
    res.status(401).json({
      error: {
        code: -32001,
        message: "Invalid credentials",
      },
    });
    return;
  }

  next();
}

export async function createHttpServer(
  server: Server,
): Promise<express.Application> {
  const app = express();
  app.use(express.json());

  // Add CORS support for web clients (MUST be before auth for OPTIONS preflight)
  app.use(
    cors({
      origin: "*", // Configure appropriately for production
      exposedHeaders: ["Mcp-Session-Id", "Mcp-Protocol-Version"],
      allowedHeaders: [
        "Content-Type",
        "mcp-session-id",
        "mcp-protocol-version",
        "Authorization",
      ],
    }),
  );

  // Add HTTP Basic Authentication middleware
  app.use(basicAuthMiddleware);

  // Map to store transports by session ID
  const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  // Handle POST requests for client-to-server communication
  app.post("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      // Reuse existing transport
      transport = transports[sessionId];
      logMessage(server, "debug", `Reusing session: ${sessionId}`);
    } else if (!sessionId && isInitializeRequest(req.body)) {
      // New initialization request
      logMessage(server, "info", "Creating new HTTP session");
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sessionId) => {
          transports[sessionId] = transport;
          logMessage(server, "debug", `Session initialized: ${sessionId}`);
        },
        // DNS rebinding protection disabled by default for backwards compatibility
        // For production, consider enabling:
        // enableDnsRebindingProtection: true,
        // allowedHosts: ['127.0.0.1', 'localhost'],
      });

      // Clean up transport when closed
      transport.onclose = () => {
        if (transport.sessionId) {
          logMessage(server, "debug", `Session closed: ${transport.sessionId}`);
          delete transports[transport.sessionId];
        }
      };

      // Connect the existing server to the new transport
      await server.connect(transport);
    } else {
      // Invalid request
      console.warn(`⚠️  POST request rejected - invalid request:`, {
        clientIP: req.ip || req.connection.remoteAddress,
        sessionId: sessionId || "undefined",
        hasInitializeRequest: isInitializeRequest(req.body),
        userAgent: req.headers["user-agent"],
        contentType: req.headers["content-type"],
        accept: req.headers["accept"],
      });
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: No valid session ID provided",
        },
        id: null,
      });
      return;
    }

    // Handle the request
    try {
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      // Log header-related rejections for debugging
      if (error instanceof Error && error.message.includes("accept")) {
        console.warn(`⚠️  Connection rejected due to missing headers:`, {
          clientIP: req.ip || req.connection.remoteAddress,
          userAgent: req.headers["user-agent"],
          contentType: req.headers["content-type"],
          accept: req.headers["accept"],
          error: error.message,
        });
      }
      throw error;
    }
  });

  // Handle GET requests for server-to-client notifications via SSE
  app.get("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      console.warn(
        `⚠️  GET request rejected - missing or invalid session ID:`,
        {
          clientIP: req.ip || req.connection.remoteAddress,
          sessionId: sessionId || "undefined",
          userAgent: req.headers["user-agent"],
        },
      );
      res.status(400).send("Invalid or missing session ID");
      return;
    }

    const transport = transports[sessionId];
    try {
      await transport.handleRequest(req, res);
    } catch (error) {
      console.warn(`⚠️  GET request failed:`, {
        clientIP: req.ip || req.connection.remoteAddress,
        sessionId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  // Handle DELETE requests for session termination
  app.delete("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      console.warn(
        `⚠️  DELETE request rejected - missing or invalid session ID:`,
        {
          clientIP: req.ip || req.connection.remoteAddress,
          sessionId: sessionId || "undefined",
          userAgent: req.headers["user-agent"],
        },
      );
      res.status(400).send("Invalid or missing session ID");
      return;
    }

    const transport = transports[sessionId];
    try {
      await transport.handleRequest(req, res);
    } catch (error) {
      console.warn(`⚠️  DELETE request failed:`, {
        clientIP: req.ip || req.connection.remoteAddress,
        sessionId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  // Health check endpoint
  app.get("/health", (_req, res) => {
    res.json({
      status: "healthy",
      server: "ihor-sokoliuk/mcp-searxng",
      version: packageVersion,
      transport: "http",
    });
  });

  // Favicon endpoint to prevent browser requests to google.com
  app.get("/favicon.ico", (_req, res) => {
    // Return a simple transparent 1x1 PNG
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=31536000");
    // 1x1 transparent PNG in base64
    const favicon = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6cgAAAABJRU5ErkJggg==",
      "base64",
    );
    res.end(favicon);
  });

  // Also handle any icon requests
  app.get("/icon", (_req, res) => {
    res.redirect("/favicon.ico");
  });

  return app;
}
