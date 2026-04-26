const path = require("path");
const crypto = require("crypto");
const express = require("express");
const http = require("http");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
app.disable("x-powered-by");

const port = Number.parseInt(process.env.PORT || "3000", 10);
const allowedOrigins = parseAllowedOrigins(process.env.ALLOWED_ORIGINS, port);
const sessionSecret = process.env.SESSION_SECRET || "change-me-in-production";
const secureCookie = process.env.SECURE_COOKIE === "true" || process.env.RENDER === "true";
const voteWindowMs = 10 * 1000;
const voteLimit = 8;
const databaseUrl = process.env.DATABASE_URL || "";
const useDatabase = Boolean(databaseUrl);
const pool = useDatabase ? createDatabasePool(databaseUrl) : null;

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true,
    methods: ["GET", "POST"],
  },
});

const poll = {
  id: "presidential-race-2027",
  question: "If the 2027 presidential election were held today, who would you support?",
  options: [
    { id: "candidate-a", label: "Candidate A", votes: 0 },
    { id: "candidate-b", label: "Candidate B", votes: 0 },
    { id: "candidate-c", label: "Candidate C", votes: 0 },
    { id: "undecided", label: "Undecided", votes: 0 },
  ],
};

const votesByVoter = new Map();
const socketToVoter = new Map();
const voteRateByVoter = new Map();
let voteWriteQueue = Promise.resolve();

function toOrigin(input) {
  if (!input || typeof input !== "string") {
    return null;
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return null;
  }

  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    return new URL(withScheme).origin;
  } catch (_error) {
    return null;
  }
}

function parseAllowedOrigins(rawOrigins, activePort) {

  if (!rawOrigins || !rawOrigins.trim()) {
    const defaults = new Set([`http://localhost:${activePort}`, `http://127.0.0.1:${activePort}`]);
    const renderExternalUrl = toOrigin(process.env.RENDER_EXTERNAL_URL);
    const renderExternalHost = toOrigin(process.env.RENDER_EXTERNAL_HOSTNAME);

    if (renderExternalUrl) {
      defaults.add(renderExternalUrl);
    }

    if (renderExternalHost) {
      defaults.add(renderExternalHost);
    }

    return defaults;
  }

  const configured = new Set(
    rawOrigins
      .split(",")
      .map((origin) => toOrigin(origin))
      .filter(Boolean),
  );
  configured.add(`http://localhost:${activePort}`);
  configured.add(`http://127.0.0.1:${activePort}`);
  return configured;
}

function createDatabasePool(connectionString) {
  const sslOverride = process.env.DATABASE_SSL;
  if (sslOverride === "true") {
    return new Pool({ connectionString, ssl: { rejectUnauthorized: false } });
  }

  if (sslOverride === "false") {
    return new Pool({ connectionString });
  }

  if (/sslmode=require/i.test(connectionString)) {
    return new Pool({ connectionString, ssl: { rejectUnauthorized: false } });
  }

  return new Pool({ connectionString });
}

function parseCookieHeader(header = "") {
  const pairs = header.split(";");
  const cookies = {};

  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex < 0) {
      continue;
    }

    const name = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();
    if (!name) {
      continue;
    }

    cookies[name] = decodeURIComponent(value);
  }

  return cookies;
}

function signVoterId(voterId) {
  return crypto.createHmac("sha256", sessionSecret).update(voterId).digest("base64url");
}

function buildSessionToken(voterId) {
  return `${voterId}.${signVoterId(voterId)}`;
}

function timingSafeEqual(a, b) {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function verifySessionToken(token = "") {
  const separatorIndex = token.lastIndexOf(".");
  if (separatorIndex < 1) {
    return null;
  }

  const voterId = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  if (!voterId || !signature || voterId.length > 128) {
    return null;
  }

  const expectedSignature = signVoterId(voterId);
  if (!timingSafeEqual(signature, expectedSignature)) {
    return null;
  }

  return voterId;
}

function getOrCreateVoterIdFromCookies(cookieHeader) {
  const cookies = parseCookieHeader(cookieHeader);
  const token = cookies.voter_session;
  const verifiedVoterId = verifySessionToken(token);

  if (verifiedVoterId) {
    return { voterId: verifiedVoterId, token, isNew: false };
  }

  const voterId = `voter_${crypto.randomUUID()}`;
  const nextToken = buildSessionToken(voterId);
  return { voterId, token: nextToken, isNew: true };
}

function isAllowedOrigin(origin, allowList) {
  if (!origin) {
    return true;
  }

  const normalizedOrigin = toOrigin(origin);
  if (!normalizedOrigin) {
    return false;
  }

  if (allowList.has(normalizedOrigin)) {
    return true;
  }

  return false;
}

function isSameHostOrigin(origin, hostHeader) {
  const normalizedOrigin = toOrigin(origin);
  if (!normalizedOrigin || !hostHeader) {
    return false;
  }

  const host = hostHeader.trim();
  if (!host) {
    return false;
  }

  return normalizedOrigin === `https://${host}` || normalizedOrigin === `http://${host}`;
}

function isAllowedRequestOrigin(origin, allowList, hostHeader) {
  if (!origin) {
    return true;
  }

  return isAllowedOrigin(origin, allowList) || isSameHostOrigin(origin, hostHeader);
}

function isVoteRateLimited(voterId) {
  const now = Date.now();
  const current = voteRateByVoter.get(voterId);

  if (!current || now > current.windowStart + voteWindowMs) {
    voteRateByVoter.set(voterId, { windowStart: now, count: 1 });
    return false;
  }

  current.count += 1;
  if (current.count > voteLimit) {
    return true;
  }

  return false;
}

function scrubStaleRateLimitEntries() {
  const now = Date.now();
  for (const [voterId, state] of voteRateByVoter.entries()) {
    if (now > state.windowStart + voteWindowMs * 2) {
      voteRateByVoter.delete(voterId);
    }
  }
}

function getOptionById(optionId) {
  return poll.options.find((option) => option.id === optionId);
}

function resetInMemoryVotes() {
  votesByVoter.clear();
  for (const option of poll.options) {
    option.votes = 0;
  }
}

function setVoteInMemory(voterId, optionId) {
  const nextOption = getOptionById(optionId);
  if (!nextOption) {
    return false;
  }

  const previousOptionId = votesByVoter.get(voterId);
  if (previousOptionId === optionId) {
    return true;
  }

  if (previousOptionId) {
    const previousOption = getOptionById(previousOptionId);
    if (previousOption && previousOption.votes > 0) {
      previousOption.votes -= 1;
    }
  }

  nextOption.votes += 1;
  votesByVoter.set(voterId, optionId);
  return true;
}

async function initializePersistence() {
  if (!pool) {
    console.warn("DATABASE_URL not set. Running with in-memory votes only.");
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id TEXT NOT NULL,
      voter_id TEXT NOT NULL,
      option_id TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (poll_id, voter_id)
    )
  `);

  const result = await pool.query(
    `SELECT voter_id, option_id FROM poll_votes WHERE poll_id = $1`,
    [poll.id],
  );

  resetInMemoryVotes();
  for (const row of result.rows) {
    setVoteInMemory(row.voter_id, row.option_id);
  }

  console.log(`Loaded ${result.rowCount} persisted votes from Postgres.`);
}

async function persistVote(voterId, optionId) {
  if (!pool) {
    return;
  }

  await pool.query(
    `
    INSERT INTO poll_votes (poll_id, voter_id, option_id, updated_at)
    VALUES ($1, $2, $3, NOW())
    ON CONFLICT (poll_id, voter_id)
    DO UPDATE SET option_id = EXCLUDED.option_id, updated_at = NOW()
    `,
    [poll.id, voterId, optionId],
  );
}

function enqueueVoteOperation(operation) {
  const run = voteWriteQueue.then(operation, operation);
  voteWriteQueue = run.catch(() => {});
  return run;
}

function snapshot() {
  const totalVotes = poll.options.reduce((sum, option) => sum + option.votes, 0);
  return {
    pollId: poll.id,
    question: poll.question,
    options: poll.options.map((option) => ({
      id: option.id,
      label: option.label,
      votes: option.votes,
    })),
    totalVotes,
  };
}

async function applyVote(voterId, optionId) {
  const optionExists = Boolean(getOptionById(optionId));
  if (!optionExists) {
    return { ok: false, code: "invalid_option" };
  }

  const previousOptionId = votesByVoter.get(voterId);
  if (previousOptionId === optionId) {
    return { ok: true, unchanged: true };
  }

  await persistVote(voterId, optionId);
  setVoteInMemory(voterId, optionId);
  return { ok: true, unchanged: false };
}

function broadcastState() {
  io.emit("poll:update", snapshot());
}

app.use((req, res, next) => {
  if (!isAllowedRequestOrigin(req.headers.origin, allowedOrigins, req.headers.host)) {
    res.status(403).send("Origin not allowed");
    return;
  }

  next();
});

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "same-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
  }),
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 500,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  }),
);

app.use((req, res, next) => {
  const session = getOrCreateVoterIdFromCookies(req.headers.cookie || "");
  if (session.isNew) {
    res.cookie("voter_session", session.token, {
      httpOnly: true,
      sameSite: "lax",
      secure: secureCookie,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: "/",
    });
  }

  req.voterId = session.voterId;
  next();
});

app.use(express.static(path.join(__dirname, "public")));

io.use((socket, next) => {
  if (!isAllowedRequestOrigin(socket.handshake.headers.origin, allowedOrigins, socket.handshake.headers.host)) {
    next(new Error("Origin not allowed"));
    return;
  }

  const session = getOrCreateVoterIdFromCookies(socket.handshake.headers.cookie || "");
  if (session.isNew) {
    next(new Error("Unauthorized"));
    return;
  }

  socket.data.voterId = session.voterId;
  next();
});

io.on("connection", (socket) => {
  const voterId = socket.data.voterId;
  socketToVoter.set(socket.id, voterId);
  socket.emit("poll:update", snapshot());
  io.emit("presence:update", { online: io.engine.clientsCount });

  const currentChoice = votesByVoter.get(voterId);
  if (currentChoice) {
    socket.emit("poll:your-vote", { optionId: currentChoice });
  }

  socket.on("poll:vote", async (payload) => {
    const optionId = payload && typeof payload.optionId === "string" ? payload.optionId.trim() : "";
    if (!optionId || optionId.length > 64) {
      return;
    }

    if (isVoteRateLimited(voterId)) {
      socket.emit("poll:error", { message: "Too many vote actions. Please wait a few seconds." });
      return;
    }

    let voteResult;
    try {
      voteResult = await enqueueVoteOperation(() => applyVote(voterId, optionId));
    } catch (error) {
      console.error("Failed to persist vote:", error);
      socket.emit("poll:error", { message: "Vote could not be saved. Please try again." });
      return;
    }

    if (!voteResult.ok) {
      return;
    }

    socket.emit("poll:your-vote", { optionId });
    if (!voteResult.unchanged) {
      broadcastState();
    }
  });

  socket.on("disconnect", () => {
    socketToVoter.delete(socket.id);
    io.emit("presence:update", { online: io.engine.clientsCount });
  });
});

async function start() {
  try {
    await initializePersistence();
    setInterval(scrubStaleRateLimitEntries, voteWindowMs).unref();

    server.listen(port, () => {
      console.log(`Real-time voting site running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

start();
