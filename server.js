const path = require("path");
const crypto = require("crypto");
const express = require("express");
const http = require("http");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
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

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin, allowedOrigins)) {
        callback(null, true);
        return;
      }

      callback(new Error("Origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST"],
  },
});

const poll = {
  id: "launch-priority",
  question: "What should we prioritize this week?",
  options: [
    { id: "new-feature", label: "Build a new feature", votes: 0 },
    { id: "bug-fixes", label: "Fix top bugs", votes: 0 },
    { id: "performance", label: "Performance improvements", votes: 0 },
    { id: "ui-refresh", label: "UI refresh", votes: 0 },
  ],
};

const votesByVoter = new Map();
const socketToVoter = new Map();
const voteRateByVoter = new Map();

function parseAllowedOrigins(rawOrigins, activePort) {
  const toOrigin = (input) => {
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
  };

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

  return allowList.has(origin);
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

function applyVote(voterId, optionId) {
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

function broadcastState() {
  io.emit("poll:update", snapshot());
}

app.use((req, res, next) => {
  if (!isAllowedOrigin(req.headers.origin, allowedOrigins)) {
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

  socket.on("poll:vote", (payload) => {
    const optionId = payload && typeof payload.optionId === "string" ? payload.optionId.trim() : "";
    if (!optionId || optionId.length > 64) {
      return;
    }

    if (isVoteRateLimited(voterId)) {
      socket.emit("poll:error", { message: "Too many vote actions. Please wait a few seconds." });
      return;
    }

    const voteAccepted = applyVote(voterId, optionId);
    if (!voteAccepted) {
      return;
    }

    socket.emit("poll:your-vote", { optionId });
    broadcastState();
  });

  socket.on("disconnect", () => {
    socketToVoter.delete(socket.id);
    io.emit("presence:update", { online: io.engine.clientsCount });
  });
});

setInterval(scrubStaleRateLimitEntries, voteWindowMs).unref();

server.listen(port, () => {
  console.log(`Real-time voting site running at http://localhost:${port}`);
});
