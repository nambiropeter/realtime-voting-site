# Real-Time Voting Website

Simple live voting site built with Express + Socket.IO.

## Run

```bash
npm install
npm start
```

Open `http://localhost:3000` in multiple browser tabs/devices and vote. Results update in real time for everyone.

## Security hardening

- Signed `HttpOnly` voter session cookie (`voter_session`) so the browser no longer controls voter identity directly.
- Socket auth middleware validates the signed cookie before allowing real-time events.
- Security headers via `helmet` and disabled `x-powered-by`.
- Origin allow-list for both HTTP requests and Socket.IO handshakes.
- HTTP rate limiting (`express-rate-limit`) plus vote-action rate limiting to reduce bot/spam abuse.

## Optional environment variables

- `SESSION_SECRET`: secret used to sign voter session cookies (set this in production).
- `ALLOWED_ORIGINS`: comma-separated origins (example: `https://vote.example.com`).
- `SECURE_COOKIE=true`: mark session cookie as secure (use with HTTPS).
