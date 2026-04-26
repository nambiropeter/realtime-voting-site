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

## Beginner-friendly deploy (Render)

This app uses Socket.IO, so Render is a good beginner-friendly host that supports long-lived WebSocket connections.

1. Go to Render and create a new **Blueprint**.
2. Connect your GitHub repo: `nambiropeter/realtime-voting-site`.
3. Render will detect [render.yaml](./render.yaml) and create the web service automatically.
4. Click **Deploy**.

After deploy:
- Use the generated `https://<your-app>.onrender.com` URL.
- If you add a custom domain later, set `ALLOWED_ORIGINS` to include both domains, comma-separated.
