# openclaw-web

A web interface for [OpenClaw](https://github.com/openclaw/openclaw).

## About

This project provides a clean web UI for interacting with the OpenClaw AI gateway.

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+ recommended)
- A running [OpenClaw](https://github.com/openclaw/openclaw) gateway

### Install dependencies

```bash
npm install
```

### Configure environment variables

Copy `.env.example` to `.env` (or create `.env` manually) and set the following:

```env
# OpenClaw gateway URL (default: local loopback)
OPENCLAW_URL=http://127.0.0.1:18789/v1/chat/completions

# Gateway bearer token (from openclaw.json gateway.auth.token)
OPENCLAW_TOKEN=your_token_here
```

- **`OPENCLAW_URL`** — The URL of your OpenClaw gateway. Defaults to local loopback (`127.0.0.1:18789`). Change this if your gateway is running on a different host or port.
- **`OPENCLAW_TOKEN`** — The bearer token for authenticating with the gateway. Find this in your OpenClaw config under `gateway.auth.token`.

### Run the server

```bash
npm start
```

Then open your browser and navigate to `http://localhost:3000` (or whatever port the server binds to).

### Auto-boot + redeploy (recommended)

This project is configured to run as a **user systemd service** named `openclaw-web.service`.

Use this to deploy updates safely:

```bash
./scripts/deploy.sh
```

What deploy does:

1. Installs dependencies
2. Runs tests
3. Installs/updates the systemd service
4. Enables auto-start on login/restart
5. Restarts the service

---

*Built by Jun 🥷 for Logbie LLC*
