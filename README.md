# BCM — Secret Messages · Real Backend

A full Node.js + Express backend replacing the original localStorage-only implementation.

## Stack
- **Express** — HTTP server
- **NeDB** — embedded file-persisted database (no external DB needed)
- **bcrypt** — proper password hashing (replaces the weak client-side hash)
- **multer** — multipart file uploads for images/videos
- **uuid** — secure ID generation

## Quick Start

```bash
# Install dependencies
npm install

# Run the server (default port 3000)
npm start
```

Then open **http://localhost:3000** in your browser.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | — | Register with PIN + optional login_id |
| POST | `/api/login` | — | Login with login_id + PIN → JWT-style token |
| GET | `/api/profile` | ✓ | Stats: total/active messages, redemptions |
| GET | `/api/messages` | ✓ | List your unredeemed messages |
| POST | `/api/messages/text` | ✓ | Create a text secret message |
| POST | `/api/messages/media` | ✓ | Upload an image/video secret (multipart) |
| POST | `/api/redeem` | — | Redeem a code (anyone with the code can) |
| DELETE | `/api/messages/:id` | ✓ | Delete one of your messages |
| GET | `/api/health` | — | Health check |

## Data Storage

| Path | Contents |
|------|----------|
| `data/users.db` | User accounts (login_id + bcrypt hash) |
| `data/messages.db` | Messages (text content or media URL) |
| `uploads/` | Uploaded image/video files |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP port |

## Deployment

The frontend (`public/index.html`) is served by the same Express server,
so just deploy the whole folder as a single Node.js app.

For external frontends, set `window.BCM_API_BASE = 'https://your-server.com'`
before the scripts load.

### Render / Railway / Fly.io
```bash
# Set start command to:
node server.js
```

### Docker (example)
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```
