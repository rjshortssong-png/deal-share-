# DealShare — Fully Online Backend (No external API key)

Self-hosted Node.js marketplace. **No Supabase / Firebase / external API keys needed.**

## Features
- User signup / login (first user = admin)
- Product listing with search & categories
- Image upload (max 5 MB, png/jpg/webp)
- Favorites / Saved products
- Affiliate click tracking
- Admin approval workflow (pending → approved / rejected)
- Profile edit

## Run locally
```bash
# Node.js 18+ required
cd dealshare-backend
npm start
# Open http://localhost:3000
```

## Deploy online (any of these)

### 1. Railway / Render / Fly.io / VPS
- Push this folder to GitHub
- Create a new Node service
- Set start command: `node server.js`
- **Important**: Enable **persistent disk** for `/data` and `/uploads` folders  
  (otherwise data is lost on restart)

### 2. Environment variables (optional)
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | 3000    | Server port |
| `HOST`   | 0.0.0.0 | Bind address |
| `NODE_ENV` | -     | Set to `production` for Secure cookies |

## Data storage
- Accounts, products, sessions, favorites, clicks → `data/db.json`
- Product images → `uploads/`

## Notes
- First registered account automatically becomes **admin**.
- Products submitted by users stay `pending` until admin approves them.
- Admin can see all products and change status from Profile → Admin Dashboard.
