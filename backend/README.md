# CipherGuard AI - Backend (Member 2)

Node.js + Express + TypeScript + PostgreSQL (Prisma) + JWT auth.

## Quick start

```bash
cd backend
npm install
cp .env.example .env          # Windows: copy .env.example .env  (then edit secrets)
docker compose up -d          # starts PostgreSQL
npx prisma migrate dev --name init
npm run dev                   # http://localhost:4000
```

In a second terminal: `npm run smoke` (runs all checks automatically).

## API

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /api/auth/register | - | `{email,password}` |
| POST | /api/auth/login | - | returns `accessToken`, `refreshToken` |
| POST | /api/auth/refresh | - | `{refreshToken}` -> new pair |
| POST | /api/auth/logout | - | `{refreshToken}` |
| POST | /api/scans | JWT | multipart field `file` |
| GET | /api/scans?page&limit&sortBy&order | JWT | history |
| GET | /api/scans/:id | JWT + owner | detail |
| GET | /api/scans/:id/download | JWT + owner | verified download |
| DELETE | /api/scans/:id | JWT + owner | delete |

## Files

- `src/services/mlClient.ts` - mock / real FastAPI switch (`ML_MODE` in .env)
- `src/services/storage.ts` - **Member 3 replaces this** with AES-GCM + RSA-OAEP
