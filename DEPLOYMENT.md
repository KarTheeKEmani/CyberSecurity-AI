# Production Deployment & Docker Guide — AIAC Cyber

## 1. Multi-Container Docker Deployment

AIAC Cyber provides a production-ready `docker-compose.yml` deploying:
- **`postgres`**: PostgreSQL 15 Database with persistent data volume and health checks.
- **`backend`**: FastAPI Application Server running under Uvicorn with connection pooling.
- **`frontend`**: Nginx Reverse Proxy serving the static Liquid Glass web client.

### Launch Containers
```bash
docker compose up --build -d
```

### Check Container Status
```bash
docker compose ps
```

### View Logs
```bash
docker compose logs -f backend
```

---

## 2. Environment Variables

| Variable | Description | Default / Example |
|---|---|---|
| `DATABASE_URL` | PostgreSQL or SQLite connection string | `postgresql://user:pass@postgres:5432/aiac_cyber` |
| `JWT_SECRET_KEY` | Secret key for signing JWT tokens | `generate-a-secure-random-secret` |
| `CORS_ORIGINS` | JSON list of allowed origins | `["http://localhost:3000"]` |
| `AI_PROVIDER` | AI triage provider (`mock`, `openai`, `gemini`) | `mock` |
| `DEMO_MODE` | Enable automatic database seeding on startup | `true` |
| `ENVIRONMENT` | Deployment environment | `production` |
