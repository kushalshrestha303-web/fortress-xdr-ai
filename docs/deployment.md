# Deployment Guide

## Prerequisites

- Docker & Docker Compose
- Python 3.10+
- Node.js 18+
- Git

## Local Development

```bash
# Clone repository
git clone https://github.com/kushalshrestha303-web/fortress-xdr-ai.git
cd fortress-xdr-ai

# Copy environment
cp .env.example .env

# Start services
docker-compose up -d

# Access
Dashboard: http://localhost:3000
API Docs: http://localhost:8000/docs
OpenSearch: http://localhost:9200
```

## Production Deployment

### 1. SSL/TLS Certificates

```bash
certbot certonly --standalone -d yourdomain.com
```

### 2. Environment Configuration

Update `.env` with production settings:
- Strong database password
- Valid OpenAI API key
- Proper CORS origins
- Secure SECRET_KEY

### 3. Database Migration

```bash
docker-compose exec backend alembic upgrade head
```

### 4. Create Admin User

```bash
docker-compose exec backend python -m scripts.create_admin
```

### 5. Deploy with Nginx

Configure Nginx as reverse proxy with SSL.
