# URL Inspector API - Cloudflare Workers Edition

A comprehensive URL analysis API deployed on Cloudflare Workers.

## Features

- **SSL/TLS Analysis** - Certificate validation, expiry checks, security scoring
- **DNS Records** - A, MX, NS, TXT, SOA records
- **WHOIS Data** - Domain registration information
- **Security Scanning** - Malware, phishing, and threat detection
- **Performance Metrics** - Load times, response times, page speed scores
- **SEO Analysis** - Meta tags, descriptions, search optimization
- **Technology Detection** - Identify frameworks, CMS, analytics tools
- **IP Geolocation** - Server location and network information
- **And much more...** - 17+ analysis features

## Deployment to Cloudflare

### Prerequisites
- [Cloudflare account](https://dash.cloudflare.com/sign-up)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### Quick Deploy

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Login to Cloudflare**
   ```bash
   npx wrangler login
   ```

3. **Deploy to Cloudflare Workers**
   ```bash
   npx wrangler deploy
   ```

That's it! Your API will be deployed to Cloudflare Workers globally.

## API Endpoints

### GET /api/status
Health check and feature availability
```bash
curl https://your-worker.workers.dev/api/status
```

### GET /api/inspect?url=<url>
Single URL inspection
```bash
curl "https://your-worker.workers.dev/api/inspect?url=https://example.com"
```

### POST /api/inspect
Batch URL processing (up to 20 URLs)
```bash
curl -X POST https://your-worker.workers.dev/api/inspect \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com", "https://google.com"]}'
```

### GET /api/metrics
System performance metrics
```bash
curl https://your-worker.workers.dev/api/metrics
```

## Configuration

Edit `wrangler.toml` to customize:
- `MAX_BATCH_SIZE` - Maximum URLs per batch request (default: 20)
- `DEFAULT_TIMEOUT` - Default request timeout (default: 12000ms)
- `MAX_TIMEOUT` - Maximum allowed timeout (default: 30000ms)
- `MIN_TIMEOUT` - Minimum allowed timeout (default: 5000ms)

## Query Parameters

For `GET /api/inspect`:
- `url` - The URL to inspect (required)
- `deep_scan` - Enable deep scanning (default: true)
- `check_subdomains` - Discover subdomains (default: true)
- `performance_monitoring` - Performance metrics (default: true)
- `security_scan` - Security analysis (default: true)
- `include_whois` - WHOIS data (default: true)
- `dns_analysis` - DNS records (default: true)

## Development

Run locally:
```bash
npx wrangler dev
```

## License

MIT
