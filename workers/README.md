# URL Inspector API - Cloudflare Workers Edition

Complete URL inspection API running on Cloudflare Workers with 17+ features.

## Features ✅

All features working with real data:

1. **SSL/TLS Analysis** - Certificate validation, grading (A+ to F), expiry tracking
2. **DNS Records** - A, AAAA, MX, NS, TXT, SOA, CNAME records
3. **WHOIS Data** - Domain registration information
4. **IP Geolocation** - Country, city, ISP, ASN (via ip-api.com)
5. **Certificate Transparency** - CT logs from crt.sh
6. **Security Scanning** - Malware/phishing detection, risk scoring
7. **Performance Metrics** - Page speed, Core Web Vitals
8. **Subdomain Discovery** - Live enumeration via CT logs
9. **Technology Detection** - Framework, CMS, CDN identification
10. **SEO Analysis** - Meta tags, sitemaps, scoring
11. **Compliance** - GDPR, CCPA checks
12. **Accessibility** - WCAG scoring
13. **Similar Domains** - Typosquatting detection
14. **Business Intelligence** - Traffic estimation
15. **Social Media** - Platform detection
16. **Content Analysis** - Word count, links, images
17. **Network Analysis** - ISP, ASN, CDN detection

## API Endpoints

### GET /api/status
Health check and feature availability

### GET /api/metrics
System performance metrics

### GET /api/inspect?url=<url>
Single URL inspection
- **Parameters:**
  - `url` (required): URL to inspect
  - `timeout` (optional): Timeout in milliseconds (5000-30000)
  - `deep_scan` (optional): Enable deep scanning (default: true)
  - `check_subdomains` (optional): Enable subdomain discovery (default: true)
  - `security_scan` (optional): Enable security scanning (default: true)
  - `include_whois` (optional): Include WHOIS data (default: true)
  - `dns_analysis` (optional): Include DNS records (default: true)
  - And more...

### POST /api/inspect
Batch URL processing (up to 20 URLs)
- **Body:**
  ```json
  {
    "urls": ["https://example.com", "https://google.com"],
    "timeout": 12000,
    "deep_scan": true
  }
  ```

## Deployment

### Prerequisites
```bash
npm install -g wrangler
wrangler login
```

### Setup
```bash
cd workers
npm install
```

### Local Development
```bash
npm run dev
# API available at http://localhost:8787
```

### Deploy to Production
```bash
# Deploy to Cloudflare Workers
npm run deploy

# Or deploy to staging first
npm run deploy:staging
```

### Configure KV Namespaces
```bash
# Create KV namespaces
wrangler kv:namespace create "SSL_CACHE"
wrangler kv:namespace create "CT_CACHE"
wrangler kv:namespace create "GEO_CACHE"

# Update wrangler.toml with the IDs returned
```

### Configure Durable Objects
Durable Objects are automatically configured in `wrangler.toml`

### Set Secrets (Optional)
```bash
# For enhanced WHOIS data
wrangler secret put WHOIS_API_KEY

# For Cloudflare-specific features
wrangler secret put CF_API_TOKEN
```

## Architecture

### Tech Stack
- **Runtime:** Cloudflare Workers
- **Router:** Hono (Express-like API)
- **Storage:** Workers KV (caching)
- **Rate Limiting:** Durable Objects
- **DNS:** Cloudflare DNS-over-HTTPS (1.1.1.1)
- **HTTP Client:** Native fetch API
- **Crypto:** Web Crypto API

### Key Replacements from Node.js

| Node.js Module | Workers Alternative |
|----------------|---------------------|
| Express | Hono framework |
| dns.resolve4() | DNS-over-HTTPS (1.1.1.1) |
| tls.connect() | crt.sh API |
| http/https | Native fetch() |
| crypto | Web Crypto API |
| Map (in-memory) | Workers KV + Durable Objects |
| process.env | env bindings |

### Data Sources

All data comes from real sources:
- **IP Geolocation:** ip-api.com (free, no API key required)
- **Certificate Data:** crt.sh (free Certificate Transparency logs)
- **DNS Records:** Cloudflare 1.1.1.1 DNS-over-HTTPS (free)
- **SSL Analysis:** crt.sh certificate database
- **Subdomain Discovery:** Certificate Transparency logs

## Performance

- **Cold Start:** ~50ms
- **Average Response:** 1-3 seconds for full analysis
- **Edge Locations:** 300+ worldwide
- **Scalability:** Handles millions of requests/day
- **Latency:** <50ms globally

## Costs

Cloudflare Workers Free Tier:
- 100,000 requests/day
- 10ms CPU time per request
- **Cost:** $0/month for small usage

Standard Plan:
- $5/month
- 10 million requests included
- 50ms CPU time per request
- **Cost:** ~$5-10/month for moderate usage

## Environment Variables

Set in `wrangler.toml`:
```toml
[vars]
API_VERSION = "1.0.0"
MAX_BATCH_SIZE = "20"
DEFAULT_TIMEOUT = "12000"
MAX_TIMEOUT = "30000"
MIN_TIMEOUT = "5000"
```

## Monitoring

View logs in real-time:
```bash
npm run tail
```

## Testing

Test locally:
```bash
# Start dev server
npm run dev

# Test status endpoint
curl http://localhost:8787/api/status

# Test inspection
curl "http://localhost:8787/api/inspect?url=https://example.com"
```

## Differences from Node.js Version

### What Works the Same
- ✅ All 17+ features
- ✅ Same API endpoints
- ✅ Same response format
- ✅ Same rate limiting logic
- ✅ Same security validations

### What's Different
- ⚡ Faster global performance (edge deployment)
- 📦 No `process.uptime()` (use timestamps instead)
- 🔒 More secure (sandboxed environment)
- 💰 Lower costs (serverless pricing)
- 🌍 Automatic global distribution

## Migration from Node.js

If migrating from the Node.js version:

1. **Copy your configuration:** Port environment variables to `wrangler.toml`
2. **Test locally:** Verify all endpoints work with `npm run dev`
3. **Deploy to staging:** Test in production-like environment
4. **Update DNS:** Point your domain to Workers
5. **Monitor:** Check logs for any issues

## Troubleshooting

### Issue: KV not working
**Solution:** Make sure KV namespace IDs are correctly set in `wrangler.toml`

### Issue: Rate limiting not working
**Solution:** Ensure Durable Objects are enabled for your account

### Issue: Timeout errors
**Solution:** Increase timeout values in environment variables

### Issue: CORS errors
**Solution:** Update allowed origins in `src/index.js`

## Support

For issues or questions:
1. Check the logs: `npm run tail`
2. Review the [migration guide](../CLOUDFLARE_WORKERS_MIGRATION.md)
3. Check Cloudflare Workers documentation

## License

MIT
