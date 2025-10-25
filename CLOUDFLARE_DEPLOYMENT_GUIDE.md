# Cloudflare Workers Deployment Guide

## ✅ Pre-Deployment Checklist

Before deploying your URL Inspector API to Cloudflare Workers, verify:

- [ ] Cloudflare account created (free tier works!)
- [ ] Wrangler CLI installed (`npm install -g wrangler`)
- [ ] Logged into Wrangler (`wrangler login`)
- [ ] Code tested locally (see Testing section)
- [ ] API endpoints verified (run test script)

## 📋 Step-by-Step Deployment

### 1. Install Wrangler (if not already installed)

```bash
npm install -g wrangler
```

### 2. Login to Cloudflare

```bash
wrangler login
```

This will open a browser window to authenticate with your Cloudflare account.

### 3. Navigate to Workers Directory

```bash
cd workers
```

### 4. Install Dependencies

```bash
npm install
```

### 5. Test Locally (Optional but Recommended)

```bash
npm run dev
```

This starts a local development server at `http://localhost:8787`

### 6. Deploy to Cloudflare

```bash
npm run deploy
```

Or using wrangler directly:

```bash
wrangler deploy
```

### 7. Verify Deployment

After deployment, Wrangler will provide a URL like:
```
https://url-inspector-api.<your-subdomain>.workers.dev
```

Test the deployed API:

```bash
# Test status endpoint
curl https://url-inspector-api.<your-subdomain>.workers.dev/api/status

# Test inspection
curl "https://url-inspector-api.<your-subdomain>.workers.dev/api/inspect?url=https://example.com"
```

## 🧪 Testing Your Deployment

### Local Testing

```bash
cd workers
npm run dev
```

Then in another terminal:

```bash
# Run the test script against local server
node ../test-cloudflare-deployment.js http://localhost:8787
```

### Production Testing

After deploying, test your live API:

```bash
# Replace with your actual Workers URL
node test-cloudflare-deployment.js https://url-inspector-api.<your-subdomain>.workers.dev
```

## 🔧 Configuration

### Environment Variables

All configuration is in `workers/wrangler.toml`:

```toml
[vars]
API_VERSION = "1.0.0"
MAX_BATCH_SIZE = "20"
DEFAULT_TIMEOUT = "12000"
MAX_TIMEOUT = "30000"
MIN_TIMEOUT = "5000"
```

### Secrets (Optional)

For enhanced features, you can set secrets:

```bash
# Enhanced WHOIS data (optional)
wrangler secret put WHOIS_API_KEY

# Cloudflare-specific features (optional)
wrangler secret put CF_API_TOKEN
```

## 📊 Available Endpoints

Once deployed, your API will have:

### 1. Health Check
```bash
GET /api/status
```

### 2. System Metrics
```bash
GET /api/metrics
```

### 3. Single URL Inspection
```bash
GET /api/inspect?url=https://example.com&timeout=15000
```

### 4. Batch URL Inspection
```bash
POST /api/inspect
Content-Type: application/json

{
  "urls": ["https://example.com", "https://google.com"],
  "timeout": 15000,
  "deep_scan": true
}
```

## 🌍 Custom Domain (Optional)

To use a custom domain:

1. Add a route in `wrangler.toml`:
```toml
routes = [
  { pattern = "api.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

2. Deploy again:
```bash
npm run deploy
```

3. Add DNS record in Cloudflare Dashboard:
   - Type: CNAME
   - Name: api
   - Target: your-worker-name.workers.dev

## 📈 Monitoring

### View Live Logs

```bash
cd workers
npm run tail
```

Or:

```bash
wrangler tail
```

### Cloudflare Dashboard

Visit your Cloudflare Workers dashboard to see:
- Request analytics
- Error rates
- CPU usage
- Bandwidth

## 💰 Costs

### Free Tier
- 100,000 requests/day
- Perfect for testing and small projects
- **Cost: $0/month**

### Paid Plan ($5/month)
- 10 million requests included
- 50ms CPU time per request
- Additional requests: $0.50 per million
- **Typical cost: $5-10/month**

## 🔍 Troubleshooting

### Issue: "Not logged in"
**Solution:**
```bash
wrangler login
```

### Issue: "No account found"
**Solution:**
1. Go to https://dash.cloudflare.com
2. Create a free account
3. Run `wrangler login` again

### Issue: "Build failed"
**Solution:**
```bash
cd workers
npm install
wrangler deploy
```

### Issue: "Module not found"
**Solution:** Make sure you're in the `workers` directory:
```bash
cd workers
npm install
```

### Issue: "Request timeout"
**Solution:** Increase timeout in query params:
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://example.com&timeout=20000"
```

## 🚀 Quick Deploy Commands

```bash
# Full deployment flow
cd workers
npm install
wrangler login
wrangler deploy

# Update after code changes
cd workers
wrangler deploy

# View logs
wrangler tail

# Test locally
npm run dev
```

## 📝 Next Steps

After deployment:

1. ✅ Test all endpoints with real URLs
2. ✅ Monitor logs for any errors
3. ✅ Set up custom domain (optional)
4. ✅ Configure alerts in Cloudflare Dashboard
5. ✅ Share your API URL!

## 🔗 Useful Links

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Wrangler CLI Docs](https://developers.cloudflare.com/workers/wrangler/)
- [Workers Dashboard](https://dash.cloudflare.com/?to=/:account/workers)
- [Pricing](https://workers.cloudflare.com/#plans)

---

## 🎯 Ready to Deploy?

Run these commands in your terminal:

```bash
cd workers
npm install
wrangler login
wrangler deploy
```

That's it! Your URL Inspector API will be live on Cloudflare's global network! 🌐
