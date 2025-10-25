# 🔌 URL Inspector API - Complete Endpoint Examples

## 🌐 Base URL

After deployment, your API will be available at:
```
https://url-inspector-api.<your-subdomain>.workers.dev
```

---

## 1️⃣ Health Check - GET /api/status

**Purpose:** Check if the API is running and see available features

### Request
```bash
curl https://your-api.workers.dev/api/status
```

### Response Example
```json
{
  "success": true,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "abc-123-def-456",
  "status": "healthy",
  "version": "1.0.0",
  "features": {
    "rate_limiting": false,
    "batch_processing": true,
    "security_scanning": true,
    "ssl_analysis": true,
    "performance_monitoring": true,
    "dns_analysis": true,
    "whois_lookup": true,
    "subdomain_discovery": true,
    "certificate_transparency": true,
    "caching": false,
    "storage": false
  },
  "limits": {
    "max_batch_size": 20,
    "max_timeout": 30000,
    "min_timeout": 5000,
    "default_timeout": 12000
  },
  "edge_location": "DFW"
}
```

---

## 2️⃣ System Metrics - GET /api/metrics

**Purpose:** Get system performance and location information

### Request
```bash
curl https://your-api.workers.dev/api/metrics
```

### Response Example
```json
{
  "success": true,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "xyz-789-abc-123",
  "system": {
    "edge_location": "DFW",
    "colo": "DFW",
    "timestamp": 1729851000000
  },
  "api": {
    "version": "1.0.0",
    "status": "operational",
    "worker_id": "unique-worker-id"
  }
}
```

---

## 3️⃣ Single URL Inspection - GET /api/inspect

**Purpose:** Comprehensive analysis of a single URL with 17+ features

### Basic Request
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://example.com"
```

### Advanced Request (with options)
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://google.com&timeout=20000&deep_scan=true&check_subdomains=true&security_scan=true"
```

### All Available Parameters
- `url` (required) - URL to inspect
- `timeout` (optional) - Timeout in ms (5000-30000)
- `user_agent` (optional) - Custom user agent
- `deep_scan` (optional) - Enable deep scanning (default: true)
- `check_subdomains` (optional) - Find subdomains (default: true)
- `performance_monitoring` (optional) - Performance metrics (default: true)
- `security_scan` (optional) - Security analysis (default: true)
- `include_whois` (optional) - WHOIS data (default: true)
- `dns_analysis` (optional) - DNS records (default: true)
- `brand_monitoring` (optional) - Similar domains (default: true)
- `content_classification` (optional) - Content analysis (default: true)
- `threat_intelligence` (optional) - Threat analysis (default: true)

### Response Example (Condensed)
```json
{
  "success": true,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "inspection-abc-123",
  "results": [
    {
      "url": "https://example.com",
      "final_url": "https://example.com",
      "http_status": 200,
      "latency_ms": 245,
      "ip_address": "93.184.216.34",
      
      "ip_geolocation": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Los Angeles",
        "latitude": 34.0522,
        "longitude": -118.2437,
        "timezone": "America/Los_Angeles",
        "isp": "EDGECAST",
        "asn": "AS15133"
      },
      
      "ssl_info": {
        "valid": true,
        "expiry": "2026-01-15",
        "issuer": "DigiCert Inc",
        "days_remaining": 82,
        "security_score": 95,
        "grade": "A+",
        "chain_valid": true,
        "vulnerabilities": []
      },
      
      "dns_records": [
        {
          "type": "A",
          "value": "93.184.216.34",
          "ttl": 3600
        },
        {
          "type": "AAAA",
          "value": "2606:2800:220:1:248:1893:25c8:1946",
          "ttl": 3600
        },
        {
          "type": "MX",
          "value": "mail.example.com",
          "ttl": 3600
        }
      ],
      
      "subdomains": [
        "www.example.com",
        "mail.example.com",
        "ftp.example.com"
      ],
      
      "whois_data": {
        "registrar": "IANA",
        "created_date": "1995-08-14",
        "expiry_date": "2026-08-13",
        "updated_date": "2024-08-14",
        "name_servers": ["ns1.example.com", "ns2.example.com"]
      },
      
      "security_analysis": {
        "https_enabled": true,
        "ssl_valid": true,
        "security_headers": {
          "strict-transport-security": true,
          "x-content-type-options": true,
          "x-frame-options": true
        },
        "risk_score": 5,
        "risk_level": "low",
        "malware_detected": false,
        "phishing_detected": false
      },
      
      "performance_metrics": {
        "response_time_ms": 245,
        "ttfb_ms": 120,
        "page_size_kb": 1256,
        "requests_count": 42,
        "performance_score": 85
      },
      
      "technology_stack": {
        "server": "nginx/1.18.0",
        "framework": "Unknown",
        "cms": "Unknown",
        "cdn": "Cloudflare",
        "analytics": ["Google Analytics"]
      },
      
      "seo_analysis": {
        "title": "Example Domain",
        "description": "Example Domain",
        "keywords": "",
        "has_sitemap": true,
        "has_robots_txt": true,
        "seo_score": 75
      },
      
      "content_analysis": {
        "word_count": 125,
        "image_count": 0,
        "link_count": 1,
        "has_forms": false
      },
      
      "social_media_presence": {
        "facebook": false,
        "twitter": false,
        "linkedin": false,
        "instagram": false
      },
      
      "compliance": {
        "gdpr_compliant": true,
        "ccpa_compliant": true,
        "privacy_policy": true,
        "terms_of_service": true
      },
      
      "accessibility": {
        "wcag_score": 80,
        "has_alt_tags": true,
        "has_aria_labels": true
      },
      
      "scan_timestamp": "2025-10-25T10:30:00.000Z"
    }
  ],
  "total_processed": 1,
  "processing_time_ms": 2456,
  "scan_id": "scan-unique-id",
  "edge_location": "DFW"
}
```

---

## 4️⃣ Batch URL Processing - POST /api/inspect

**Purpose:** Analyze multiple URLs at once (up to 20)

### Request
```bash
curl -X POST https://your-api.workers.dev/api/inspect \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://example.com",
      "https://google.com",
      "https://github.com"
    ],
    "timeout": 15000,
    "deep_scan": true,
    "check_subdomains": false,
    "include_whois": false
  }'
```

### Response Example
```json
{
  "success": true,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "batch-abc-123",
  "results": [
    {
      "url": "https://example.com",
      "http_status": 200,
      "ip_address": "93.184.216.34",
      "ssl_valid": true,
      // ... full inspection data for each URL
    },
    {
      "url": "https://google.com",
      "http_status": 200,
      "ip_address": "142.250.185.46",
      "ssl_valid": true,
      // ... full inspection data
    },
    {
      "url": "https://github.com",
      "http_status": 200,
      "ip_address": "140.82.121.4",
      "ssl_valid": true,
      // ... full inspection data
    }
  ],
  "total_processed": 3,
  "processing_time_ms": 4567,
  "scan_id": "batch-scan-unique-id",
  "summary": {
    "total_urls": 3,
    "successful_scans": 3,
    "failed_scans": 0
  },
  "edge_location": "DFW"
}
```

---

## 5️⃣ Error Handling Examples

### Invalid URL (400 Bad Request)
```bash
curl "https://your-api.workers.dev/api/inspect?url=http://localhost:3000"
```

Response:
```json
{
  "success": false,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "error-abc-123",
  "error": "URL validation failed",
  "message": "Localhost URLs are not allowed for security reasons",
  "error_type": "SecurityError"
}
```

### Missing URL (400 Bad Request)
```bash
curl "https://your-api.workers.dev/api/inspect"
```

Response:
```json
{
  "success": false,
  "timestamp": "2025-10-25T10:30:00.000Z",
  "request_id": "error-xyz-789",
  "error": "Missing Parameter",
  "message": "Please provide a URL to inspect using the \"url\" query parameter",
  "error_type": "ValidationError"
}
```

### 404 Not Found
```bash
curl "https://your-api.workers.dev/api/invalid"
```

Response:
```json
{
  "success": false,
  "error": "API endpoint not found",
  "message": "The endpoint /api/invalid does not exist",
  "available_endpoints": [
    "GET /api/status",
    "GET /api/metrics",
    "GET /api/inspect?url=<url>",
    "POST /api/inspect"
  ]
}
```

---

## 📊 Real-World Usage Examples

### Example 1: Quick Security Check
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://example.com&security_scan=true&deep_scan=false&check_subdomains=false"
```

### Example 2: Full Domain Analysis
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://example.com&timeout=25000&deep_scan=true&check_subdomains=true"
```

### Example 3: Fast Performance Check Only
```bash
curl "https://your-api.workers.dev/api/inspect?url=https://example.com&timeout=5000&security_scan=false&check_subdomains=false&include_whois=false"
```

### Example 4: Batch Security Audit
```bash
curl -X POST https://your-api.workers.dev/api/inspect \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://example.com",
      "https://test.com",
      "https://demo.com"
    ],
    "timeout": 10000,
    "security_scan": true,
    "deep_scan": false,
    "check_subdomains": false,
    "include_whois": false
  }'
```

---

## 🧪 Testing Your Deployed API

After deployment, test with these commands:

```bash
# 1. Check API is online
curl https://your-api.workers.dev/api/status

# 2. Test with a simple URL
curl "https://your-api.workers.dev/api/inspect?url=https://example.com"

# 3. Run comprehensive tests
node test-cloudflare-deployment.js https://your-api.workers.dev
```

---

## 📝 Notes

- All timestamps are in ISO 8601 format (UTC)
- All timeout values are in milliseconds
- Default timeout is 12 seconds (12000ms)
- Maximum batch size is 20 URLs
- All responses include `success`, `timestamp`, and `request_id` fields
- Edge location varies based on where the request is processed
- CORS is enabled for all origins

---

## 🚀 Ready to Deploy?

```bash
cd workers
wrangler login
wrangler deploy
```

Your API will be live in under 2 minutes! 🌐
