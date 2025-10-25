# URL Inspector API - Cloudflare Workers

## Overview

A comprehensive URL analysis API deployed on Cloudflare Workers that provides 17+ inspection features including SSL/TLS analysis, DNS records, WHOIS data, security scanning, performance metrics, SEO analysis, technology detection, and more. The system is designed to run entirely on Cloudflare's edge infrastructure without requiring traditional backend servers.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Serverless Edge Computing Platform

**Problem**: Need to analyze URLs at scale with low latency globally without managing server infrastructure.

**Solution**: Cloudflare Workers runtime with edge-based execution and distributed caching.

**Rationale**: 
- Workers execute at Cloudflare's edge locations worldwide for minimal latency
- Serverless model eliminates infrastructure management
- Built-in global distribution and DDoS protection
- Pay-per-request pricing model scales economically

**Pros**:
- Near-instant cold starts
- Global distribution out of the box
- No server maintenance required
- Automatic scaling

**Cons**:
- 50ms CPU time limit per request
- Limited execution environment (no Node.js standard library)
- Restricted package compatibility

### Web Framework

**Problem**: Need a lightweight, Workers-compatible routing and middleware framework.

**Solution**: Hono.js web framework

**Rationale**: Specifically designed for edge runtimes with minimal overhead and full Workers compatibility.

**Alternatives Considered**: Express.js (not Workers-compatible), native routing (too much boilerplate)

### API Architecture

**Pattern**: RESTful API with parallel data fetching and modular inspection services

**Core Endpoints**:
- `GET /api/status` - Health checks and feature availability
- `GET /api/metrics` - System performance metrics  
- `GET /api/inspect` - Single URL analysis
- `POST /api/inspect` - Batch URL processing (up to 20 URLs)

**Design Decisions**:
- Parallel execution using `Promise.allSettled()` for independent analysis tasks
- Configurable feature flags via query parameters
- Graceful degradation when individual features fail
- Standard response format with success/error handling

### Rate Limiting

**Problem**: Prevent abuse and ensure fair usage across all API consumers.

**Solution**: Durable Objects-based rate limiter with per-IP tracking

**Implementation**:
- 20 requests per minute per IP address
- Automatic counter reset after time window expires
- Rate limit headers in responses (X-RateLimit-*)
- Persistent state using Durable Objects storage

### Security Architecture

**SSRF Protection**: URL validation blocks private IP ranges, localhost, and non-HTTP(S) protocols

**Allowed Protocols**: HTTP and HTTPS only

**Blocked Targets**:
- Localhost (127.0.0.1, ::1)
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local addresses (169.254.0.0/16)
- .local domains

### Caching Strategy

**Problem**: Reduce redundant external API calls and improve response times for frequently inspected URLs.

**Solution**: Three-tier KV namespace caching system:

1. **SSL_CACHE** - SSL/TLS certificate data
2. **CT_CACHE** - Certificate Transparency logs
3. **GEO_CACHE** - IP geolocation data

**Rationale**: KV storage provides globally distributed, eventually-consistent caching with Workers integration.

### Inspection Service Architecture

**Pattern**: Modular service class with feature-specific methods

**Core Components**:
- `RealDataInspectorWorker` - Main inspection orchestrator
- Feature-specific methods (getHTTPData, getSSLInfo, getDNSRecords, etc.)
- Parallel execution of independent features
- Timeout handling for external requests

**Data Flow**:
1. URL validation and normalization
2. Parallel feature execution using Promise.allSettled
3. Result aggregation with graceful error handling
4. Response formatting with metadata

### CORS Configuration

**Strategy**: Permissive CORS for public API access

**Settings**:
- Allow all origins (*)
- Permitted methods: GET, POST, OPTIONS
- Standard headers plus X-API-Key
- 24-hour preflight cache

## External Dependencies

### Third-Party APIs

**IP Geolocation**: `ip-api.com`
- Purpose: Country, city, ISP, ASN data
- Authentication: None (free tier)
- Rate Limits: API-specific

**Certificate Transparency**: `crt.sh`
- Purpose: CT log retrieval and subdomain discovery
- Authentication: None
- Format: JSON API

**WHOIS Services**: Various WHOIS providers
- Purpose: Domain registration information
- Note: Implementation details in code suggest external WHOIS API integration

### Runtime Environment

**Platform**: Cloudflare Workers
- JavaScript runtime based on V8
- Web Standards APIs (fetch, URL, crypto, etc.)
- No Node.js standard library access

**Version**: Workers runtime (latest)

**Constraints**:
- 50ms CPU time per request
- 128MB memory limit
- No file system access
- No synchronous I/O

### Key JavaScript Libraries

**Hono** (^4.0.0): Edge-optimized web framework for routing and middleware

**Cheerio** (^1.0.0-rc.12): HTML parsing and manipulation for content analysis

**Note**: Standard Cheerio may not be fully Workers-compatible; implementation likely uses a compatible fork or alternative

### Cloudflare Platform Services

**KV Namespaces**: Distributed key-value storage for caching
- Global replication
- Eventual consistency model
- Accessed via Workers KV API

**Durable Objects**: Stateful coordination for rate limiting
- Single-instance consistency
- Transactional storage
- Alarm-based cleanup

### DNS Resolution

**Implementation**: Custom DNS resolution using Cloudflare's DNS-over-HTTPS (DoH) or Workers-compatible DNS APIs

**Record Types Supported**: A, AAAA, MX, NS, TXT, SOA, CNAME

### Development Tools

**Wrangler CLI** (^3.0.0): Cloudflare Workers deployment and development tool

**esbuild** (^0.19.0): JavaScript bundler for Workers deployment

### Deployment Pipeline

**CI/CD**: GitHub Actions integration (referenced in QUICK_START.md)

**Secrets Management**: GitHub Secrets for Cloudflare API tokens

**Environments**: Production and staging environments supported