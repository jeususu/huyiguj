/**
 * URL Inspector API - Cloudflare Workers Edition
 * 
 * Comprehensive URL analysis API with 17+ features:
 * - SSL/TLS analysis
 * - DNS records
 * - WHOIS data
 * - Security scanning
 * - Performance metrics
 * - SEO analysis
 * - And much more...
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { RealDataInspectorWorker } from './services/inspector';
import { validateUrl, generateRequestId } from './utils/helpers';

const app = new Hono();

// CORS middleware
app.use('/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Origin', 'Content-Type', 'Accept', 'Authorization', 'X-API-Key'],
  credentials: true,
  maxAge: 86400
}));

// Standard response helper
function createStandardResponse(success, data = {}, error = null) {
  const baseResponse = {
    success,
    timestamp: new Date().toISOString(),
    request_id: crypto.randomUUID()
  };
  
  if (success) {
    return { ...baseResponse, ...data };
  } else {
    return {
      ...baseResponse,
      error: error?.type || 'Unknown error',
      message: error?.message || 'An unexpected error occurred',
      error_type: error?.errorType || 'InternalError',
      ...error?.additionalData
    };
  }
}

// NO STORAGE - No rate limiting, no KV cache, no Durable Objects
// Simple stateless API

// GET /api/status - Health check endpoint
app.get('/api/status', (c) => {
  return c.json(createStandardResponse(true, {
    status: 'healthy',
    version: c.env.API_VERSION || '1.0.0',
    features: {
      rate_limiting: false,
      batch_processing: true,
      security_scanning: true,
      ssl_analysis: true,
      performance_monitoring: true,
      dns_analysis: true,
      whois_lookup: true,
      subdomain_discovery: true,
      certificate_transparency: true,
      caching: false,
      storage: false
    },
    limits: {
      max_batch_size: parseInt(c.env.MAX_BATCH_SIZE || '20'),
      max_timeout: parseInt(c.env.MAX_TIMEOUT || '30000'),
      min_timeout: parseInt(c.env.MIN_TIMEOUT || '5000'),
      default_timeout: parseInt(c.env.DEFAULT_TIMEOUT || '12000')
    },
    edge_location: c.req.header('CF-Ray')?.split('-')[1] || 'unknown'
  }));
});

// GET /api/metrics - System metrics endpoint
app.get('/api/metrics', (c) => {
  return c.json(createStandardResponse(true, {
    system: {
      edge_location: c.req.header('CF-Ray')?.split('-')[1] || 'unknown',
      colo: c.req.header('CF-RAY')?.split('-')[1] || 'unknown',
      timestamp: Date.now()
    },
    api: {
      version: c.env.API_VERSION || '1.0.0',
      status: 'operational',
      worker_id: crypto.randomUUID()
    },
    timestamp: new Date().toISOString()
  }));
});

// GET /api/inspect?url=<url> - Single URL inspection
app.get('/api/inspect', async (c) => {
  const url = c.req.query('url');
  const userAgent = c.req.query('user_agent');
  const requestedTimeout = parseInt(c.req.query('timeout')) || parseInt(c.env.DEFAULT_TIMEOUT || '12000');
  const startTime = Date.now();
  
  // Feature toggles
  const deepScan = c.req.query('deep_scan') !== 'false';
  const checkSubdomains = c.req.query('check_subdomains') !== 'false';
  const performanceMonitoring = c.req.query('performance_monitoring') !== 'false';
  const securityScan = c.req.query('security_scan') !== 'false';
  const includeWhois = c.req.query('include_whois') !== 'false';
  const dnsAnalysis = c.req.query('dns_analysis') !== 'false';
  const brandMonitoring = c.req.query('brand_monitoring') !== 'false';
  const contentClassification = c.req.query('content_classification') !== 'false';
  const threatIntelligence = c.req.query('threat_intelligence') !== 'false';
  
  try {
    // Validate URL
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return c.json(createStandardResponse(false, {}, {
        type: 'Missing Parameter',
        message: 'Please provide a URL to inspect using the "url" query parameter',
        errorType: 'ValidationError'
      }), 400);
    }

    const sanitizedUrl = url.trim();
    
    // Security validation
    const securityCheck = validateUrl(sanitizedUrl);
    if (!securityCheck.allowed) {
      return c.json(createStandardResponse(false, {}, {
        type: 'URL validation failed',
        message: securityCheck.reason || 'URL not allowed for security reasons',
        errorType: 'SecurityError'
      }), 400);
    }

    // Perform inspection
    const inspector = new RealDataInspectorWorker(c.env);
    const inspectionTimeout = Math.max(
      Math.min(requestedTimeout, parseInt(c.env.MAX_TIMEOUT || '30000')),
      parseInt(c.env.MIN_TIMEOUT || '5000')
    );
    
    const result = await Promise.race([
      inspector.inspectWithRealData(sanitizedUrl, {
        urls: [sanitizedUrl],
        user_agent: userAgent,
        timeout: inspectionTimeout,
        include_screenshot: false,
        deep_scan: deepScan,
        check_subdomains: checkSubdomains,
        performance_monitoring: performanceMonitoring,
        security_scan: securityScan,
        include_whois: includeWhois,
        dns_analysis: dnsAnalysis,
        brand_monitoring: brandMonitoring,
        content_classification: contentClassification,
        threat_intelligence: threatIntelligence
      }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('ANALYSIS_TIMEOUT')), inspectionTimeout + 1000)
      )
    ]);

    const processingTime = Date.now() - startTime;

    return c.json(createStandardResponse(true, {
      results: [result],
      total_processed: 1,
      processing_time_ms: processingTime,
      scan_id: crypto.randomUUID(),
      edge_location: c.req.header('CF-Ray')?.split('-')[1] || 'unknown'
    }));

  } catch (error) {
    console.error('Single URL inspection error:', error);
    return c.json(createStandardResponse(false, {}, {
      type: 'Inspection failed',
      message: error.message || 'URL inspection failed',
      errorType: 'InspectionError',
      additionalData: {
        processing_time_ms: Date.now() - startTime
      }
    }), 500);
  }
});

// POST /api/inspect - Batch URL processing
app.post('/api/inspect', async (c) => {
  const startTime = Date.now();
  
  try {
    const body = await c.req.json();
    
    // Validate request body
    if (!body || Object.keys(body).length === 0) {
      return c.json(createStandardResponse(false, {}, {
        type: 'Request body is required',
        message: 'Please provide a valid JSON request body with URLs to inspect',
        errorType: 'ValidationError'
      }), 400);
    }
    
    if (!body.urls || !Array.isArray(body.urls) || body.urls.length === 0) {
      return c.json(createStandardResponse(false, {}, {
        type: 'Validation Error',
        message: 'Request must include a "urls" array with at least one URL',
        errorType: 'ValidationError'
      }), 400);
    }

    const inspector = new RealDataInspectorWorker(c.env);
    
    // Limit batch size
    const maxBatchSize = parseInt(c.env.MAX_BATCH_SIZE || '20');
    const urlsToProcess = body.urls.slice(0, maxBatchSize);
    
    const batchTimeout = Math.max(
      Math.min(body.timeout || 25000, parseInt(c.env.MAX_TIMEOUT || '30000')),
      parseInt(c.env.MIN_TIMEOUT || '5000')
    );
    
    const settledResults = await Promise.allSettled(
      urlsToProcess.map(url => 
        Promise.race([
          inspector.inspectWithRealData(url, {
            ...body,
            urls: [url]
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('URL_TIMEOUT')), batchTimeout)
          )
        ])
      )
    );

    const results = [];
    const errors = [];

    settledResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        errors.push({
          url: urlsToProcess[index],
          error: result.reason?.message || 'Unknown error'
        });
      }
    });

    const processingTime = Date.now() - startTime;

    return c.json(createStandardResponse(true, {
      results,
      total_processed: results.length,
      processing_time_ms: processingTime,
      scan_id: crypto.randomUUID(),
      summary: {
        total_urls: urlsToProcess.length,
        successful_scans: results.length,
        failed_scans: errors.length
      },
      errors: errors.length > 0 ? errors : undefined,
      edge_location: c.req.header('CF-Ray')?.split('-')[1] || 'unknown'
    }));

  } catch (error) {
    console.error('Batch URL inspection error:', error);
    return c.json(createStandardResponse(false, {}, {
      type: 'Batch inspection failed',
      message: error.message || 'Batch URL inspection failed',
      errorType: 'InspectionError',
      additionalData: {
        processing_time_ms: Date.now() - startTime
      }
    }), 500);
  }
});

// 404 handler for API routes
app.all('/api/*', (c) => {
  return c.json({
    success: false,
    error: 'API endpoint not found',
    message: `The endpoint ${c.req.path} does not exist`,
    available_endpoints: [
      'GET /api/status',
      'GET /api/metrics',
      'GET /api/inspect?url=<url>',
      'POST /api/inspect'
    ]
  }, 404);
});

// NO STORAGE VERSION - No Durable Objects, No KV
// Export default handler only
export default app;
