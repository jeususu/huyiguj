/**
 * Helper utilities for Cloudflare Workers
 */

/**
 * Validate URL for security (SSRF protection)
 */
export function validateUrl(url) {
  try {
    const parsed = new URL(url);
    
    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return {
        allowed: false,
        reason: 'Only HTTP and HTTPS protocols are supported'
      };
    }
    
    // Block private IP ranges (SSRF protection)
    const hostname = parsed.hostname.toLowerCase();
    
    // Block localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return {
        allowed: false,
        reason: 'Localhost URLs are not allowed for security reasons'
      };
    }
    
    // Block private IP ranges
    const privateIpPatterns = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^169\.254\./,
      /^fc00:/,
      /^fe80:/
    ];
    
    for (const pattern of privateIpPatterns) {
      if (pattern.test(hostname)) {
        return {
          allowed: false,
          reason: 'Private IP addresses are not allowed for security reasons'
        };
      }
    }
    
    // Block .local domains
    if (hostname.endsWith('.local')) {
      return {
        allowed: false,
        reason: '.local domains are not allowed for security reasons'
      };
    }
    
    return { allowed: true };
  } catch (error) {
    return {
      allowed: false,
      reason: 'Invalid URL format'
    };
  }
}

/**
 * Generate a unique request ID
 */
export function generateRequestId() {
  return crypto.randomUUID();
}

/**
 * Fetch with timeout
 */
export async function fetchWithTimeout(url, options = {}, timeout = 15000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}

/**
 * DNS-over-HTTPS resolver using Cloudflare 1.1.1.1
 */
export async function resolveDNS(hostname, recordType = 'A') {
  try {
    const response = await fetch(
      `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=${recordType}`,
      {
        headers: {
          'Accept': 'application/dns-json'
        }
      }
    );
    
    if (!response.ok) {
      throw new Error(`DNS query failed: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.Answer || data.Answer.length === 0) {
      return [];
    }
    
    return data.Answer.map(answer => ({
      type: recordType,
      value: answer.data,
      ttl: answer.TTL
    }));
  } catch (error) {
    console.error(`DNS resolution failed for ${hostname}:`, error);
    return [];
  }
}

/**
 * Get cached data from KV with fallback
 */
export async function getCached(kv, key, ttl, fetchFn) {
  // Try to get from cache
  const cached = await kv.get(key, 'json');
  if (cached && cached.timestamp && (Date.now() - cached.timestamp) < ttl) {
    return cached.data;
  }
  
  // Fetch fresh data
  try {
    const fresh = await fetchFn();
    
    // Cache the result
    await kv.put(key, JSON.stringify({
      data: fresh,
      timestamp: Date.now()
    }), {
      expirationTtl: Math.floor(ttl / 1000) // Convert to seconds
    });
    
    return fresh;
  } catch (error) {
    // If fetch fails but we have stale cache, return it
    if (cached && cached.data) {
      return cached.data;
    }
    throw error;
  }
}

/**
 * Parse HTML to extract meta tags (lightweight alternative to Cheerio)
 */
export function parseMetaTags(html) {
  const meta = {
    title: '',
    description: '',
    keywords: ''
  };
  
  // Extract title
  const titleMatch = html.match(/<title>(.*?)<\/title>/i);
  if (titleMatch) {
    meta.title = titleMatch[1].trim();
  }
  
  // Extract meta description
  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i);
  if (descMatch) {
    meta.description = descMatch[1].trim();
  }
  
  // Extract meta keywords
  const keywordsMatch = html.match(/<meta[^>]*name=["']keywords["'][^>]*content=["']([^"']*)["']/i);
  if (keywordsMatch) {
    meta.keywords = keywordsMatch[1].trim();
  }
  
  return meta;
}

/**
 * Extract domain from URL
 */
export function extractDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (error) {
    return null;
  }
}

/**
 * Calculate security grade from score
 */
export function calculateSecurityGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
