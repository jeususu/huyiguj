/**
 * Rate Limiter Durable Object
 * Implements per-IP rate limiting with automatic cleanup
 */

export class RateLimiter {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    
    if (url.pathname === '/check') {
      return this.checkRateLimit();
    } else if (url.pathname === '/increment') {
      return this.incrementCounter();
    }
    
    return new Response('Not found', { status: 404 });
  }

  async checkRateLimit() {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxRequests = 20; // 20 requests per minute
    
    const currentCount = await this.state.storage.get('count') || 0;
    const resetTime = await this.state.storage.get('resetTime') || now + windowMs;
    
    // Check if window has expired
    if (now > resetTime) {
      // Reset the counter
      await this.state.storage.put('count', 1);
      await this.state.storage.put('resetTime', now + windowMs);
      
      // Set alarm for cleanup
      await this.state.storage.setAlarm(now + windowMs);
      
      return new Response('OK', { 
        status: 200,
        headers: {
          'X-RateLimit-Limit': maxRequests.toString(),
          'X-RateLimit-Remaining': (maxRequests - 1).toString(),
          'X-RateLimit-Reset': Math.floor((now + windowMs) / 1000).toString()
        }
      });
    }
    
    // Check if rate limit exceeded
    if (currentCount >= maxRequests) {
      const retryAfter = Math.ceil((resetTime - now) / 1000);
      return new Response('Rate limit exceeded', { 
        status: 429,
        headers: {
          'Retry-After': retryAfter.toString(),
          'X-RateLimit-Limit': maxRequests.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.floor(resetTime / 1000).toString()
        }
      });
    }
    
    // Increment counter
    await this.state.storage.put('count', currentCount + 1);
    
    return new Response('OK', { 
      status: 200,
      headers: {
        'X-RateLimit-Limit': maxRequests.toString(),
        'X-RateLimit-Remaining': (maxRequests - currentCount - 1).toString(),
        'X-RateLimit-Reset': Math.floor(resetTime / 1000).toString()
      }
    });
  }

  async alarm() {
    // Clean up expired counters
    await this.state.storage.deleteAll();
  }
}
