/**
 * Simple test server to verify Cloudflare Worker code locally
 * This simulates the Cloudflare Workers environment
 */

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Simple HTTP server on port 5000
const port = 5000;

async function startServer() {
  try {
    // Use Hono app directly from the worker
    const { default: app } = await import('./workers/src/index.js');
    
    // Serve the Hono app
    const server = Bun.serve({
      port: port,
      fetch: (req) => {
        // Mock Cloudflare environment
        const mockEnv = {
          API_VERSION: '1.0.0',
          MAX_BATCH_SIZE: '20',
          DEFAULT_TIMEOUT: '12000',
          MAX_TIMEOUT: '30000',
          MIN_TIMEOUT: '5000'
        };
        
        return app.fetch(req, mockEnv);
      }
    });
    
    console.log(`✅ Test server running on http://localhost:${port}`);
    console.log(`\nAvailable endpoints:`);
    console.log(`  GET  http://localhost:${port}/api/status`);
    console.log(`  GET  http://localhost:${port}/api/metrics`);
    console.log(`  GET  http://localhost:${port}/api/inspect?url=https://example.com`);
    console.log(`  POST http://localhost:${port}/api/inspect\n`);
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    console.error(error);
    process.exit(1);
  }
}

startServer();
