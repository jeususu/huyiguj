/**
 * Cloudflare Workers Deployment Readiness Test
 * Tests all API endpoints with real URLs
 */

const TEST_URLS = [
  'https://example.com',
  'https://google.com',
  'https://github.com'
];

class DeploymentTester {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.results = {
      passed: [],
      failed: [],
      total: 0
    };
  }

  async test(name, testFn) {
    this.results.total++;
    console.log(`\n🧪 Testing: ${name}`);
    console.log('─'.repeat(60));
    
    try {
      await testFn();
      console.log(`✅ PASSED: ${name}`);
      this.results.passed.push(name);
      return true;
    } catch (error) {
      console.error(`❌ FAILED: ${name}`);
      console.error(`   Error: ${error.message}`);
      this.results.failed.push({ name, error: error.message });
      return false;
    }
  }

  async testStatusEndpoint() {
    await this.test('GET /api/status', async () => {
      const response = await fetch(`${this.baseUrl}/api/status`);
      if (!response.ok) {
        throw new Error(`Status ${response.status}`);
      }
      const data = await response.json();
      
      if (!data.success) {
        throw new Error('Response not successful');
      }
      
      console.log('   Status:', data.status);
      console.log('   Version:', data.version);
      console.log('   Features Available:', Object.keys(data.features).length);
    });
  }

  async testMetricsEndpoint() {
    await this.test('GET /api/metrics', async () => {
      const response = await fetch(`${this.baseUrl}/api/metrics`);
      if (!response.ok) {
        throw new Error(`Status ${response.status}`);
      }
      const data = await response.json();
      
      if (!data.success) {
        throw new Error('Response not successful');
      }
      
      console.log('   API Version:', data.api?.version);
      console.log('   Status:', data.api?.status);
    });
  }

  async testSingleURLInspection() {
    for (const url of TEST_URLS.slice(0, 1)) {
      await this.test(`GET /api/inspect - ${url}`, async () => {
        const response = await fetch(
          `${this.baseUrl}/api/inspect?url=${encodeURIComponent(url)}&timeout=15000`
        );
        
        if (!response.ok) {
          const error = await response.text();
          throw new Error(`Status ${response.status}: ${error}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
          throw new Error('Response not successful');
        }
        
        if (!data.results || data.results.length === 0) {
          throw new Error('No results returned');
        }
        
        const result = data.results[0];
        console.log('   URL:', result.url);
        console.log('   HTTP Status:', result.http_status);
        console.log('   IP Address:', result.ip_address);
        console.log('   SSL Valid:', result.ssl_valid);
        console.log('   DNS Records:', result.dns_records?.length || 0);
        console.log('   Processing Time:', data.processing_time_ms, 'ms');
      });
    }
  }

  async testBatchURLInspection() {
    await this.test('POST /api/inspect (Batch)', async () => {
      const response = await fetch(`${this.baseUrl}/api/inspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          urls: TEST_URLS,
          timeout: 15000,
          deep_scan: false,
          check_subdomains: false
        })
      });
      
      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Status ${response.status}: ${error}`);
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error('Response not successful');
      }
      
      console.log('   URLs Processed:', data.total_processed);
      console.log('   Processing Time:', data.processing_time_ms, 'ms');
      console.log('   Successful:', data.summary?.successful_scans || 0);
      console.log('   Failed:', data.summary?.failed_scans || 0);
    });
  }

  async test404Handler() {
    await this.test('404 Handler', async () => {
      const response = await fetch(`${this.baseUrl}/api/nonexistent`);
      
      if (response.status !== 404) {
        throw new Error(`Expected 404, got ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.success) {
        throw new Error('404 endpoint should not return success');
      }
      
      console.log('   Error Message:', data.message);
    });
  }

  async testInvalidURL() {
    await this.test('Invalid URL Validation', async () => {
      const response = await fetch(
        `${this.baseUrl}/api/inspect?url=http://localhost:3000`
      );
      
      if (response.status !== 400) {
        throw new Error(`Expected 400, got ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.success) {
        throw new Error('Invalid URL should be rejected');
      }
      
      console.log('   Validation Error:', data.message);
    });
  }

  async testFeatureToggles() {
    await this.test('Feature Toggles', async () => {
      const response = await fetch(
        `${this.baseUrl}/api/inspect?url=${encodeURIComponent('https://example.com')}&` +
        `deep_scan=false&check_subdomains=false&include_whois=false&dns_analysis=false`
      );
      
      if (!response.ok) {
        throw new Error(`Status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error('Response not successful');
      }
      
      console.log('   Features disabled correctly');
      console.log('   Processing Time:', data.processing_time_ms, 'ms');
    });
  }

  printSummary() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${this.results.total}`);
    console.log(`✅ Passed: ${this.results.passed.length}`);
    console.log(`❌ Failed: ${this.results.failed.length}`);
    console.log(`Success Rate: ${((this.results.passed.length / this.results.total) * 100).toFixed(1)}%`);
    
    if (this.results.failed.length > 0) {
      console.log('\n❌ Failed Tests:');
      this.results.failed.forEach(({ name, error }) => {
        console.log(`   - ${name}: ${error}`);
      });
    }
    
    console.log('\n' + '='.repeat(60));
    
    if (this.results.failed.length === 0) {
      console.log('✅ All tests passed! Ready for Cloudflare deployment.');
    } else {
      console.log('⚠️  Some tests failed. Please review before deploying.');
    }
    console.log('='.repeat(60));
  }

  async runAll() {
    console.log('🚀 Starting Cloudflare Workers API Tests');
    console.log(`📍 Base URL: ${this.baseUrl}`);
    console.log('='.repeat(60));

    await this.testStatusEndpoint();
    await this.testMetricsEndpoint();
    await this.testSingleURLInspection();
    await this.testBatchURLInspection();
    await this.test404Handler();
    await this.testInvalidURL();
    await this.testFeatureToggles();
    
    this.printSummary();
  }
}

// Main execution
const baseUrl = process.argv[2] || 'http://localhost:8787';

console.log(`
╔══════════════════════════════════════════════════════════╗
║   URL Inspector API - Deployment Readiness Test         ║
╚══════════════════════════════════════════════════════════╝
`);

const tester = new DeploymentTester(baseUrl);
tester.runAll().catch(error => {
  console.error('\n💥 Fatal Error:', error);
  process.exit(1);
});
