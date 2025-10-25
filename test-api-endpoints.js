/**
 * Comprehensive API Endpoint Testing
 * Tests all endpoints with real requests and validates responses
 */

import { Hono } from 'hono';

// Import the worker app
async function runTests() {
  console.log('🧪 Starting comprehensive API endpoint tests...\n');
  
  try {
    // Import the app
    const { default: app } = await import('./workers/src/index.js');
    
    // Mock environment
    const mockEnv = {
      API_VERSION: '1.0.0',
      MAX_BATCH_SIZE: '20',
      DEFAULT_TIMEOUT: '12000',
      MAX_TIMEOUT: '30000',
      MIN_TIMEOUT: '5000'
    };
    
    let passedTests = 0;
    let failedTests = 0;
    
    // TEST 1: GET /api/status
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 1: GET /api/status');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/status');
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Response:', JSON.stringify(data, null, 2));
      
      if (res.status === 200 && 
          data.success === true && 
          data.status === 'healthy' &&
          data.features &&
          data.limits) {
        console.log('✅ PASSED: /api/status returns correct data\n');
        passedTests++;
      } else {
        console.log('❌ FAILED: /api/status response invalid\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message, '\n');
      failedTests++;
    }
    
    // TEST 2: GET /api/metrics
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 2: GET /api/metrics');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/metrics');
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Response:', JSON.stringify(data, null, 2));
      
      if (res.status === 200 && 
          data.success === true &&
          data.system &&
          data.api) {
        console.log('✅ PASSED: /api/metrics returns correct data\n');
        passedTests++;
      } else {
        console.log('❌ FAILED: /api/metrics response invalid\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message, '\n');
      failedTests++;
    }
    
    // TEST 3: GET /api/inspect without URL parameter (should fail)
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 3: GET /api/inspect (no URL - should fail)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/inspect');
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Response:', JSON.stringify(data, null, 2));
      
      if (res.status === 400 && 
          data.success === false &&
          data.message.includes('URL')) {
        console.log('✅ PASSED: Validation working - rejects missing URL\n');
        passedTests++;
      } else {
        console.log('❌ FAILED: Should return 400 error for missing URL\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message, '\n');
      failedTests++;
    }
    
    // TEST 4: GET /api/inspect with real URL
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 4: GET /api/inspect?url=https://example.com');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/inspect?url=https://example.com');
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Processing Time:', data.processing_time_ms, 'ms');
      
      if (data.success && data.results && data.results.length > 0) {
        const result = data.results[0];
        console.log('\n📊 Inspection Results:');
        console.log('  URL:', result.url);
        console.log('  Final URL:', result.final_url);
        console.log('  HTTP Status:', result.http_status);
        console.log('  IP Address:', result.ip_address);
        console.log('  Latency:', result.latency_ms, 'ms');
        
        if (result.ip_geolocation) {
          console.log('  📍 Geolocation:');
          console.log('    Country:', result.ip_geolocation.country);
          console.log('    City:', result.ip_geolocation.city);
          console.log('    ISP:', result.ip_geolocation.isp);
        }
        
        if (result.ssl_info) {
          console.log('  🔒 SSL Info:');
          console.log('    Valid:', result.ssl_info.valid);
          console.log('    Issuer:', result.ssl_info.issuer);
          console.log('    Grade:', result.ssl_info.grade);
        }
        
        if (result.performance_metrics) {
          console.log('  ⚡ Performance:');
          console.log('    Load Time:', result.performance_metrics.total_load_time, 'ms');
          console.log('    Score:', result.performance_metrics.performance_score || result.performance_metrics.overall_score);
        }
        
        if (result.technology_stack) {
          console.log('  🛠️ Technology:');
          console.log('    Server:', result.technology_stack.server_software);
          console.log('    Framework:', result.technology_stack.framework);
        }
        
        if (result.seo_analysis) {
          console.log('  🔍 SEO:');
          console.log('    SEO Score:', result.seo_analysis.seo_score);
          console.log('    Has Sitemap:', result.seo_analysis.has_sitemap);
        }
        
        if (res.status === 200 && 
            data.success === true &&
            result.url &&
            result.http_status) {
          console.log('\n✅ PASSED: /api/inspect returns real inspection data\n');
          passedTests++;
        } else {
          console.log('\n❌ FAILED: Response missing expected fields\n');
          failedTests++;
        }
      } else {
        console.log('Response:', JSON.stringify(data, null, 2));
        console.log('\n❌ FAILED: No results returned\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message);
      console.log('Stack:', error.stack, '\n');
      failedTests++;
    }
    
    // TEST 5: POST /api/inspect (batch processing)
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 5: POST /api/inspect (batch)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urls: ['https://example.com', 'https://google.com']
        })
      });
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Total Processed:', data.total_processed);
      console.log('Processing Time:', data.processing_time_ms, 'ms');
      
      if (data.summary) {
        console.log('\n📊 Batch Summary:');
        console.log('  Total URLs:', data.summary.total_urls);
        console.log('  Successful:', data.summary.successful_scans);
        console.log('  Failed:', data.summary.failed_scans);
      }
      
      if (res.status === 200 && 
          data.success === true &&
          data.results &&
          data.results.length > 0 &&
          data.summary) {
        console.log('\n✅ PASSED: Batch processing works correctly\n');
        passedTests++;
      } else {
        console.log('Response:', JSON.stringify(data, null, 2));
        console.log('\n❌ FAILED: Batch processing failed\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message, '\n');
      failedTests++;
    }
    
    // TEST 6: Invalid endpoint (404)
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('TEST 6: GET /api/invalid (404 handler)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      const req = new Request('http://localhost/api/invalid');
      const res = await app.fetch(req, mockEnv);
      const data = await res.json();
      
      console.log('Status Code:', res.status);
      console.log('Response:', JSON.stringify(data, null, 2));
      
      if (res.status === 404 && 
          data.success === false &&
          data.available_endpoints) {
        console.log('✅ PASSED: 404 handler working correctly\n');
        passedTests++;
      } else {
        console.log('❌ FAILED: 404 handler not working\n');
        failedTests++;
      }
    } catch (error) {
      console.log('❌ FAILED:', error.message, '\n');
      failedTests++;
    }
    
    // Final Summary
    console.log('\n');
    console.log('═══════════════════════════════════════════');
    console.log('           TEST SUMMARY');
    console.log('═══════════════════════════════════════════');
    console.log(`✅ Passed: ${passedTests}/6`);
    console.log(`❌ Failed: ${failedTests}/6`);
    console.log('═══════════════════════════════════════════\n');
    
    if (failedTests === 0) {
      console.log('🎉 ALL TESTS PASSED! API is fully functional.\n');
    } else {
      console.log('⚠️  Some tests failed. Review the errors above.\n');
    }
    
  } catch (error) {
    console.error('❌ Test suite failed to run:', error.message);
    console.error(error.stack);
  }
}

runTests();
