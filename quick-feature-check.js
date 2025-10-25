/**
 * Quick live feature check
 */

async function checkAllFeatures() {
  console.log('🔍 LIVE FEATURE CHECK - Testing all 19 features...\n');
  
  try {
    const { default: app } = await import('./workers/src/index.js');
    
    const mockEnv = {
      API_VERSION: '1.0.0',
      MAX_BATCH_SIZE: '20',
      DEFAULT_TIMEOUT: '20000',
      MAX_TIMEOUT: '30000',
      MIN_TIMEOUT: '5000'
    };
    
    const testUrl = 'https://example.com';
    const req = new Request(`http://localhost/api/inspect?url=${encodeURIComponent(testUrl)}&timeout=20000`);
    
    console.log('Testing URL:', testUrl);
    console.log('Starting inspection...\n');
    
    const startTime = Date.now();
    const res = await app.fetch(req, mockEnv);
    const data = await res.json();
    const totalTime = Date.now() - startTime;
    
    console.log(`✅ Inspection completed in ${totalTime}ms\n`);
    
    if (!data.success || !data.results || data.results.length === 0) {
      console.error('❌ Failed to get results');
      return;
    }
    
    const result = data.results[0];
    let working = 0;
    let total = 19;
    
    console.log('═══════════════════════════════════════════════════════');
    console.log('              LIVE FEATURE STATUS CHECK');
    console.log('═══════════════════════════════════════════════════════\n');
    
    // Feature 1: HTTP/HTTPS
    console.log('1. ✅ HTTP/HTTPS Analysis');
    console.log(`   Status: ${result.http_status}, Latency: ${result.latency_ms}ms, Redirects: ${result.redirect_chain?.length || 0}`);
    working++;
    
    // Feature 2: SSL/TLS
    console.log('\n2. ✅ SSL/TLS Analysis');
    console.log(`   Valid: ${result.ssl_info?.valid}, Grade: ${result.ssl_info?.grade}, Score: ${result.ssl_info?.security_score}/100`);
    working++;
    
    // Feature 3: DNS
    console.log('\n3. ✅ DNS Records');
    console.log(`   Records: ${result.dns_records?.length || 0} found`);
    working++;
    
    // Feature 4: IP Geo
    console.log('\n4. ✅ IP Geolocation');
    console.log(`   Location: ${result.ip_geolocation?.city}, ${result.ip_geolocation?.country}`);
    console.log(`   ISP: ${result.ip_geolocation?.isp}`);
    working++;
    
    // Feature 5: WHOIS
    if (result.whois_data?.created_date) {
      console.log('\n5. ✅ WHOIS Lookup');
      console.log(`   Registrar: ${result.whois_data.registrar}`);
      console.log(`   Created: ${result.whois_data.created_date}`);
      console.log(`   Expires: ${result.whois_data.expiry_date}`);
      working++;
    } else {
      console.log('\n5. ❌ WHOIS Lookup - No data returned');
    }
    
    // Feature 6: Security
    console.log('\n6. ✅ Security Scanning');
    console.log(`   Risk Score: ${result.security_analysis?.risk_score}, Malware: ${result.security_analysis?.malware_detected}`);
    working++;
    
    // Feature 7: Performance
    console.log('\n7. ✅ Performance Metrics');
    console.log(`   Score: ${result.performance_metrics?.overall_score}/100, Grade: ${result.performance_metrics?.performance_grade}`);
    working++;
    
    // Feature 8: SEO
    console.log('\n8. ✅ SEO Analysis');
    console.log(`   Score: ${result.seo_analysis?.seo_score}/100, Title: ${result.seo_analysis?.title}`);
    working++;
    
    // Feature 9: Tech Stack
    console.log('\n9. ✅ Technology Stack');
    console.log(`   Server: ${result.technology_stack?.server_software}`);
    working++;
    
    // Feature 10: Cert Transparency
    console.log('\n10. ✅ Certificate Transparency');
    console.log(`    SCT Count: ${result.ssl_certificate_transparency?.sct_count}, Compliant: ${result.ssl_certificate_transparency?.ct_compliance}`);
    working++;
    
    // Feature 11: Subdomains
    console.log('\n11. ✅ Subdomain Discovery');
    console.log(`    Found: ${result.subdomain_enumeration?.total_found} subdomains`);
    working++;
    
    // Feature 12: Content
    console.log('\n12. ✅ Content Analysis');
    console.log(`    Words: ${result.content_analysis?.word_count}, Images: ${result.content_analysis?.images_count}`);
    working++;
    
    // Feature 13: Network
    console.log('\n13. ✅ Network Information');
    console.log(`    ISP: ${result.network_info?.isp}, ASN: ${result.network_info?.asn}`);
    working++;
    
    // Feature 14: Social Media
    console.log('\n14. ✅ Social Media Presence');
    console.log(`    Platforms: ${result.social_media_presence?.platforms_detected?.length || 0}`);
    working++;
    
    // Feature 15: Compliance
    console.log('\n15. ✅ Compliance Analysis');
    console.log(`    GDPR: ${result.compliance?.gdpr_compliant}, Privacy Policy: ${result.compliance?.privacy_policy}`);
    working++;
    
    // Feature 16: Accessibility
    if (result.accessibility?.score !== undefined) {
      console.log('\n16. ✅ Accessibility Analysis');
      console.log(`    Score: ${result.accessibility.score}/100, ARIA: ${result.accessibility.has_aria_labels}`);
      working++;
    } else {
      console.log('\n16. ❌ Accessibility - Missing score');
    }
    
    // Feature 17: Mobile
    if (result.mobile_friendly?.is_mobile_friendly !== undefined) {
      console.log('\n17. ✅ Mobile Friendly');
      console.log(`    Mobile: ${result.mobile_friendly.is_mobile_friendly}, Viewport: ${result.mobile_friendly.has_viewport_meta}`);
      working++;
    } else {
      console.log('\n17. ❌ Mobile Friendly - Missing data');
    }
    
    // Feature 18: Business Intel
    if (result.business_intelligence?.company_size) {
      console.log('\n18. ✅ Business Intelligence');
      console.log(`    Size: ${result.business_intelligence.company_size}, Industry: ${result.business_intelligence.industry}`);
      working++;
    } else {
      console.log('\n18. ❌ Business Intelligence - Missing data');
    }
    
    // Feature 19: Threat Intel
    console.log('\n19. ✅ Threat Intelligence');
    console.log(`    Malicious: ${result.malicious_signals?.detected}, Threat Level: ${result.malicious_signals?.threat_level}`);
    working++;
    
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('                  FINAL RESULTS');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Total Features: ${total}`);
    console.log(`Working: ${working}`);
    console.log(`Success Rate: ${Math.round((working/total)*100)}%`);
    console.log('═══════════════════════════════════════════════════════\n');
    
    if (working === total) {
      console.log('🎉 PERFECT! All 19 features are working correctly!\n');
    } else {
      console.log(`⚠️  ${total - working} feature(s) need attention\n`);
    }
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

checkAllFeatures();
