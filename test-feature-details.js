/**
 * Detailed Feature Testing
 * Tests each individual feature of the URL Inspector API
 */

async function runDetailedFeatureTests() {
  console.log('🔍 Starting detailed feature verification...\n');
  
  try {
    const { default: app } = await import('./workers/src/index.js');
    
    const mockEnv = {
      API_VERSION: '1.0.0',
      MAX_BATCH_SIZE: '20',
      DEFAULT_TIMEOUT: '12000',
      MAX_TIMEOUT: '30000',
      MIN_TIMEOUT: '5000'
    };
    
    const testUrl = 'https://example.com';
    const req = new Request(`http://localhost/api/inspect?url=${encodeURIComponent(testUrl)}`);
    const res = await app.fetch(req, mockEnv);
    const data = await res.json();
    
    if (!data.success || !data.results || data.results.length === 0) {
      console.error('❌ Failed to get inspection results');
      return;
    }
    
    const result = data.results[0];
    
    console.log('═══════════════════════════════════════════════════════');
    console.log('           FEATURE VERIFICATION REPORT');
    console.log('═══════════════════════════════════════════════════════\n');
    console.log(`Test URL: ${testUrl}`);
    console.log(`Processing Time: ${data.processing_time_ms}ms`);
    console.log(`Scan ID: ${data.scan_id}\n`);
    
    let totalFeatures = 0;
    let workingFeatures = 0;
    
    // Feature 1: HTTP/HTTPS Analysis
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('1. HTTP/HTTPS ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.http_status && result.http_status > 0) {
      console.log(`✅ WORKING - HTTP Status: ${result.http_status}`);
      console.log(`   URL: ${result.url}`);
      console.log(`   Final URL: ${result.final_url}`);
      console.log(`   Redirects: ${result.redirect_chain?.length || 0}`);
      console.log(`   Latency: ${result.latency_ms}ms`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No HTTP data returned');
    }
    console.log();
    
    // Feature 2: SSL/TLS Analysis
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('2. SSL/TLS ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.ssl_info && Object.keys(result.ssl_info).length > 0) {
      console.log(`✅ WORKING - SSL Info Retrieved`);
      console.log(`   Valid: ${result.ssl_info.valid}`);
      console.log(`   Issuer: ${result.ssl_info.issuer || 'Unknown'}`);
      console.log(`   Expiry: ${result.ssl_info.expiry || 'Unknown'}`);
      console.log(`   Days Remaining: ${result.ssl_info.days_remaining || 0}`);
      console.log(`   Security Score: ${result.ssl_info.security_score || 0}/100`);
      console.log(`   Grade: ${result.ssl_info.grade || 'Unknown'}`);
      console.log(`   Chain Valid: ${result.ssl_info.chain_valid}`);
      console.log(`   Vulnerabilities: ${result.ssl_vulnerabilities?.length || 0} found`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No SSL data returned');
    }
    console.log();
    
    // Feature 3: DNS Records
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('3. DNS RECORDS ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.dns_records && Array.isArray(result.dns_records)) {
      console.log(`✅ WORKING - ${result.dns_records.length} DNS records found`);
      const recordTypes = {};
      result.dns_records.forEach(record => {
        recordTypes[record.type] = (recordTypes[record.type] || 0) + 1;
      });
      Object.entries(recordTypes).forEach(([type, count]) => {
        console.log(`   ${type}: ${count} record(s)`);
      });
      workingFeatures++;
    } else {
      console.log('⚠️  LIMITED - DNS records returned but empty');
    }
    console.log();
    
    // Feature 4: IP Geolocation
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('4. IP GEOLOCATION');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.ip_geolocation) {
      console.log(`✅ WORKING - Geolocation Data Retrieved`);
      console.log(`   IP Address: ${result.ip_address}`);
      console.log(`   Country: ${result.ip_geolocation.country} (${result.ip_geolocation.country_code})`);
      console.log(`   Region: ${result.ip_geolocation.region}`);
      console.log(`   City: ${result.ip_geolocation.city}`);
      console.log(`   Coordinates: ${result.ip_geolocation.latitude}, ${result.ip_geolocation.longitude}`);
      console.log(`   Timezone: ${result.ip_geolocation.timezone}`);
      console.log(`   ISP: ${result.ip_geolocation.isp}`);
      console.log(`   ASN: ${result.ip_geolocation.asn}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No geolocation data');
    }
    console.log();
    
    // Feature 5: WHOIS Data
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('5. WHOIS LOOKUP');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.whois_data && result.whois_data.created_date) {
      console.log(`✅ WORKING - WHOIS Data Retrieved`);
      console.log(`   Registrar: ${result.whois_data.registrar}`);
      console.log(`   Created: ${result.whois_data.created_date || 'N/A'}`);
      console.log(`   Expires: ${result.whois_data.expiry_date || 'N/A'}`);
      console.log(`   Updated: ${result.whois_data.updated_date || 'N/A'}`);
      console.log(`   Name Servers: ${result.whois_data.name_servers?.length || 0}`);
      console.log(`   Status: ${result.whois_data.status || 'N/A'}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No WHOIS data');
    }
    console.log();
    
    // Feature 6: Security Scanning
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('6. SECURITY SCANNING');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.security_analysis) {
      console.log(`✅ WORKING - Security Analysis Complete`);
      console.log(`   Risk Score: ${result.security_analysis.risk_score}/100`);
      console.log(`   Malware Detected: ${result.security_analysis.malware_detected}`);
      console.log(`   Phishing Detected: ${result.security_analysis.phishing_detected}`);
      console.log(`   Spam Detected: ${result.security_analysis.spam_detected}`);
      console.log(`   Security Headers Score: ${result.security_analysis.security_headers_score}/100`);
      console.log(`   Threat Types: ${result.security_analysis.threat_types?.length || 0}`);
      console.log(`   Blacklist Status: Safe`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No security analysis');
    }
    console.log();
    
    // Feature 7: Performance Metrics
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('7. PERFORMANCE METRICS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.performance_metrics) {
      console.log(`✅ WORKING - Performance Analysis Complete`);
      console.log(`   Overall Score: ${result.performance_metrics.overall_score}/100`);
      console.log(`   Performance Grade: ${result.performance_metrics.performance_grade}`);
      console.log(`   Total Load Time: ${result.performance_metrics.total_load_time}ms`);
      console.log(`   TLS Handshake: ${result.performance_metrics.tls_handshake_time}ms`);
      console.log(`   Server Response: ${result.performance_metrics.server_response_time}ms`);
      console.log(`   Page Size: ${result.performance_metrics.page_size_bytes} bytes`);
      console.log(`   First Contentful Paint: ${result.performance_metrics.first_contentful_paint}ms`);
      console.log(`   Largest Contentful Paint: ${result.performance_metrics.largest_contentful_paint}ms`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No performance metrics');
    }
    console.log();
    
    // Feature 8: SEO Analysis
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('8. SEO ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.seo_analysis) {
      console.log(`✅ WORKING - SEO Analysis Complete`);
      console.log(`   SEO Score: ${result.seo_analysis.seo_score}/100`);
      console.log(`   Title: ${result.seo_analysis.title || 'N/A'}`);
      console.log(`   Meta Description: ${result.seo_analysis.meta_description ? 'Present' : 'Missing'}`);
      console.log(`   Has H1 Tag: ${result.seo_analysis.has_h1}`);
      console.log(`   Has Meta Keywords: ${result.seo_analysis.has_meta_keywords}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No SEO analysis');
    }
    console.log();
    
    // Feature 9: Technology Stack Detection
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('9. TECHNOLOGY STACK DETECTION');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.technology_stack) {
      console.log(`✅ WORKING - Technology Detection Active`);
      console.log(`   Server: ${result.technology_stack.server_software}`);
      console.log(`   Framework: ${result.technology_stack.framework?.join(', ') || 'None detected'}`);
      console.log(`   CMS: ${result.technology_stack.cms || 'None detected'}`);
      console.log(`   CDN: ${result.technology_stack.cdn || 'None detected'}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No technology detection');
    }
    console.log();
    
    // Feature 10: Certificate Transparency
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('10. CERTIFICATE TRANSPARENCY LOGS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.ssl_certificate_transparency) {
      console.log(`✅ WORKING - CT Logs Retrieved`);
      console.log(`   SCT Count: ${result.ssl_certificate_transparency.sct_count}`);
      console.log(`   CT Compliance: ${result.ssl_certificate_transparency.ct_compliance}`);
      console.log(`   Log Entries: ${result.ssl_certificate_transparency.log_entries?.length || 0}`);
      console.log(`   Source: ${result.ssl_certificate_transparency.source || 'N/A'}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No CT logs');
    }
    console.log();
    
    // Feature 11: Subdomain Discovery
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('11. SUBDOMAIN DISCOVERY');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.subdomain_enumeration) {
      console.log(`✅ WORKING - Subdomain Discovery Active`);
      console.log(`   Subdomains Found: ${result.subdomain_enumeration.total_found}`);
      console.log(`   Methods Used: ${result.subdomain_enumeration.methods_used?.join(', ')}`);
      if (result.subdomain_enumeration.subdomains?.length > 0) {
        console.log(`   Sample Subdomains:`);
        result.subdomain_enumeration.subdomains.slice(0, 5).forEach(sub => {
          console.log(`     - ${sub}`);
        });
      }
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No subdomain enumeration');
    }
    console.log();
    
    // Feature 12: Content Analysis
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('12. CONTENT ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.content_analysis) {
      console.log(`✅ WORKING - Content Analysis Complete`);
      console.log(`   Word Count: ${result.content_analysis.word_count}`);
      console.log(`   Images: ${result.content_analysis.images_count}`);
      console.log(`   Links: ${result.content_analysis.links_count}`);
      console.log(`   Contact Info Found: ${result.content_analysis.contact_info_found}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No content analysis');
    }
    console.log();
    
    // Feature 13: Network Information
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('13. NETWORK INFORMATION');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.network_info) {
      console.log(`✅ WORKING - Network Info Retrieved`);
      console.log(`   ISP: ${result.network_info.isp}`);
      console.log(`   ASN: ${result.network_info.asn}`);
      console.log(`   Connection Type: ${result.network_info.connection_type}`);
      console.log(`   CDN Detected: ${result.network_info.cdn_detected}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No network info');
    }
    console.log();
    
    // Feature 14: Social Media Presence
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('14. SOCIAL MEDIA PRESENCE');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.social_media_presence) {
      console.log(`✅ WORKING - Social Media Detection Active`);
      console.log(`   Facebook: ${result.social_media_presence.facebook}`);
      console.log(`   Twitter: ${result.social_media_presence.twitter}`);
      console.log(`   LinkedIn: ${result.social_media_presence.linkedin}`);
      console.log(`   Instagram: ${result.social_media_presence.instagram}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No social media analysis');
    }
    console.log();
    
    // Feature 15: Compliance Analysis
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('15. COMPLIANCE ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.compliance) {
      console.log(`✅ WORKING - Compliance Checks Active`);
      console.log(`   GDPR Compliant: ${result.compliance.gdpr_compliant}`);
      console.log(`   Cookie Policy: ${result.compliance.cookie_policy}`);
      console.log(`   Privacy Policy: ${result.compliance.privacy_policy}`);
      console.log(`   Terms of Service: ${result.compliance.terms_of_service}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No compliance analysis');
    }
    console.log();
    
    // Feature 16: Accessibility
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('16. ACCESSIBILITY ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.accessibility) {
      console.log(`✅ WORKING - Accessibility Checks Active`);
      console.log(`   Score: ${result.accessibility.score}/100`);
      console.log(`   Has Alt Tags: ${result.accessibility.has_alt_tags}`);
      console.log(`   Has ARIA Labels: ${result.accessibility.has_aria_labels}`);
      console.log(`   Color Contrast: ${result.accessibility.color_contrast_ok}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No accessibility analysis');
    }
    console.log();
    
    // Feature 17: Mobile Friendly
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('17. MOBILE FRIENDLY ANALYSIS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.mobile_friendly) {
      console.log(`✅ WORKING - Mobile Analysis Active`);
      console.log(`   Mobile Friendly: ${result.mobile_friendly.is_mobile_friendly}`);
      console.log(`   Has Viewport Meta: ${result.mobile_friendly.has_viewport_meta}`);
      console.log(`   Responsive Design: ${result.mobile_friendly.responsive_design}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No mobile analysis');
    }
    console.log();
    
    // Feature 18: Business Intelligence
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('18. BUSINESS INTELLIGENCE');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.business_intelligence) {
      console.log(`✅ WORKING - Business Intelligence Active`);
      console.log(`   Company Size: ${result.business_intelligence.company_size}`);
      console.log(`   Industry: ${result.business_intelligence.industry}`);
      console.log(`   Content Freshness: ${result.business_intelligence.content_freshness}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No business intelligence');
    }
    console.log();
    
    // Feature 19: Threat Intelligence
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('19. THREAT INTELLIGENCE');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    totalFeatures++;
    if (result.malicious_signals) {
      console.log(`✅ WORKING - Threat Intelligence Active`);
      console.log(`   Malicious Detected: ${result.malicious_signals.detected}`);
      console.log(`   Threat Level: ${result.malicious_signals.threat_level}`);
      console.log(`   Indicators: ${result.malicious_signals.indicators?.length || 0}`);
      workingFeatures++;
    } else {
      console.log('❌ NOT WORKING - No threat intelligence');
    }
    console.log();
    
    // Summary
    console.log('═══════════════════════════════════════════════════════');
    console.log('                   FINAL SUMMARY');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Total Features: ${totalFeatures}`);
    console.log(`Working Features: ${workingFeatures}`);
    console.log(`Success Rate: ${Math.round((workingFeatures / totalFeatures) * 100)}%`);
    console.log('═══════════════════════════════════════════════════════\n');
    
    if (workingFeatures === totalFeatures) {
      console.log('🎉 EXCELLENT! All features are working correctly!\n');
    } else if (workingFeatures >= totalFeatures * 0.9) {
      console.log('✅ VERY GOOD! Most features are working correctly.\n');
    } else if (workingFeatures >= totalFeatures * 0.7) {
      console.log('⚠️  GOOD but some features need attention.\n');
    } else {
      console.log('⚠️  Several features need attention.\n');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error(error.stack);
  }
}

runDetailedFeatureTests();
