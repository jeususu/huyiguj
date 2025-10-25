/**
 * Direct WHOIS test
 */

import whois from 'whois';

console.log('Testing WHOIS package directly...\n');

whois.lookup('example.com', (err, data) => {
  if (err) {
    console.error('❌ WHOIS Error:', err.message);
    return;
  }
  
  console.log('✅ WHOIS Data Retrieved Successfully!\n');
  console.log('Raw WHOIS Data (first 500 chars):');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(data.substring(0, 500));
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  // Parse key fields
  const lines = data.split('\n');
  let registrar = 'Unknown';
  let createdDate = null;
  let expiryDate = null;
  
  for (const line of lines) {
    const lower = line.toLowerCase();
    
    if (lower.includes('registrar:') && registrar === 'Unknown') {
      registrar = line.split(':')[1]?.trim() || 'Unknown';
    }
    
    if (lower.includes('creation date:') && !createdDate) {
      createdDate = line.split(':').slice(1).join(':').trim();
    }
    
    if ((lower.includes('expiry date:') || lower.includes('registry expiry')) && !expiryDate) {
      expiryDate = line.split(':').slice(1).join(':').trim();
    }
  }
  
  console.log('📊 Parsed WHOIS Information:');
  console.log(`   Registrar: ${registrar}`);
  console.log(`   Created: ${createdDate}`);
  console.log(`   Expires: ${expiryDate}`);
  console.log('\n✅ WHOIS package is working correctly!');
});
