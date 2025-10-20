# JWT Authentication Security Lab
# Mohamed Osama 2305180
This lab demonstrates secure vs vulnerable JWT authentication implementations, showcasing common JWT security issues and their proper mitigations.

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- npm
- Wireshark (for traffic analysis)

### Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Initialize the database:**
   ```bash
   npm run init-db
   ```

3. **Start the servers:**
   ```bash
   # Start vulnerable server (port 1234)
   npm run start-vuln
   
   # Start secure server (port 1235) 
   npm run start-secure
   
   # Or start secure server by default
   npm start
   ```

4. **Access the application:**
   - Vulnerable server: http://localhost:1234
   - Secure server: http://localhost:1235

## 🔐 Environment Configuration

### Required: .env File Setup

**CRITICAL:** Copy the provided `.env` file and ensure all secrets are properly configured:

```bash
# Copy the template
cp .env.example .env  # (if available)
# OR manually create .env with the provided template
```

### Secret Generation

The JWT secrets in this lab were generated using Node.js crypto module:

```javascript
// Generate secure random secrets (64 bytes = 128 hex characters)
const crypto = require('crypto');
const accessSecret = crypto.randomBytes(64).toString('hex');
const refreshSecret = crypto.randomBytes(64).toString('hex');
```

**Current secrets in .env:**
- `ACCESS_SECRET`: 128-character hex string for access tokens
- `REFRESH_SECRET`: Different 128-character hex string for refresh tokens
- `WEAK_SECRET`: Intentionally weak secret for vulnerable server demo

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULN_PORT` | Vulnerable server port | 1234 |
| `SECURE_PORT` | Secure server port | 1235 |
| `DB_PATH` | SQLite database path | ./users.db |
| `ACCESS_SECRET` | Access token signing secret | **REQUIRED** |
| `REFRESH_SECRET` | Refresh token signing secret | **REQUIRED** |
| `WEAK_SECRET` | Weak secret for vulnerable server | weak-secret-lab-only |
| `JWT_ISSUER` | JWT issuer claim | jwt-lab-secure |
| `JWT_AUDIENCE` | JWT audience claim | jwt-lab-client |
| `ACCESS_TOKEN_LIFETIME` | Access token expiry | 15m |
| `REFRESH_TOKEN_LIFETIME` | Refresh token expiry | 7d |

## 🛡️ Security Features

### Secure Server (Port 1235)

#### ✅ Implemented Security Measures

1. **Environment-based Configuration**
   - All secrets stored in `.env` file
   - No hardcoded credentials in source code
   - Environment validation on startup

2. **Strong Token Claims & Verification**
   - **Issuer (`iss`)**: `jwt-lab-secure`
   - **Audience (`aud`)**: `jwt-lab-client`
   - **Algorithm**: Strictly `HS256` only
   - **Expiry**: 15 minutes for access tokens
   - **Verification**: All claims validated on every request

3. **Refresh Token Strategy**
   - **Token Rotation**: Old refresh tokens invalidated on use
   - **Separate Secret**: Different secret from access tokens
   - **HttpOnly Cookies**: Refresh tokens not accessible via JavaScript
   - **Server-side Storage**: Refresh token IDs tracked in memory
   - **Database Role Lookup**: User roles fetched from DB for new access tokens

4. **CORS Protection**
   - Restricted to specific origins
   - Credentials support for cookie-based auth
   - Preflight request handling

#### 🔒 Token Structure

**Access Token Payload:**
```json
{
  "sub": "username",
  "role": "admin|user", 
  "iss": "jwt-lab-secure",
  "aud": "jwt-lab-client",
  "iat": 1234567890,
  "exp": 1234567890
}
```

**Refresh Token Payload:**
```json
{
  "sub": "username",
  "tid": "random_token_id",
  "iss": "jwt-lab-secure", 
  "aud": "jwt-lab-client",
  "iat": 1234567890,
  "exp": 1234567890
}
```

### Vulnerable Server (Port 1234)

#### ⚠️ Intentionally Vulnerable Features

1. **Weak Secret**: `weak-secret-lab-only` (easily guessable)
2. **Long Expiry**: 7 days for access tokens
3. **Algorithm None Attack**: Accepts `{"alg":"none"}` tokens
4. **No Claim Verification**: Missing issuer/audience validation
5. **localStorage Storage**: Tokens accessible via JavaScript

## 🎯 Attack Demonstrations

### Attack 1: Algorithm None Attack

**Target**: Vulnerable server (port 1234)

1. **Get a valid token** by logging in normally
2. **Decode the token** using the "Whoami" button
3. **Modify the header** to `{"alg":"none"}`
4. **Remove the signature** (third part of JWT)
5. **Send the modified token** to `/admin` endpoint

**Expected Result**: Access granted with modified token

**Protection**: Secure server rejects `alg: none` tokens

### Attack 2: Weak Secret Token Forgery

**Target**: Vulnerable server (port 1234)

1. **Use known weak secret**: `weak-secret-lab-only`
2. **Create forged token** with admin role
3. **Send forged token** to `/admin` endpoint

**Expected Result**: Access granted with forged token

**Protection**: Secure server uses cryptographically strong secrets

### Attack 3: Token Theft Simulation

**Target**: Both servers

1. **Login normally** and capture token
2. **Copy token** from localStorage/sessionStorage
3. **Use token** in different browser/session
4. **Demonstrate** token reuse

**Expected Result**: 
- Vulnerable: Token works indefinitely
- Secure: Token expires in 15 minutes, refresh required

## 📊 Traffic Analysis with Wireshark

### Capture Setup

1. **Start Wireshark** and select appropriate interface:
   - **Loopback**: For localhost traffic
   - **Ethernet/WiFi**: For network traffic

2. **Apply filters**:
   ```
   # HTTP traffic on specific ports
   tcp.port == 1234 or tcp.port == 1235
   
   # HTTP requests only
   http.request
   
   # Specific endpoints
   http.request.uri contains "/login"
   http.request.uri contains "/admin"
   ```

3. **Capture during attacks**:
   - Login requests
   - Admin endpoint access
   - Token refresh operations

### What's Visible in HTTP Traffic

#### Login Request
```
POST /login HTTP/1.1
Content-Type: application/json
Authorization: Bearer <TOKEN_VISIBLE_IN_CLEAR>

{"username":"admin","password":"adminpass"}
```

#### Admin Access Request  
```
GET /admin HTTP/1.1
Authorization: Bearer <TOKEN_VISIBLE_IN_CLEAR>
```

#### Token in Response
```
HTTP/1.1 200 OK
Set-Cookie: refreshToken=<REFRESH_TOKEN_VISIBLE>

{"accessToken":"<ACCESS_TOKEN_VISIBLE_IN_CLEAR>"}
```

### Security Implications

- **HTTP**: All tokens visible in cleartext
- **HTTPS**: Tokens encrypted in TLS tunnel
- **Cookies**: HttpOnly cookies not accessible via JavaScript
- **Headers**: Authorization headers visible in network traffic

## 🧪 Testing Commands

### Manual API Testing

```bash
# Login to secure server
curl -X POST http://localhost:1235/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}' \
  -c cookies.txt

# Access admin endpoint
curl http://localhost:1235/admin \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -b cookies.txt

# Refresh token
curl -X POST http://localhost:1235/refresh \
  -b cookies.txt
```

### Attack Testing

```bash
# Algorithm none attack (vulnerable server)
curl http://localhost:1234/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."

# Weak secret forgery (vulnerable server)  
# Use jwt.io or similar to create token with weak-secret-lab-only
```

## 📁 Project Structure

```
jwt/
├── .env                    # Environment configuration
├── package.json           # Dependencies and scripts
├── init-db.js            # Database initialization
├── secure-server.js      # Hardened JWT server
├── vuln-server.js        # Vulnerable JWT server  
├── users.db             # SQLite database
├── attack-demos.js      # Attack demonstration script
├── security-demo.js     # Complete security summary
├── README.md            # English documentation
├── README_AR.md         # Arabic documentation
└── public/              # Frontend files
    ├── index.html       # Main application
    ├── script.js        # Client-side JavaScript
    └── style.css        # Styling
```

## 🔧 Available Scripts

- `npm run init-db`: Initialize database with sample users
- `npm run start-vuln`: Start vulnerable server (port 1234)
- `npm run start-secure`: Start secure server (port 1235)  
- `npm start`: Start secure server (default)

## 👥 Sample Users

| Username | Password | Role |
|----------|----------|------|
| admin | adminpass | admin |
| alice | alicepass | user |

## ⚠️ Security Notes

- **Lab Environment Only**: Vulnerable server is intentionally insecure
- **Production Use**: Never use weak secrets or `alg: none` in production
- **HTTPS Required**: Use HTTPS in production to protect tokens in transit
- **Secret Management**: Rotate secrets regularly in production
- **Token Storage**: Prefer HttpOnly cookies over localStorage for refresh tokens

## 📚 Learning Objectives

After completing this lab, you should understand:

1. **JWT Security Best Practices**
   - Strong secret generation and management
   - Proper claim validation (iss, aud, alg)
   - Token lifetime management

2. **Common JWT Vulnerabilities**
   - Algorithm confusion attacks
   - Weak secret exploitation
   - Token theft and replay attacks

3. **Refresh Token Strategies**
   - Token rotation for security
   - Server-side token tracking
   - HttpOnly cookie protection

4. **Network Security**
   - HTTP vs HTTPS token visibility
   - CORS configuration
   - Traffic analysis techniques

## 🎯 Attack Results Summary

### ✅ Attack Results

**Vulnerable Server (Port 1234):**
- Algorithm None Attack: SUCCESS (200 OK)
- Weak Secret Attack: SUCCESS (200 OK)

**Secure Server (Port 1235):**
- Algorithm None Attack: BLOCKED (401 Unauthorized)
- Weak Secret Attack: BLOCKED (401 Unauthorized)

### 🔒 Security Features Implemented

1. ✅ Environment configuration with .env
2. ✅ Removed hardcoded weak secrets
3. ✅ Enforced token claims (iss, aud) and verification
4. ✅ Implemented refresh token strategy with rotation
5. ✅ Kept existing frontend with minimal changes
6. ✅ Demonstrated attacks on vulnerable server
7. ✅ Showed attack failures on hardened server
8. ✅ Documented traffic analysis with Wireshark

---

**⚠️ Disclaimer**: This lab is for educational purposes only. The vulnerable server contains intentionally insecure code that should never be used in production environments.

## 🚀 How to Use

1. **Start servers:**
   ```bash
   npm run start-vuln    # Port 1234 (vulnerable)
   npm run start-secure  # Port 1235 (secure)
   ```

2. **Test attacks:**
   ```bash
   node attack-demos.js  # Generate attack tokens
   node security-demo.js # View complete summary
   ```

3. **Access the application:**
   - Vulnerable: http://localhost:1234
   - Secure: http://localhost:1235

The secure server successfully blocks all demonstrated attacks while maintaining proper authentication functionality.
