// secure-server.js  (HARDENED)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// Add CORS middleware to allow browser requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:1235');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }
  
  next();
});

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.SECURE_PORT || 1235;
const DB = new sqlite3.Database(process.env.DB_PATH || './users.db');

// Strong secrets from environment variables
const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

// JWT Configuration from environment
const JWT_ISSUER = process.env.JWT_ISSUER || 'jwt-lab-secure';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'jwt-lab-client';
const ACCESS_TOKEN_LIFETIME = process.env.ACCESS_TOKEN_LIFETIME || '15m';
const REFRESH_TOKEN_LIFETIME = process.env.REFRESH_TOKEN_LIFETIME || '7d';

// Validate required environment variables
if (!ACCESS_SECRET || !REFRESH_SECRET) {
  console.error('ERROR: ACCESS_SECRET and REFRESH_SECRET must be set in .env file');
  process.exit(1);
}

// Helpers
function issueAccessToken(username, role) {
  return jwt.sign(
    { 
      sub: username, 
      role,
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE
    }, 
    ACCESS_SECRET, 
    {
      algorithm: 'HS256',
      expiresIn: ACCESS_TOKEN_LIFETIME
    }
  );
}

function issueRefreshToken(username, tokenId) {
  return jwt.sign(
    { 
      sub: username, 
      tid: tokenId,
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE
    }, 
    REFRESH_SECRET, 
    {
      algorithm: 'HS256',
      expiresIn: REFRESH_TOKEN_LIFETIME
    }
  );
}

// In-memory refresh store for lab (in production use DB/redis)
const refreshStore = new Map();

// Login -> returns access token and sets refresh token in HttpOnly cookie
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  DB.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row || !bcrypt.compareSync(password, row.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = issueAccessToken(row.username, row.role);
    const tokenId = Math.random().toString(36).slice(2);
    const refreshToken = issueRefreshToken(row.username, tokenId);
    // store tokenId associated with username
    refreshStore.set(tokenId, { username: row.username, created: Date.now() });

    // set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false, // in lab use false; in production under HTTPS set true
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ accessToken, expiresIn: 900 }); // 15m
  });
});

// Middleware to authenticate access token (strict verification)
function authMiddleware(req, res, next) {
  const auth = (req.headers.authorization || '');
  const token = auth.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const payload = jwt.verify(token, ACCESS_SECRET, { 
      algorithms: ['HS256'], 
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token', details: e.message });
  }
}

// Protected admin
app.get('/admin', authMiddleware, (req, res) => {
  if (req.user.role === 'admin') return res.json({ secret: 'VERY SENSITIVE ADMIN DATA (SECURE)' });
  return res.status(403).json({ error:   'Forbidden' });
});

// Refresh endpoint (rotate refresh tokens in this lab)
app.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });
  
  try {
    const payload = jwt.verify(token, REFRESH_SECRET, { 
      algorithms: ['HS256'], 
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
    
    const info = refreshStore.get(payload.tid);
    if (!info || info.username !== payload.sub) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Token rotation: delete old token and issue new ones
    refreshStore.delete(payload.tid);
    const newTid = Math.random().toString(36).slice(2);
    refreshStore.set(newTid, { username: payload.sub, created: Date.now() });
    
    // Get user role from database for new access token
    DB.get("SELECT role FROM users WHERE username = ?", [payload.sub], (err, row) => {
      if (err || !row) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      const accessToken = issueAccessToken(payload.sub, row.role);
      const newRefresh = issueRefreshToken(payload.sub, newTid);

      res.cookie('refreshToken', newRefresh, { 
        httpOnly: true, 
        secure: false, 
        sameSite: 'Strict',
        maxAge: 7*24*60*60*1000 
      });
      res.json({ accessToken });
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid refresh token', details: e.message });
  }
});

app.listen(PORT, () => console.log(`SECURE server running at http://localhost:${PORT}`));
