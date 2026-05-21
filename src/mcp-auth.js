import { randomUUID, createHash } from 'crypto';

// ── In-memory stores ──
const registeredClients = new Map();  // client_id -> { client_name, redirect_uris, created_at }
const authCodes = new Map();          // code -> { client_id, redirect_uri, code_challenge, expires_at, scope }
const validTokens = new Set();        // Set of issued access tokens

const CODE_TTL = 600_000;     // auth codes valid for 10 minutes
const TOKEN_TTL = 86400_000;  // tokens valid for 24 hours

// ── Dynamic Client Registration (RFC 7591) ──

export function registerClient(body) {
  const clientId = randomUUID();
  const clientName = body.client_name || 'MCP Client';
  const redirectUris = body.redirect_uris || [];

  registeredClients.set(clientId, {
    client_name: clientName,
    redirect_uris: redirectUris,
    grant_types: body.grant_types || ['authorization_code'],
    response_types: body.response_types || ['code'],
    token_endpoint_auth_method: 'none', // public client
    created_at: Date.now(),
  });

  return {
    client_id: clientId,
    client_name: clientName,
    redirect_uris: redirectUris,
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };
}

// ── Authorization Endpoint Helpers ──

export function validateAuthRequest(query) {
  const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } = query;

  if (!client_id) return { error: 'invalid_request', error_description: 'client_id is required' };
  if (!redirect_uri) return { error: 'invalid_request', error_description: 'redirect_uri is required' };
  if (response_type !== 'code') return { error: 'unsupported_response_type', error_description: 'Only response_type=code is supported' };
  if (!code_challenge) return { error: 'invalid_request', error_description: 'code_challenge is required (PKCE)' };
  if (code_challenge_method && code_challenge_method !== 'S256') {
    return { error: 'invalid_request', error_description: 'Only S256 code_challenge_method is supported' };
  }

  const client = registeredClients.get(client_id);
  if (!client) return { error: 'invalid_client', error_description: 'Unknown client_id. Register via POST /register first.' };

  // Validate redirect_uri if client registered specific ones
  if (client.redirect_uris.length > 0 && !client.redirect_uris.includes(redirect_uri)) {
    return { error: 'invalid_request', error_description: 'redirect_uri does not match registered URIs' };
  }

  return null; // valid
}

export function createAuthCode(clientId, redirectUri, codeChallenge, scope) {
  const code = randomUUID();
  authCodes.set(code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    scope: scope || 'mcp',
    expires_at: Date.now() + CODE_TTL,
  });

  // Clean up expired codes periodically
  for (const [k, v] of authCodes) {
    if (v.expires_at < Date.now()) authCodes.delete(k);
  }

  return code;
}

// ── Token Endpoint ──

export function exchangeCodeForToken(body) {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = body;

  if (grant_type !== 'authorization_code') {
    return { error: 'unsupported_grant_type', error_description: 'Only authorization_code is supported' };
  }
  if (!code) return { error: 'invalid_request', error_description: 'code is required' };
  if (!code_verifier) return { error: 'invalid_request', error_description: 'code_verifier is required (PKCE)' };

  const stored = authCodes.get(code);
  if (!stored) return { error: 'invalid_grant', error_description: 'Invalid or expired authorization code' };

  // Consume the code (one-time use)
  authCodes.delete(code);

  if (stored.expires_at < Date.now()) {
    return { error: 'invalid_grant', error_description: 'Authorization code has expired' };
  }
  if (stored.client_id !== client_id) {
    return { error: 'invalid_grant', error_description: 'client_id mismatch' };
  }
  if (stored.redirect_uri !== redirect_uri) {
    return { error: 'invalid_grant', error_description: 'redirect_uri mismatch' };
  }

  // Verify PKCE: S256 = BASE64URL(SHA256(code_verifier))
  const expectedChallenge = base64url(createHash('sha256').update(code_verifier).digest());
  if (expectedChallenge !== stored.code_challenge) {
    return { error: 'invalid_grant', error_description: 'PKCE code_verifier verification failed' };
  }

  // Issue token
  const accessToken = randomUUID();
  validTokens.add(accessToken);

  // Schedule token expiry
  setTimeout(() => validTokens.delete(accessToken), TOKEN_TTL);

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL / 1000,
    scope: stored.scope || 'mcp',
  };
}

// ── Token Validation ──

// Multi-tenant API key registry. The legacy MCP_API_KEY env var still works
// (mapped to tenant="owner"); additional keys are picked up from any env var
// matching MCP_API_KEY_<TENANT> so new consumers can be added by setting an
// env var on Railway with no code change required.
//
// Pattern intentionally mirrors the Vercel /api/ar-aging multi-tenant
// scheme (getServiceApiKeys in api/ar-aging.js) — separate keys per tenant
// so audit logs attribute traffic correctly and revocation is one-off.
function getValidApiKeys() {
  const keys = {};
  if (process.env.MCP_API_KEY) {
    keys[process.env.MCP_API_KEY] = 'owner';
  }
  // Enumerate per-tenant keys: MCP_API_KEY_MITCHELL → "mitchell", etc.
  for (const [name, value] of Object.entries(process.env)) {
    if (!name.startsWith('MCP_API_KEY_')) continue;
    if (!value) continue;
    const tenant = name.slice('MCP_API_KEY_'.length).toLowerCase();
    if (!tenant) continue;
    keys[value] = tenant;
  }
  return keys;
}

// Returns the tenant name (string) if the token is valid, or null otherwise.
// Bearer-token validation surface kept boolean-compatible via validateBearerToken
// below — most callers only need the yes/no answer.
export function resolveBearerToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);

  // Static API keys (owner + tenants)
  const keys = getValidApiKeys();
  if (keys[token]) return keys[token];

  // OAuth-issued tokens — owner-equivalent scope
  if (validTokens.has(token)) return 'owner';

  return null;
}

export function validateBearerToken(authHeader) {
  return resolveBearerToken(authHeader) !== null;
}

// ── Metadata Builders ──

export function getServerUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  return `${proto}://${host}`;
}

export function buildProtectedResourceMetadata(serverUrl) {
  return {
    resource: serverUrl,
    authorization_servers: [serverUrl],
    bearer_methods_supported: ['header'],
    scopes_supported: ['mcp'],
  };
}

export function buildAuthServerMetadata(serverUrl) {
  return {
    issuer: serverUrl,
    authorization_endpoint: `${serverUrl}/authorize`,
    token_endpoint: `${serverUrl}/token`,
    registration_endpoint: `${serverUrl}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp'],
  };
}

// ── Helpers ──

function base64url(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
