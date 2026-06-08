// ─── Dashboard JSON API ────────────────────────────────────────────────────
// Authenticated, CORS-locked, cached read-only passthrough to QuickBooks Online
// for the harbinger-dashboard Vercel app. This exists so the dashboard does NOT
// need its own QBO OAuth credentials — Railway is the single source of truth
// for QBO data and tokens.
//
// This module is mounted at /api in src/index.js. It does NOT touch the /mcp
// endpoint or any existing OAuth routes.

import express from 'express';
import axios from 'axios';
import { ensureValidToken, refreshToken } from './auth.js';

const QBO_BASE_URL = 'https://quickbooks.api.intuit.com/v3/company';

// ─── 60-second response cache (per-path+querystring) ──────────────────────
// Keeps QBO rate limits safe when the dashboard refreshes or multiple viewers
// load in the same minute. In-memory only; cleared when the server restarts.
const CACHE_TTL_MS = 60 * 1000;
const CACHE_MAX_ENTRIES = 200;
const cache = new Map(); // key -> { expiresAt, value }

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  // Move to end for rough-LRU eviction
  cache.delete(key);
  cache.set(key, entry);
  return entry.value;
}

function cacheSet(key, value) {
  cache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, value });
  while (cache.size > CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
}

// ─── Auth middleware: x-api-key header must match a registered key ───────
// Multi-tenant pattern. Each consuming dashboard gets its own env-var
// so they can be rotated independently. The map's keys are friendly
// labels surfaced in audit logs (e.g. when commissions-dashboard hits
// /api/expenses, the request log records that tenant). Add new
// consumers by adding new entries here + the matching env var on Railway.
function getValidApiKeys() {
  const keys = {};
  // Primary key — used by the Harbinger Finance Dashboard.
  if (process.env.DASHBOARD_API_KEY) {
    keys['harbinger-dashboard'] = process.env.DASHBOARD_API_KEY;
  }
  // Sales-commissions dashboard. Issued separately so we can rotate
  // without disrupting the main dashboard's traffic.
  if (process.env.DASHBOARD_API_KEY_COMMISSIONS) {
    keys['commissions-dashboard'] = process.env.DASHBOARD_API_KEY_COMMISSIONS;
  }
  return keys;
}

function requireDashboardKey(req, res, next) {
  const keys = getValidApiKeys();
  if (Object.keys(keys).length === 0) {
    return res.status(500).json({
      error: 'No DASHBOARD_API_KEY* env vars are configured on the server.',
    });
  }
  const provided = req.headers['x-api-key'];
  if (!provided) {
    return res.status(401).json({
      error: 'Unauthorized — valid x-api-key header required.',
    });
  }
  // Find which registered key matched, so audit logs can show who's
  // calling. Constant-time comparison would be nicer here for the
  // paranoid; for an internal tool with two trusted consumers, the
  // simple equality check is fine.
  const tenant = Object.keys(keys).find((k) => keys[k] === provided);
  if (!tenant) {
    return res.status(401).json({
      error: 'Unauthorized — valid x-api-key header required.',
    });
  }
  req.apiKeyTenant = tenant;
  // One-line audit log so usage is visible in Railway's logs.
  console.log(`[dashboard-api] ${req.method} ${req.path} · tenant=${tenant}`);
  next();
}

// ─── CORS: locked to the Vercel dashboard domain(s) ───────────────────────
// Default allowlist covers the production dashboard. Extend via env var
// DASHBOARD_ALLOWED_ORIGINS (comma-separated) for preview deployments.
const DEFAULT_ALLOWED_ORIGINS = [
  'https://harbinger-dashboard.vercel.app',
];

function getAllowedOrigins() {
  const extra = (process.env.DASHBOARD_ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return [...DEFAULT_ALLOWED_ORIGINS, ...extra];
}

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  const allowed = getAllowedOrigins();
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
}

// ─── Low-level QBO GET helper ─────────────────────────────────────────────
// Reuses Railway's existing token-refresh machinery via ensureValidToken().
async function qboGet(path, params = {}) {
  const { accessToken, realmId } = await ensureValidToken();
  const url = `${QBO_BASE_URL}/${realmId}${path}`;
  const res = await axios.get(url, {
    params,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
    // Let axios return JSON; don't throw on 4xx so we can forward QBO errors.
    validateStatus: (s) => s < 500,
  });
  if (res.status >= 400) {
    const body = res.data;
    const msg =
      body?.Fault?.Error?.[0]?.Message ||
      body?.Fault?.Error?.[0]?.Detail ||
      `QBO ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.qbo = body;
    throw err;
  }
  return res.data;
}

// ─── Low-level QBO POST helper ────────────────────────────────────────────
// Used for sparse updates (e.g. renaming a customer). Wraps the same
// token-refresh + error-forwarding machinery as qboGet.
async function qboPost(path, body, params = {}) {
  const { accessToken, realmId } = await ensureValidToken();
  const url = `${QBO_BASE_URL}/${realmId}${path}`;
  const res = await axios.post(url, body, {
    params,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    validateStatus: (s) => s < 500,
  });
  if (res.status >= 400) {
    const resBody = res.data;
    const msg =
      resBody?.Fault?.Error?.[0]?.Message ||
      resBody?.Fault?.Error?.[0]?.Detail ||
      `QBO ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.qbo = resBody;
    throw err;
  }
  return res.data;
}

function handleError(routeName, err, res) {
  const status = err.status || err.response?.status || 500;
  console.error(`[${routeName}] ${status}: ${err.message}`);
  res.status(status).json({
    error: err.message || 'Internal error',
    qbo: err.qbo || null,
  });
}

// ─── Router factory ───────────────────────────────────────────────────────
export function createDashboardRouter() {
  const router = express.Router();

  // Middleware order: CORS first (so OPTIONS short-circuits before auth),
  // then API-key auth for all other methods.
  router.use(corsMiddleware);
  router.use(requireDashboardKey);

  // ── GET /api/accounts — Chart of Accounts ──
  // Query params:
  //   maxResults    (default 1000, max 1000)
  //   startPosition (default 1, for pagination)
  //   minorversion  (default 75)
  router.get('/accounts', async (req, res) => {
    try {
      const maxResults = Math.min(
        parseInt(req.query.maxResults, 10) || 1000,
        1000,
      );
      const startPosition = parseInt(req.query.startPosition, 10) || 1;
      const minorversion = req.query.minorversion || '75';

      const cacheKey = `accounts:${maxResults}:${startPosition}:${minorversion}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }

      const q = `SELECT Id, AcctNum, FullyQualifiedName, AccountType, AccountSubType, Active FROM Account STARTPOSITION ${startPosition} MAXRESULTS ${maxResults}`;
      const data = await qboGet('/query', { query: q, minorversion });
      cacheSet(cacheKey, data);
      res.setHeader('X-Cache', 'MISS');
      res.json(data);
    } catch (err) {
      handleError('/api/accounts', err, res);
    }
  });

  // ── GET /api/reports/profit-and-loss ──
  // Query params: start_date, end_date (required),
  //               summarize_column_by (default Total),
  //               accounting_method   (default Accrual),
  //               minorversion        (default 75)
  router.get('/reports/profit-and-loss', async (req, res) => {
    try {
      if (!req.query.start_date || !req.query.end_date) {
        return res
          .status(400)
          .json({ error: 'start_date and end_date are required' });
      }
      const params = {
        start_date: req.query.start_date,
        end_date: req.query.end_date,
        summarize_column_by: req.query.summarize_column_by || 'Total',
        accounting_method: req.query.accounting_method || 'Accrual',
        minorversion: req.query.minorversion || '75',
      };
      const cacheKey = `pnl:${JSON.stringify(params)}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
      const data = await qboGet('/reports/ProfitAndLoss', params);
      cacheSet(cacheKey, data);
      res.setHeader('X-Cache', 'MISS');
      res.json(data);
    } catch (err) {
      handleError('/api/reports/profit-and-loss', err, res);
    }
  });

  // ── GET /api/reports/transaction-list ──
  // Query params: start_date, end_date (required),
  //               account (QBO account ID), columns (csv), minorversion
  router.get('/reports/transaction-list', async (req, res) => {
    try {
      if (!req.query.start_date || !req.query.end_date) {
        return res
          .status(400)
          .json({ error: 'start_date and end_date are required' });
      }
      const params = {
        start_date: req.query.start_date,
        end_date: req.query.end_date,
        columns:
          req.query.columns ||
          'tx_date,txn_type,doc_num,name,memo,subt_nat_amount,account_name',
        minorversion: req.query.minorversion || '75',
      };
      if (req.query.account) params.account = req.query.account;

      const cacheKey = `txlist:${JSON.stringify(params)}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
      const data = await qboGet('/reports/TransactionList', params);
      cacheSet(cacheKey, data);
      res.setHeader('X-Cache', 'MISS');
      res.json(data);
    } catch (err) {
      handleError('/api/reports/transaction-list', err, res);
    }
  });

  // ── GET /api/reports/ar-aging ──
  // Summary AR aging ("AgedReceivables") as of a given date. Defaults to today.
  // Query params: report_date (YYYY-MM-DD, optional, defaults to today UTC),
  //               aging_method (default Report_Date),
  //               days_per_period (default 30),
  //               num_periods (default 4),
  //               minorversion (default 75)
  router.get('/reports/ar-aging', async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const params = {
        report_date: req.query.report_date || today,
        aging_method: req.query.aging_method || 'Report_Date',
        days_per_period: req.query.days_per_period || '30',
        num_periods: req.query.num_periods || '4',
        minorversion: req.query.minorversion || '75',
      };
      const cacheKey = `ar-aging:${JSON.stringify(params)}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
      const data = await qboGet('/reports/AgedReceivables', params);
      cacheSet(cacheKey, data);
      res.setHeader('X-Cache', 'MISS');
      res.json(data);
    } catch (err) {
      handleError('/api/reports/ar-aging', err, res);
    }
  });

  // ── GET /api/query — generic read-only SELECT passthrough ──
  // Escape hatch for future needs without a Railway redeploy.
  // Query params: query (SELECT ... — required), minorversion
  router.get('/query', async (req, res) => {
    try {
      const raw = req.query.query;
      if (!raw) {
        return res.status(400).json({ error: 'query parameter is required' });
      }
      const trimmed = String(raw).trim();
      // Read-only guard: only SELECT statements allowed.
      if (!/^select\b/i.test(trimmed)) {
        return res
          .status(400)
          .json({ error: 'Only SELECT queries are allowed on this endpoint.' });
      }
      const minorversion = req.query.minorversion || '75';

      const cacheKey = `query:${trimmed}:${minorversion}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
      const data = await qboGet('/query', { query: trimmed, minorversion });
      cacheSet(cacheKey, data);
      res.setHeader('X-Cache', 'MISS');
      res.json(data);
    } catch (err) {
      handleError('/api/query', err, res);
    }
  });

  // ── POST /api/customers/:id/rename — rename a QBO customer ──
  // Body: { displayName: string }
  // Performs a sparse-update against the QBO Customer entity, preserving
  // every other field. We fetch the current SyncToken just-in-time so the
  // caller doesn't need to track it. Used by the harbinger-dashboard
  // partner-reconciliation batch (PR-U3.3).
  router.post('/customers/:id/rename', async (req, res) => {
    const cacheBust = () => {
      // Invalidate any cached /query results that mention Customer rows
      for (const key of Array.from(cache.keys())) {
        if (key.startsWith('query:') && /\bCustomer\b/i.test(key)) {
          cache.delete(key);
        }
      }
    };
    try {
      const id = String(req.params.id || '').trim();
      const newName = (req.body && req.body.displayName) || '';
      if (!id) {
        return res.status(400).json({ error: 'customer id is required in URL' });
      }
      if (!newName || typeof newName !== 'string') {
        return res
          .status(400)
          .json({ error: 'displayName (string) is required in body' });
      }
      if (newName.length > 100) {
        // QBO DisplayName max is 100 chars
        return res
          .status(400)
          .json({ error: 'displayName cannot exceed 100 characters' });
      }

      // Step 1: fetch current SyncToken (mandatory for any QBO update)
      const current = await qboGet('/query', {
        query: `SELECT Id, DisplayName, SyncToken FROM Customer WHERE Id = '${id}'`,
        minorversion: '75',
      });
      const cust =
        current?.QueryResponse?.Customer && current.QueryResponse.Customer[0];
      if (!cust) {
        return res
          .status(404)
          .json({ error: `Customer ${id} not found in QBO` });
      }

      // Step 2: sparse update — only changes DisplayName, preserves rest
      const updated = await qboPost(
        '/customer',
        {
          sparse: true,
          Id: cust.Id,
          SyncToken: cust.SyncToken,
          DisplayName: newName,
        },
        { minorversion: '75' },
      );

      cacheBust();

      const updatedCust = updated?.Customer || updated?.QueryResponse?.Customer;
      console.log(
        `[/api/customers/${id}/rename] '${cust.DisplayName}' → '${newName}'`,
      );
      return res.json({
        success: true,
        id,
        previousName: cust.DisplayName,
        newName,
        customer: updatedCust || null,
      });
    } catch (err) {
      handleError(`/api/customers/${req.params.id}/rename`, err, res);
    }
  });

  // ── POST /api/refresh — force token refresh ──
  router.post('/refresh', async (req, res) => {
    try {
      await refreshToken();
      res.json({
        success: true,
        refreshedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.error('[/api/refresh]', err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  return router;
}
