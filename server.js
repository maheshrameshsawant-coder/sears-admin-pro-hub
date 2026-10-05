/* Zero-dependency static file server for local development.
   Serves this project's existing files as-is over HTTP so the app has
   real URLs instead of file:// paths. Uses only Node's built-in http/fs/path
   modules — no framework, no packages, no build step. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const chatbotService = require('./services/chatbotService');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

// ============================================================================
// Authentication & role-based access control
//
// DEVELOPMENT-ONLY AUTHENTICATION — read this before relying on it anywhere
// real. This app has no database, no HTTPS termination and no process
// manager — it is a single `node server.js` on localhost. What follows is
// the safest mechanism that fits that reality, not a production auth stack:
//   - Passwords are never stored in plain text: each is salted and hashed
//     with Node's built-in crypto.scrypt (no external package), verified
//     with a timing-safe comparison. See shared/data/users.json.
//   - Sessions are opaque random tokens (crypto.randomBytes) held in this
//     process's memory only (the `sessions` Map below) and referenced by an
//     HttpOnly cookie — never a JWT or anything the client can decode or
//     forge, and never persisted to disk. Restarting the server invalidates
//     every session, which is expected for a dev tool like this.
//   - The cookie is NOT marked Secure, because this server only ever speaks
//     plain HTTP on localhost. Serving this over real HTTP(S) to other
//     machines without adding TLS and the Secure flag would leak session
//     tokens on the network — do not do that.
//   - All 4 seed accounts share one known development password, shown right
//     on the login screen. That is intentional and disclosed, not hidden —
//     swap in real per-user passwords (and a real identity provider, for a
//     real deployment) before this ever leaves a developer's machine.
// ============================================================================
const USERS_FILE = path.join(ROOT, 'shared', 'data', 'users.json');
const NOTIFICATIONS_FILE = path.join(ROOT, 'shared', 'data', 'notifications.json');
const SESSION_COOKIE = 'sears_session';
const DEV_DEFAULT_PASSWORD = 'Sears@123';
const ROLES = { SUPER_ADMIN: 'Super Admin', ADMIN: 'Admin', AUDITOR: 'Auditor' };

// token -> { userId, createdAt } — in-memory only, see note above.
const sessions = new Map();

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeUserRecord(id, name, role, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { id, name, role, passwordSalt: salt, passwordHash: hashPassword(password, salt) };
}

// Seeds the 4 named accounts on first run only; never overwrites an existing
// users.json (so a Super Admin's later role changes persist across restarts).
function ensureUsersFile() {
  if (fs.existsSync(USERS_FILE)) return;
  const users = [
    makeUserRecord('mahesh-sawant', 'Mahesh Sawant', ROLES.SUPER_ADMIN, DEV_DEFAULT_PASSWORD),
    makeUserRecord('rajesh-shinde', 'Rajesh Shinde', ROLES.ADMIN, DEV_DEFAULT_PASSWORD),
    makeUserRecord('imran-shaikh', 'Imran Shaikh', ROLES.ADMIN, DEV_DEFAULT_PASSWORD),
    makeUserRecord('ankur-gupta', 'Ankur Gupta', ROLES.AUDITOR, DEV_DEFAULT_PASSWORD)
  ];
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2) + '\n');
}
function ensureNotificationsFile() {
  if (fs.existsSync(NOTIFICATIONS_FILE)) return;
  fs.mkdirSync(path.dirname(NOTIFICATIONS_FILE), { recursive: true });
  fs.writeFileSync(NOTIFICATIONS_FILE, '[]\n');
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2) + '\n');
}
function publicUser(u) {
  return u ? { id: u.id, name: u.name, role: u.role } : null;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

// Resolves the caller's session cookie to a real user record read fresh from
// disk every time (never cached), so a Super Admin's role change for another
// user takes effect on that user's very next request.
function getSessionUser(req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  const user = readUsers().find(u => u.id === session.userId);
  return user || null;
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Lax');
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

async function handleLogin(req, res) {
  let payload;
  try { payload = JSON.parse(await readRequestBody(req)); } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const userId = String((payload && payload.userId) || '');
  const password = String((payload && payload.password) || '');
  const user = readUsers().find(u => u.id === userId);
  if (!user) {
    return sendJson(res, 401, { ok: false, error: 'Unknown account.' });
  }
  const attemptHash = hashPassword(password, user.passwordSalt);
  const a = Buffer.from(attemptHash, 'hex');
  const b = Buffer.from(user.passwordHash, 'hex');
  const matches = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!matches) {
    return sendJson(res, 401, { ok: false, error: 'Incorrect password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, createdAt: new Date().toISOString() });
  setSessionCookie(res, token);
  sendJson(res, 200, { ok: true, user: publicUser(user) });
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (token) sessions.delete(token);
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

function handleMe(req, res) {
  const user = getSessionUser(req);
  if (!user) return sendJson(res, 401, { ok: false, user: null });
  sendJson(res, 200, { ok: true, user: publicUser(user) });
}

// Guard for every state-mutating API route. Returns the authenticated user
// on success; on failure it has already written the error response itself,
// and the caller must `return` immediately without doing any work. This is
// the real enforcement layer — client-side button hiding is a courtesy on
// top of this, never a substitute for it (an Auditor's request is rejected
// here even if sent directly, bypassing the UI entirely).
function requireWriteAccess(req, res, options) {
  options = options || {};
  const user = getSessionUser(req);
  if (!user) {
    sendJson(res, 401, { ok: false, error: 'Not authenticated. Please log in.' });
    return null;
  }
  if (user.role === ROLES.AUDITOR) {
    sendJson(res, 403, { ok: false, error: 'View-only access: your role cannot modify data.' });
    return null;
  }
  if (options.superAdminOnly && user.role !== ROLES.SUPER_ADMIN) {
    sendJson(res, 403, { ok: false, error: 'Only Super Admin can perform this action.' });
    return null;
  }
  return user;
}

// ---- Notifications: a genuine, append-only event log written by the real
// handlers below at the moment a real event happens (a booking request is
// submitted, a report is uploaded) — never fabricated separately from an
// actual action. `read` starts false so the header bell badge reflects a
// true unread count; opening the panel marks everything read.
function addNotification(type, title, message) {
  let list;
  try { list = JSON.parse(fs.readFileSync(NOTIFICATIONS_FILE, 'utf8')); } catch (e) { list = []; }
  list.unshift({ id: makeId('ntf'), type, title, message, createdAt: new Date().toISOString(), read: false });
  if (list.length > 100) list.length = 100; // cap growth; oldest fall off
  try { fs.writeFileSync(NOTIFICATIONS_FILE, JSON.stringify(list, null, 2) + '\n'); } catch (e) { /* non-critical */ }
}
function handleGetNotifications(req, res) {
  if (!getSessionUser(req)) return sendJson(res, 401, { ok: false, error: 'Not authenticated.' });
  let list;
  try { list = JSON.parse(fs.readFileSync(NOTIFICATIONS_FILE, 'utf8')); } catch (e) { list = []; }
  sendJson(res, 200, { ok: true, notifications: list });
}
function handleMarkNotificationsRead(req, res) {
  if (!getSessionUser(req)) return sendJson(res, 401, { ok: false, error: 'Not authenticated.' });
  let list;
  try { list = JSON.parse(fs.readFileSync(NOTIFICATIONS_FILE, 'utf8')); } catch (e) { list = []; }
  list.forEach(n => { n.read = true; });
  try { fs.writeFileSync(NOTIFICATIONS_FILE, JSON.stringify(list, null, 2) + '\n'); } catch (e) { /* non-critical */ }
  sendJson(res, 200, { ok: true });
}

// ---- User & Role Management — Super Admin only (enforced in both the page
// route and these two API handlers, not just by hiding the nav link).
function handleGetUsers(req, res) {
  const user = getSessionUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'Not authenticated.' });
  if (user.role !== ROLES.SUPER_ADMIN) return sendJson(res, 403, { ok: false, error: 'Only Super Admin can view user management.' });
  sendJson(res, 200, { ok: true, users: readUsers().map(publicUser) });
}
async function handleSetUserRole(req, res, targetId) {
  const requester = requireWriteAccess(req, res, { superAdminOnly: true });
  if (!requester) return;
  let payload;
  try { payload = JSON.parse(await readRequestBody(req)); } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const newRole = payload && payload.role;
  if (newRole !== ROLES.ADMIN && newRole !== ROLES.AUDITOR) {
    return sendJson(res, 400, { ok: false, error: 'Role must be Admin or Auditor — a second Super Admin cannot be created here.' });
  }
  const users = readUsers();
  const target = users.find(u => u.id === targetId);
  if (!target) return sendJson(res, 404, { ok: false, error: 'Unknown user.' });
  if (target.role === ROLES.SUPER_ADMIN) {
    return sendJson(res, 403, { ok: false, error: "The Super Admin's own role cannot be changed here." });
  }
  target.role = newRole;
  writeUsers(users);
  sendJson(res, 200, { ok: true, user: publicUser(target) });
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1e6) { req.destroy(); reject(new Error('Payload too large')); }
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

// ---- Field configuration (Phase 1: Manage Headers) --------------------
// One JSON file, keyed by expense category, each an array of
// { key, label, order, type, required, active }. `key` is always the exact
// original header text from that category's report file (immutable — it's
// how a value's position in a row is found) so renaming the display `label`
// or reordering/deactivating a field can never disconnect it from its data.
// Auto-generated once per category (from its current report's columns) the
// first time the server starts and finds no config yet — see
// ensureAllFieldConfigs() near the bottom of this file. Editable afterwards
// only via POST /api/field-config/<category>, which refuses to drop or add
// keys (see handleSaveFieldConfig) so "Manage Headers" can never lose data
// or invent a field that has no corresponding column.
const FIELD_CONFIG_FILE = path.join(ROOT, 'shared', 'data', 'field-config.json');
const EXPENSE_CATEGORY_IDS = ['cab', 'flight', 'stay', 'rent', 'courier', 'procurement', 'amc', 'communication'];

const NUMBER_HEADER_HINTS = /amount|amt|cost|charge|price|rate|saving|total|subtotal|gst|tax|count|weight|kms?\b|days?\b|nights?\b|guests?\b|hours?\b|no\.?\s*of/i;
const DATE_HEADER_HINTS = /date/i;
const TIME_HEADER_HINTS = /time/i;

function inferFieldType(header) {
  if (DATE_HEADER_HINTS.test(header)) return 'date';
  if (TIME_HEADER_HINTS.test(header)) return 'time';
  if (NUMBER_HEADER_HINTS.test(header)) return 'number';
  return 'text';
}

function deriveFieldConfig(columns) {
  return columns.map((key, i) => ({
    key: key,
    label: key,
    order: i + 1,
    type: inferFieldType(key),
    required: false,
    active: true
  }));
}

function readAllFieldConfigs() {
  try { return JSON.parse(fs.readFileSync(FIELD_CONFIG_FILE, 'utf8')); } catch (e) { return {}; }
}

function getFieldConfig(category) {
  const all = readAllFieldConfigs();
  return all[category] || null;
}

// Runs once at server startup (see bottom of file) so field-config.json
// always has an entry for every category that currently has real report
// data — no per-request generation, no risk of two requests racing to
// create it differently.
function ensureAllFieldConfigs() {
  const all = readAllFieldConfigs();
  let changed = false;
  EXPENSE_CATEGORY_IDS.forEach(category => {
    if (all[category]) return;
    const filePath = reportFilePath(category);
    let data;
    try { data = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (e) { return; }
    if (!data || !Array.isArray(data.columns) || !data.columns.length) return;
    all[category] = deriveFieldConfig(data.columns);
    changed = true;
  });
  if (changed) {
    fs.mkdirSync(path.dirname(FIELD_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(FIELD_CONFIG_FILE, JSON.stringify(all, null, 2) + '\n');
  }
}

async function handleSaveFieldConfig(req, res, category) {
  if (EXPENSE_CATEGORY_IDS.indexOf(category) === -1) {
    return sendJson(res, 404, { ok: false, error: 'Unknown expense category: ' + category });
  }
  const existing = getFieldConfig(category);
  if (!existing) {
    return sendJson(res, 404, { ok: false, error: 'This report has no data yet, so there are no headers to configure.' });
  }

  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const incoming = payload && payload.fields;
  if (!Array.isArray(incoming) || !incoming.length) {
    return sendJson(res, 400, { ok: false, error: 'fields must be a non-empty array' });
  }

  const existingKeys = existing.map(f => f.key).sort();
  const incomingKeys = incoming.map(f => f.key).sort();
  const sameKeySet = existingKeys.length === incomingKeys.length && existingKeys.every((k, i) => k === incomingKeys[i]);
  if (!sameKeySet) {
    return sendJson(res, 400, {
      ok: false,
      error: 'This change may affect existing records and Excel compatibility: every original header must remain present (mark it Inactive instead of removing it), and no new header can be introduced here — headers can only come from an uploaded report.'
    });
  }

  const VALID_TYPES = ['text', 'number', 'date', 'time'];
  for (const f of incoming) {
    if (!f.label || !String(f.label).trim()) {
      return sendJson(res, 400, { ok: false, error: 'Every header must have a non-empty display label.' });
    }
    if (VALID_TYPES.indexOf(f.type) === -1) {
      return sendJson(res, 400, { ok: false, error: 'Invalid field type: ' + f.type });
    }
  }

  const cleaned = incoming.map((f, i) => ({
    key: f.key,
    label: String(f.label).trim(),
    order: Number.isFinite(f.order) ? f.order : i + 1,
    type: f.type,
    required: !!f.required,
    active: !!f.active
  })).sort((a, b) => a.order - b.order);

  const all = readAllFieldConfigs();
  all[category] = cleaned;
  try {
    fs.mkdirSync(path.dirname(FIELD_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(FIELD_CONFIG_FILE, JSON.stringify(all, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save header configuration' });
  }
  sendJson(res, 200, { ok: true, fields: cleaned });
}

// ---- Expense record create/update (Phase 1: Add New Entry / Edit) -----
// Both operate on the exact same file Upload Excel writes to (via
// reportFilePath, defined below) — one record store per category, never a
// second copy. Payloads are keyed by each field's stable `key` (not
// position), e.g. { values: { "Vendor": "Acme Travels", ... } }, so a
// partial submission (only the currently Active fields) can be merged into
// the right column positions of a full-width row without disturbing
// Inactive columns' existing values.
async function handleCreateExpenseRow(req, res, category) {
  const filePath = reportFilePath(category);
  if (!filePath) return sendJson(res, 404, { ok: false, error: 'Unknown expense category: ' + category });

  let data;
  try { data = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (e) {
    return sendJson(res, 404, { ok: false, error: 'This report has not been uploaded yet, so it has no headers to add an entry against.' });
  }

  let payload;
  try { payload = JSON.parse(await readRequestBody(req)); } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const values = payload && payload.values;
  if (!values || typeof values !== 'object') {
    return sendJson(res, 400, { ok: false, error: 'values must be an object keyed by header name' });
  }

  const fields = getFieldConfig(category) || deriveFieldConfig(data.columns);
  const missing = fields.filter(f => f.active && f.required && !String(values[f.key] || '').trim()).map(f => f.label);
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  const row = data.columns.map(col => (values[col] !== undefined ? String(values[col]) : ''));
  data.rows.push(row);

  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save record' });
  }
  sendJson(res, 200, { ok: true, rowIndex: data.rows.length - 1, recordCount: data.rows.length });
}

async function handleUpdateExpenseRow(req, res, category, rowIndex) {
  const filePath = reportFilePath(category);
  if (!filePath) return sendJson(res, 404, { ok: false, error: 'Unknown expense category: ' + category });

  let data;
  try { data = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (e) {
    return sendJson(res, 404, { ok: false, error: 'This report has not been uploaded yet.' });
  }
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= data.rows.length) {
    return sendJson(res, 404, { ok: false, error: 'Record not found at position ' + rowIndex });
  }

  let payload;
  try { payload = JSON.parse(await readRequestBody(req)); } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const values = payload && payload.values;
  if (!values || typeof values !== 'object') {
    return sendJson(res, 400, { ok: false, error: 'values must be an object keyed by header name' });
  }

  const fields = getFieldConfig(category) || deriveFieldConfig(data.columns);
  const missing = fields.filter(f => f.active && f.required && !String(values[f.key] || '').trim()).map(f => f.label);
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  const existingRow = data.rows[rowIndex];
  const updatedRow = data.columns.map((col, i) => (values[col] !== undefined ? String(values[col]) : existingRow[i]));
  data.rows[rowIndex] = updatedRow;

  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save record' });
  }
  sendJson(res, 200, { ok: true, rowIndex: rowIndex, recordCount: data.rows.length });
}

// ---- Reports: whole-file replace, one JSON per report id, uploaded from an
// Excel file client-side (see pages/reports.html). Whitelisted the same way
// as expense categories — no fake save for an unconfigured report id. Each
// stored file is exactly {sourceSheet, columns, rows, uploadedAt}, the same
// shape shared/data/expenses/*.json already uses, so the uploaded Excel
// file's own headers/rows are the single source of truth with nothing added,
// renamed or reordered.
//
// REPORT_FILES mirrors shared/data/report-definitions.js's `file` field
// (that file is a browser global, not requireable in Node — same reason
// EXPENSE_DATA_FILES below is separate from expense-categories.js). `null`
// means "use the default shared/data/reports/<id>.json path"; a report can
// instead point at a file another page already reads/writes, so uploading
// it here updates that page too — e.g. Tickets stays backed by the exact
// shared/data/tickets-report.json pages/tickets.html already fetches.
const REPORTS_DIR = path.join(ROOT, 'shared', 'data', 'reports');
const REPORT_FILES = {
  cab: path.join(ROOT, 'shared', 'data', 'expenses', 'cab.json'),
  flight: path.join(ROOT, 'shared', 'data', 'expenses', 'flight.json'),
  stay: path.join(ROOT, 'shared', 'data', 'expenses', 'stay.json'),
  rent: null,
  courier: path.join(ROOT, 'shared', 'data', 'expenses', 'courier.json'),
  procurement: path.join(ROOT, 'shared', 'data', 'expenses', 'procurement.json'),
  amc: null,
  communication: null,
  tickets: path.join(ROOT, 'shared', 'data', 'tickets-report.json')
};

function reportFilePath(reportId) {
  if (!Object.prototype.hasOwnProperty.call(REPORT_FILES, reportId)) return null;
  return REPORT_FILES[reportId] || path.join(REPORTS_DIR, reportId + '.json');
}

async function handleSaveReport(req, res, reportId, onSuccess) {
  const filePath = reportFilePath(reportId);
  if (!filePath) {
    return sendJson(res, 404, { ok: false, error: 'Unknown or unconfigured report: ' + reportId });
  }

  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }

  const columns = payload && payload.columns;
  const rows = payload && payload.rows;
  if (!Array.isArray(columns) || !columns.length || !Array.isArray(rows)) {
    return sendJson(res, 400, { ok: false, error: 'Report must include a non-empty columns array and a rows array' });
  }
  const malformedRow = rows.some(row => !Array.isArray(row) || row.length !== columns.length);
  if (malformedRow) {
    return sendJson(res, 400, { ok: false, error: 'Every row must supply exactly ' + columns.length + ' values (one per column)' });
  }

  const record = {
    sourceSheet: (payload.sourceSheet || '').toString(),
    columns: columns,
    rows: rows,
    uploadedAt: new Date().toISOString()
  };

  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(record, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save report' });
  }

  if (onSuccess) onSuccess();
  sendJson(res, 200, { ok: true, rowCount: record.rows.length });
}

async function handleChatbot(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, reply: 'Invalid request.', action: null });
  }
  const clientId = (req.socket && req.socket.remoteAddress) || 'unknown';
  const result = await chatbotService.handleMessage(payload && payload.message, clientId);
  sendJson(res, result.status, result.body);
}

// ---- Activities & Tickets: shared, id-keyed collections. Both use the same
// {create, update-by-id} shape, so one pair of handlers serves both — no
// duplicated data source between Admin Console and the public pages, since
// every read (Task Lists, Tickets page, Admin Console, count calculations)
// fetches the same file these handlers write to.
const ACTIVITIES_FILE = path.join(ROOT, 'shared', 'data', 'activities.json');
const TICKETS_FILE = path.join(ROOT, 'shared', 'data', 'tickets.json');
const ACTIVITY_REQUIRED_FIELDS = ['month', 'workstream', 'activity', 'status'];
const TICKET_REQUIRED_FIELDS = ['ticketNumber', 'title', 'status'];

function makeId(prefix) {
  return prefix + '-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

async function handleCollectionCreate(req, res, filePath, requiredFields, idPrefix) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const missing = requiredFields.filter(key => !String(payload[key] || '').trim());
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  let list;
  try {
    list = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not read data' });
  }

  const now = new Date().toISOString();
  const record = Object.assign({ id: makeId(idPrefix) }, payload, { createdAt: now, updatedAt: now });
  list.push(record);

  try {
    fs.writeFileSync(filePath, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save record' });
  }
  sendJson(res, 200, { ok: true, record: record, count: list.length });
}

async function handleCollectionUpdate(req, res, filePath, id, requiredFields) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const missing = requiredFields.filter(key => !String(payload[key] || '').trim());
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  let list;
  try {
    list = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not read data' });
  }

  const idx = list.findIndex(r => r.id === id);
  if (idx === -1) {
    return sendJson(res, 404, { ok: false, error: 'Record not found: ' + id });
  }

  const updated = Object.assign({}, list[idx], payload, {
    id: list[idx].id,
    createdAt: list[idx].createdAt,
    updatedAt: new Date().toISOString()
  });
  list[idx] = updated;

  try {
    fs.writeFileSync(filePath, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save record' });
  }
  sendJson(res, 200, { ok: true, record: updated, count: list.length });
}

async function handleCollectionDelete(req, res, filePath, id) {
  let list;
  try {
    list = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not read data' });
  }
  const idx = list.findIndex(r => r.id === id);
  if (idx === -1) {
    return sendJson(res, 404, { ok: false, error: 'Record not found: ' + id });
  }
  list.splice(idx, 1);
  try {
    fs.writeFileSync(filePath, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save record' });
  }
  sendJson(res, 200, { ok: true, count: list.length });
}

// ---- New Bookings module (Cab/Flight/Hotel/Courier): each category is its
// own id-keyed collection (shared/data/bookings/<category>.json) — entirely
// separate from expense records and from the legacy Ground Transportation
// Booking collection (shared/data/bookings.json), per the requirement not to
// mix or duplicate booking data. Which fields exist, their labels, types,
// required/active state and dropdown options are NOT hardcoded here — they
// live in shared/data/booking-field-config.json (see BOOKING_FIELD_CONFIG_FILE
// below) and are editable from Admin Console → Booking Forms without
// touching this file, the same way shared/data/field-config.json already
// drives the 8 expense report forms.
const BOOKING_CATEGORY_FILES = {
  cab: path.join(ROOT, 'shared', 'data', 'bookings', 'cab.json'),
  flight: path.join(ROOT, 'shared', 'data', 'bookings', 'flight.json'),
  hotel: path.join(ROOT, 'shared', 'data', 'bookings', 'hotel.json'),
  courier: path.join(ROOT, 'shared', 'data', 'bookings', 'courier.json')
};
const BOOKING_CATEGORY_IDS = ['cab', 'flight', 'hotel', 'courier'];
const BOOKING_CATEGORY_LABELS = { cab: 'Cab Booking', flight: 'Flight Booking', hotel: 'Hotel Booking', courier: 'Courier Request' };
const BOOKING_FIELD_CONFIG_FILE = path.join(ROOT, 'shared', 'data', 'booking-field-config.json');
const BOOKING_FIELD_TYPES = ['text', 'number', 'date', 'time', 'phone', 'textarea', 'dropdown'];

// One-time seed for each category's field list — only used the first time
// the server starts and finds no config yet for that category (see
// ensureAllBookingFieldConfigs below), exactly like deriveFieldConfig seeds
// shared/data/field-config.json from an uploaded report's columns. After
// that, this array is never consulted again — booking-field-config.json is
// the sole source of truth, and Admin Console edits to it persist across
// restarts.
const DEFAULT_BOOKING_FIELD_CONFIG = {
  cab: [
    { key: 'bookingRequestDate', label: 'Booking Request Date', order: 1, type: 'date', required: true, active: true },
    { key: 'bookingDate', label: 'Booking Date', order: 2, type: 'date', required: true, active: true },
    { key: 'billingEntity', label: 'Billing Entity', order: 3, type: 'text', required: true, active: true },
    { key: 'billingLocation', label: 'Billing Location', order: 4, type: 'text', required: true, active: true },
    { key: 'packageType', label: 'Package Type', order: 5, type: 'dropdown', required: true, active: true, options: ['Local', 'Outstation'] },
    { key: 'associateId', label: 'Associate ID', order: 6, type: 'text', required: true, active: true },
    { key: 'associateName', label: 'Associate Name', order: 7, type: 'text', required: true, active: true },
    { key: 'pickupTime', label: 'Pickup Time', order: 8, type: 'time', required: true, active: true },
    { key: 'contactNumber', label: 'Contact Number', order: 9, type: 'phone', required: true, active: true },
    { key: 'pickupAddress', label: 'Pickup Address', order: 10, type: 'textarea', required: true, active: true }
  ],
  flight: [
    { key: 'bookingRequestDate', label: 'Booking Request Date', order: 1, type: 'date', required: true, active: true },
    { key: 'bookingDate', label: 'Booking Date', order: 2, type: 'date', required: true, active: true },
    { key: 'billingEntity', label: 'Billing Entity', order: 3, type: 'text', required: true, active: true },
    { key: 'billingLocation', label: 'Billing Location', order: 4, type: 'text', required: true, active: true },
    { key: 'origin', label: 'Origin', order: 5, type: 'text', required: true, active: true },
    { key: 'destination', label: 'Destination', order: 6, type: 'text', required: true, active: true },
    { key: 'associateId', label: 'Associate ID', order: 7, type: 'text', required: true, active: true },
    { key: 'associateName', label: 'Associate Name', order: 8, type: 'text', required: true, active: true },
    { key: 'contactNumber', label: 'Contact Number', order: 9, type: 'phone', required: true, active: true }
  ],
  hotel: [
    { key: 'bookingRequestDate', label: 'Booking Request Date', order: 1, type: 'date', required: true, active: true },
    { key: 'billingEntity', label: 'Billing Entity', order: 2, type: 'text', required: true, active: true },
    { key: 'billingLocation', label: 'Billing Location', order: 3, type: 'text', required: true, active: true },
    { key: 'bookingLocation', label: 'Booking Location', order: 4, type: 'text', required: true, active: true },
    { key: 'preferredLocationLandmark', label: 'Preferred Location / Landmark', order: 5, type: 'text', required: true, active: true },
    { key: 'associateId', label: 'Associate ID', order: 6, type: 'text', required: true, active: true },
    { key: 'associateName', label: 'Associate Name', order: 7, type: 'text', required: true, active: true },
    { key: 'contactNumber', label: 'Contact Number', order: 8, type: 'phone', required: true, active: true }
  ],
  courier: [
    { key: 'courierRequestType', label: 'Courier Request Type', order: 1, type: 'dropdown', required: true, active: true, options: ['Courier Pickup Date', 'Courier Delivery Date'] },
    { key: 'billingEntity', label: 'Billing Entity', order: 2, type: 'text', required: true, active: true },
    { key: 'billingLocation', label: 'Billing Location', order: 3, type: 'text', required: true, active: true },
    { key: 'bookingLocation', label: 'Booking Location', order: 4, type: 'text', required: true, active: true },
    { key: 'associateId', label: 'Associate ID', order: 5, type: 'text', required: true, active: true },
    { key: 'associateName', label: 'Associate Name', order: 6, type: 'text', required: true, active: true },
    { key: 'address', label: 'Address', order: 7, type: 'textarea', required: true, active: true },
    { key: 'contactNumber', label: 'Contact Number', order: 8, type: 'phone', required: true, active: true }
  ]
};

function readAllBookingFieldConfigs() {
  try { return JSON.parse(fs.readFileSync(BOOKING_FIELD_CONFIG_FILE, 'utf8')); } catch (e) { return {}; }
}
function getBookingFieldConfig(category) {
  const all = readAllBookingFieldConfigs();
  return all[category] || null;
}

// Runs once at server startup (see bottom of file) so every category always
// has a field config, without ever overwriting one an administrator has
// already edited.
function ensureAllBookingFieldConfigs() {
  const all = readAllBookingFieldConfigs();
  let changed = false;
  BOOKING_CATEGORY_IDS.forEach(category => {
    if (all[category]) return;
    all[category] = DEFAULT_BOOKING_FIELD_CONFIG[category];
    changed = true;
  });
  if (changed) {
    fs.mkdirSync(path.dirname(BOOKING_FIELD_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(BOOKING_FIELD_CONFIG_FILE, JSON.stringify(all, null, 2) + '\n');
  }
}

// Save handler for Admin Console → Booking Forms field editor. Mirrors
// handleSaveFieldConfig's safeguard exactly: the set of field keys can never
// change here (no adding/removing a field from this screen, matching "Do not
// add extra fields" / "Do not remove any of these fields") — only label,
// type, required, active, order and (for dropdown fields) options.
async function handleSaveBookingFieldConfig(req, res, category) {
  if (BOOKING_CATEGORY_IDS.indexOf(category) === -1) {
    return sendJson(res, 404, { ok: false, error: 'Unknown booking category: ' + category });
  }
  const existing = getBookingFieldConfig(category);
  if (!existing) {
    return sendJson(res, 404, { ok: false, error: 'This booking form has no field configuration yet.' });
  }

  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const incoming = payload && payload.fields;
  if (!Array.isArray(incoming) || !incoming.length) {
    return sendJson(res, 400, { ok: false, error: 'fields must be a non-empty array' });
  }

  const existingKeys = existing.map(f => f.key).sort();
  const incomingKeys = incoming.map(f => f.key).sort();
  const sameKeySet = existingKeys.length === incomingKeys.length && existingKeys.every((k, i) => k === incomingKeys[i]);
  if (!sameKeySet) {
    return sendJson(res, 400, {
      ok: false,
      error: 'A field cannot be added or removed from this screen — every original field must remain present (mark it Inactive instead of removing it).'
    });
  }

  for (const f of incoming) {
    if (!f.label || !String(f.label).trim()) {
      return sendJson(res, 400, { ok: false, error: 'Every field must have a non-empty label.' });
    }
    if (BOOKING_FIELD_TYPES.indexOf(f.type) === -1) {
      return sendJson(res, 400, { ok: false, error: 'Invalid field type: ' + f.type });
    }
    if (f.type === 'dropdown') {
      const opts = (f.options || []).map(o => String(o).trim()).filter(Boolean);
      if (!opts.length) {
        return sendJson(res, 400, { ok: false, error: 'Field "' + f.label + '" is a dropdown and needs at least one option.' });
      }
    }
  }

  const cleaned = incoming.map((f, i) => {
    const out = {
      key: f.key,
      label: String(f.label).trim(),
      order: Number.isFinite(f.order) ? f.order : i + 1,
      type: f.type,
      required: !!f.required,
      active: !!f.active
    };
    if (f.type === 'dropdown') {
      out.options = (f.options || []).map(o => String(o).trim()).filter(Boolean);
    }
    return out;
  }).sort((a, b) => a.order - b.order);

  const all = readAllBookingFieldConfigs();
  all[category] = cleaned;
  try {
    fs.mkdirSync(path.dirname(BOOKING_FIELD_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(BOOKING_FIELD_CONFIG_FILE, JSON.stringify(all, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save field configuration' });
  }
  sendJson(res, 200, { ok: true, fields: cleaned });
}

// ---- Bookings & Vendors: same id-keyed collection pattern as Activities/
// Tickets above (reusing handleCollectionCreate/handleCollectionUpdate
// as-is — no new storage mechanism). Bookings uses the exact 12 fields the
// Ground Transportation Booking form/card/Excel all share; Vendor email is
// intentionally optional here (not in VENDOR_REQUIRED_FIELDS) since a vendor
// can exist before its email is configured — Send to Vendor checks for a
// configured email itself rather than forcing one to exist at creation.
const BOOKINGS_FILE = path.join(ROOT, 'shared', 'data', 'bookings.json');
const VENDORS_FILE = path.join(ROOT, 'shared', 'data', 'vendors.json');
const BOOKING_REQUIRED_FIELDS = ['date', 'vendor', 'associateName', 'pickupLocation', 'dropLocation', 'dutyType'];
const VENDOR_REQUIRED_FIELDS = ['name'];

// The exact 12 columns, in this exact order, for Upload/Download Excel —
// mirrors the field keys used throughout bookings.json records.
const BOOKING_COLUMNS = [
  { key: 'date', label: 'Date' },
  { key: 'billingEntity', label: 'Billing Entity' },
  { key: 'vendor', label: 'Vendor' },
  { key: 'vehicle', label: 'Vehicle' },
  { key: 'associateId', label: 'Associate ID' },
  { key: 'associateName', label: 'Associate Name' },
  { key: 'pickupTime', label: 'Pickup Time' },
  { key: 'contactNumber', label: 'Contact Number' },
  { key: 'pickupLocation', label: 'Pickup Location' },
  { key: 'dropLocation', label: 'Drop Location' },
  { key: 'dutyType', label: 'Duty Type' },
  { key: 'flightNumber', label: 'Flight Number' }
];

// Upload Excel for Bookings replaces the whole collection — the same
// whole-file-replace behavior every other Upload Excel button in this app
// already has (see handleSaveReport) — rather than inventing new row-level
// upsert/matching logic that exists nowhere else in the codebase. Each
// uploaded row becomes one booking card with a freshly assigned id.
async function handleBookingsImport(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }

  const records = payload && payload.records;
  if (!Array.isArray(records)) {
    return sendJson(res, 400, { ok: false, error: 'Import must include a records array' });
  }

  for (let i = 0; i < records.length; i++) {
    const missing = BOOKING_REQUIRED_FIELDS.filter(key => !String(records[i][key] || '').trim());
    if (missing.length) {
      return sendJson(res, 400, { ok: false, error: 'Row ' + (i + 1) + ' is missing required field(s): ' + missing.join(', ') });
    }
  }

  const now = new Date().toISOString();
  const list = records.map(record => {
    const clean = {};
    BOOKING_COLUMNS.forEach(col => { clean[col.key] = record[col.key] || ''; });
    return Object.assign({ id: makeId('bkg') }, clean, { createdAt: now, updatedAt: now });
  });

  try {
    fs.writeFileSync(BOOKINGS_FILE, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save bookings' });
  }

  sendJson(res, 200, { ok: true, count: list.length });
}

// ---- SOP Admin: Create/Edit — reuses shared/data/sop.json, the exact
// existing SOP data store (also read by pages/sop-library.html,
// pages/sop-detail.html and services/chatbotService.js). This file already
// models an SOP as one or more *version* records sharing a sopId (see the
// seed data's Vendor Onboarding entry: v1.0 then v1.1) — versionNumber and
// changeSummary exist specifically for that. Editing therefore appends a
// new version record (same sopId, incremented versionNumber) rather than
// overwriting history, which is the existing architecture already
// demonstrates and pages/sop-detail.html already has a version picker for.
// Every SOP field is stored as the same "<p>...</p>"-wrapped HTML the seed
// records use, so pages/sop-detail.html's existing rendering (which injects
// these fields as raw HTML) keeps working unchanged for new/edited content.
const SOP_FILE = path.join(ROOT, 'shared', 'data', 'sop.json');
const SOP_REQUIRED_FIELDS = ['name', 'purpose'];
const SOP_CONTENT_FIELDS = [
  'purpose', 'scope', 'definitions', 'rolesResponsibilities', 'procedure',
  'controls', 'requiredDocuments', 'relatedPolicies', 'escalationMatrix', 'exceptions', 'remarks'
];

function nextVersionNumber(latest) {
  const n = parseFloat(latest) || 1.0;
  return (Math.round((n + 0.1) * 10) / 10).toFixed(1);
}

async function handleCreateSop(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const missing = SOP_REQUIRED_FIELDS.filter(key => !String(payload[key] || '').trim());
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  let list;
  try {
    list = JSON.parse(fs.readFileSync(SOP_FILE, 'utf8'));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not read SOP data' });
  }

  const now = new Date().toISOString();
  const record = { id: makeId('sopv'), sopId: makeId('sop'), versionNumber: '1.0', changeSummary: 'Initial version.' };
  record.createdAt = now;
  record.createdBy = 'Admin';
  record.name = String(payload.name).trim();
  SOP_CONTENT_FIELDS.forEach(key => { record[key] = payload[key] ? String(payload[key]) : '<p></p>'; });

  list.push(record);

  try {
    fs.writeFileSync(SOP_FILE, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save SOP' });
  }
  sendJson(res, 200, { ok: true, record: record });
}

async function handleUpdateSop(req, res, sopId) {
  let payload;
  try {
    payload = JSON.parse(await readRequestBody(req));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
  }
  const missing = SOP_REQUIRED_FIELDS.filter(key => !String(payload[key] || '').trim());
  if (missing.length) {
    return sendJson(res, 400, { ok: false, error: 'Missing required field(s): ' + missing.join(', ') });
  }

  let list;
  try {
    list = JSON.parse(fs.readFileSync(SOP_FILE, 'utf8'));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not read SOP data' });
  }

  const versions = list.filter(r => r.sopId === sopId);
  if (!versions.length) {
    return sendJson(res, 404, { ok: false, error: 'SOP not found: ' + sopId });
  }
  const latest = versions.slice().sort((a, b) => parseFloat(b.versionNumber) - parseFloat(a.versionNumber))[0];

  const now = new Date().toISOString();
  const record = {
    id: makeId('sopv'),
    sopId: sopId,
    versionNumber: nextVersionNumber(latest.versionNumber),
    changeSummary: (payload.changeSummary && String(payload.changeSummary).trim()) || 'Updated via SOP Admin.'
  };
  record.createdAt = now;
  record.createdBy = 'Admin';
  record.name = String(payload.name).trim();
  SOP_CONTENT_FIELDS.forEach(key => { record[key] = payload[key] ? String(payload[key]) : '<p></p>'; });

  list.push(record); // a new version, not a replacement — existing versions (and the sopId) are never removed

  try {
    fs.writeFileSync(SOP_FILE, JSON.stringify(list, null, 2) + '\n');
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Could not save SOP' });
  }
  sendJson(res, 200, { ok: true, record: record });
}

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent(req.url.split('?')[0]);

  // ---- Auth API — always reachable, logged in or not, so login/logout/me
  // themselves never get caught by the login gate further down.
  if (req.method === 'POST' && urlPath === '/api/auth/login') { handleLogin(req, res); return; }
  if (req.method === 'POST' && urlPath === '/api/auth/logout') { handleLogout(req, res); return; }
  if (req.method === 'GET' && urlPath === '/api/auth/me') { handleMe(req, res); return; }
  if (req.method === 'GET' && urlPath === '/api/notifications') { handleGetNotifications(req, res); return; }
  if (req.method === 'POST' && urlPath === '/api/notifications/mark-read') { handleMarkNotificationsRead(req, res); return; }
  if (req.method === 'GET' && urlPath === '/api/users') { handleGetUsers(req, res); return; }
  if (req.method === 'POST' && urlPath.indexOf('/api/users/') === 0 && urlPath.slice(-'/role'.length) === '/role') {
    const targetId = urlPath.slice('/api/users/'.length, -'/role'.length);
    handleSetUserRole(req, res, targetId);
    return;
  }

  // POST /api/expenses/<category> (create) and /api/expenses/<category>/<rowIndex>
  // (update) — Phase 1 Add New Entry / Edit Existing Entry. Both write to
  // the exact same file Upload Excel already writes to, so the public
  // /expenses/<category> report reflects it on its very next load.
  if (req.method === 'POST' && urlPath.indexOf('/api/expenses/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const rest = urlPath.slice('/api/expenses/'.length);
    const parts = rest.split('/');
    if (parts.length === 1) {
      handleCreateExpenseRow(req, res, parts[0]);
    } else if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      handleUpdateExpenseRow(req, res, parts[0], parseInt(parts[1], 10));
    } else {
      sendJson(res, 404, { ok: false, error: 'Not found' });
    }
    return;
  }
  // POST /api/field-config/<category> — Manage Headers save. Configuration-
  // level change (like "Manage application configuration"), so Super Admin
  // only — Admin can add/edit expense records but not redefine their fields.
  if (req.method === 'POST' && urlPath.indexOf('/api/field-config/') === 0) {
    if (!requireWriteAccess(req, res, { superAdminOnly: true })) return;
    const category = urlPath.slice('/api/field-config/'.length);
    handleSaveFieldConfig(req, res, category);
    return;
  }
  // POST /api/activities (create) and /api/activities/<id> (update) — the
  // single write path shared by Admin Console and any future activity entry.
  // POST /api/reports/<reportId> — replaces that report's stored data
  // wholesale with the parsed contents of an uploaded Excel file.
  if (req.method === 'POST' && urlPath.indexOf('/api/reports/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const reportId = urlPath.slice('/api/reports/'.length);
    handleSaveReport(req, res, reportId, () => addNotification('report', 'Report Updated', reportId + ' report was updated.'));
    return;
  }
  // POST /api/chatbot — read-only Q&A, available to every logged-in role
  // (including Auditor) — it never mutates application data.
  if (req.method === 'POST' && urlPath === '/api/chatbot') {
    if (!getSessionUser(req)) { sendJson(res, 401, { ok: false, error: 'Not authenticated.' }); return; }
    handleChatbot(req, res);
    return;
  }
  if (req.method === 'POST' && urlPath === '/api/activities') {
    if (!requireWriteAccess(req, res)) return;
    handleCollectionCreate(req, res, ACTIVITIES_FILE, ACTIVITY_REQUIRED_FIELDS, 'act');
    return;
  }
  if (req.method === 'POST' && urlPath.indexOf('/api/activities/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const id = urlPath.slice('/api/activities/'.length);
    handleCollectionUpdate(req, res, ACTIVITIES_FILE, id, ACTIVITY_REQUIRED_FIELDS);
    return;
  }
  if (req.method === 'POST' && urlPath === '/api/tickets') {
    if (!requireWriteAccess(req, res)) return;
    handleCollectionCreate(req, res, TICKETS_FILE, TICKET_REQUIRED_FIELDS, 'tkt');
    return;
  }
  if (req.method === 'POST' && urlPath.indexOf('/api/tickets/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const id = urlPath.slice('/api/tickets/'.length);
    handleCollectionUpdate(req, res, TICKETS_FILE, id, TICKET_REQUIRED_FIELDS);
    return;
  }
  // Admin Console → Booking Forms field editor save — configuration-level,
  // Super Admin only (same reasoning as /api/field-config/ above).
  if (req.method === 'POST' && urlPath.indexOf('/api/booking-field-config/') === 0) {
    if (!requireWriteAccess(req, res, { superAdminOnly: true })) return;
    const category = urlPath.slice('/api/booking-field-config/'.length);
    handleSaveBookingFieldConfig(req, res, category);
    return;
  }
  // New Bookings module APIs — deliberately a separate namespace
  // (/api/booking-<category>, singular/hyphenated) from the legacy
  // /api/bookings/* below, so a category slug like "cab" can never be
  // mistaken for a legacy booking id by that route's generic prefix match.
  // Required fields are computed fresh from booking-field-config.json on
  // every request (active && required), so an Admin Console change to which
  // fields are required takes effect immediately with no code change.
  if (req.method === 'POST' && urlPath.indexOf('/api/booking-') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const rest = urlPath.slice('/api/booking-'.length); // "cab" or "cab/<id>"
    const slashIdx = rest.indexOf('/');
    const category = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    const file = BOOKING_CATEGORY_FILES[category];
    if (!file) { sendJson(res, 404, { ok: false, error: 'Unknown booking category: ' + category }); return; }
    const requiredKeys = (getBookingFieldConfig(category) || []).filter(f => f.active && f.required).map(f => f.key);
    if (slashIdx === -1) {
      handleCollectionCreate(req, res, file, requiredKeys, 'bkc');
      addNotification('booking', 'New Booking Request', (BOOKING_CATEGORY_LABELS[category] || category) + ' request submitted.');
    } else {
      const id = rest.slice(slashIdx + 1);
      handleCollectionUpdate(req, res, file, id, requiredKeys);
    }
    return;
  }
  if (req.method === 'DELETE' && urlPath.indexOf('/api/booking-') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const rest = urlPath.slice('/api/booking-'.length);
    const slashIdx = rest.indexOf('/');
    const category = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    const file = BOOKING_CATEGORY_FILES[category];
    if (!file || slashIdx === -1) { sendJson(res, 404, { ok: false, error: 'Not found' }); return; }
    handleCollectionDelete(req, res, file, rest.slice(slashIdx + 1));
    return;
  }
  // POST /api/bookings (create), /api/bookings/import (bulk replace from
  // Excel — checked before the generic /api/bookings/<id> prefix below so
  // "import" is never mistaken for a booking id), /api/bookings/<id> (update).
  // This is the legacy Ground Transportation Booking collection — unchanged,
  // left fully intact; the new Bookings module above never reads or writes it.
  if (req.method === 'POST' && urlPath === '/api/bookings') {
    if (!requireWriteAccess(req, res)) return;
    handleCollectionCreate(req, res, BOOKINGS_FILE, BOOKING_REQUIRED_FIELDS, 'bkg');
    addNotification('booking', 'New Booking Request', 'Ground Transportation booking request submitted.');
    return;
  }
  if (req.method === 'POST' && urlPath === '/api/bookings/import') {
    if (!requireWriteAccess(req, res)) return;
    handleBookingsImport(req, res);
    return;
  }
  if (req.method === 'POST' && urlPath.indexOf('/api/bookings/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const id = urlPath.slice('/api/bookings/'.length);
    handleCollectionUpdate(req, res, BOOKINGS_FILE, id, BOOKING_REQUIRED_FIELDS);
    return;
  }
  if (req.method === 'POST' && urlPath === '/api/vendors') {
    if (!requireWriteAccess(req, res)) return;
    handleCollectionCreate(req, res, VENDORS_FILE, VENDOR_REQUIRED_FIELDS, 'vnd');
    return;
  }
  if (req.method === 'POST' && urlPath.indexOf('/api/vendors/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const id = urlPath.slice('/api/vendors/'.length);
    handleCollectionUpdate(req, res, VENDORS_FILE, id, VENDOR_REQUIRED_FIELDS);
    return;
  }
  // POST /api/sops (create) and /api/sops/<sopId> (edit — appends a new
  // version under the same sopId; see handleUpdateSop).
  if (req.method === 'POST' && urlPath === '/api/sops') {
    if (!requireWriteAccess(req, res)) return;
    handleCreateSop(req, res);
    return;
  }
  if (req.method === 'POST' && urlPath.indexOf('/api/sops/') === 0) {
    if (!requireWriteAccess(req, res)) return;
    const sopId = urlPath.slice('/api/sops/'.length);
    handleUpdateSop(req, res, sopId);
    return;
  }

  // ---- Login gate for everything below this point. Only the login page
  // itself and static presentation assets (styles/components/config/assets —
  // never business data) are reachable without a session, so the login
  // screen can render before anyone is authenticated. Every actual page AND
  // every file under /shared/data/ (the real records) requires a session —
  // this is a real server-side check, not just hiding a link in the nav.
  const PUBLIC_ASSET_PREFIXES = ['/shared/assets/', '/shared/styles/', '/shared/components/', '/shared/config/'];
  const isPublicAsset = PUBLIC_ASSET_PREFIXES.some(p => urlPath.indexOf(p) === 0) ||
    /^\/favicon\.(ico|svg)$/.test(urlPath) || urlPath.indexOf('apple-touch-icon') !== -1;
  if (req.method === 'GET' && urlPath !== '/login' && !isPublicAsset) {
    const sessionUser = getSessionUser(req);
    if (!sessionUser) {
      res.writeHead(302, { Location: '/login?next=' + encodeURIComponent(urlPath) });
      return res.end();
    }
    // Admin Console — Auditor never sees the real admin console (any sub-
    // path); User & Role Management is Super Admin only even for Admin.
    if (urlPath.indexOf('/admin-console') === 0) {
      const needsSuperAdmin = urlPath === '/admin-console/users';
      const blocked = sessionUser.role === ROLES.AUDITOR || (needsSuperAdmin && sessionUser.role !== ROLES.SUPER_ADMIN);
      if (blocked) {
        res.setHeader('Cache-Control', 'no-store');
        return serveFile(res, path.join(ROOT, 'pages', 'access-restricted.html'));
      }
    }
    // no-store keeps a signed-out browser's back/forward cache from
    // re-displaying an authenticated page without a fresh server check.
    res.setHeader('Cache-Control', 'no-store');
  }
  if (urlPath === '/login') {
    return serveFile(res, path.join(ROOT, 'pages', 'login.html'));
  }
  if (urlPath === '/admin-console/users') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-users.html'));
  }

  if (urlPath === '/' || urlPath === '/dashboard') {
    res.writeHead(302, { Location: '/pages/dashboard.html' });
    return res.end();
  }
  if (urlPath === '/admin-pro-hub') {
    res.writeHead(302, { Location: '/pages/admin-pro-hub.html' });
    return res.end();
  }
  // SOP library and SOP detail are served directly (not redirected) so the
  // address bar keeps showing /sop-admin and /sop-admin/<sopId> exactly —
  // the detail page reads the sopId itself from location.pathname.
  if (urlPath === '/sop-admin') {
    return serveFile(res, path.join(ROOT, 'pages', 'sop-library.html'));
  }
  if (urlPath.indexOf('/sop-admin/') === 0 && urlPath.length > '/sop-admin/'.length) {
    return serveFile(res, path.join(ROOT, 'pages', 'sop-detail.html'));
  }
  // Consolidated "All expenses, one view" — checked before the generic
  // per-category route below so "all" is never mistaken for a category slug.
  if (urlPath === '/expenses/all') {
    return serveFile(res, path.join(ROOT, 'pages', 'expenses-all.html'));
  }
  // One template page for every expense category — the category slug is
  // read client-side from location.pathname, same pattern as SOP detail.
  if (urlPath.indexOf('/expenses/') === 0 && urlPath.length > '/expenses/'.length) {
    return serveFile(res, path.join(ROOT, 'pages', 'expense-report.html'));
  }
  // Admin Console — top-level landing, one module-list page per module.
  if (urlPath === '/admin-console') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console.html'));
  }
  if (urlPath === '/admin-console/expenses') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-expenses.html'));
  }
  if (urlPath === '/admin-console/sop-admin') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-sop.html'));
  }
  if (urlPath === '/admin-console/bookings') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-bookings.html'));
  }
  // Booking Forms field editor — checked before any generic per-category
  // booking admin route so ".../bookings/<category>/fields" isn't swallowed.
  if (urlPath.indexOf('/admin-console/bookings/') === 0 && urlPath.slice(-'/fields'.length) === '/fields') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-booking-headers.html'));
  }
  // Manage Headers (Phase 1) — checked before the generic entry-form route
  // below so ".../expenses/<category>/headers" isn't swallowed by it.
  if (urlPath.indexOf('/admin-console/expenses/') === 0 && urlPath.slice(-'/headers'.length) === '/headers') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-expense-headers.html'));
  }
  // Per-category "add a new entry" — redirects to the report page's own
  // Add New Entry form (pages/expense-report.html, opened automatically via
  // ?action=add) rather than serving the old admin-console-expense-form.html,
  // which built its form from a `types` array that no longer exists on any
  // category's data since the Phase 1 field-config rework, and would throw
  // trying to read it. This keeps exactly one working Add New Entry
  // implementation instead of two that can drift out of sync.
  if (urlPath.indexOf('/admin-console/expenses/') === 0 && urlPath.length > '/admin-console/expenses/'.length) {
    const category = urlPath.slice('/admin-console/expenses/'.length);
    res.writeHead(302, { Location: '/expenses/' + category + '?action=add' });
    return res.end();
  }
  if (urlPath === '/admin-console/activities') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-activities.html'));
  }
  if (urlPath === '/admin-console/tickets') {
    return serveFile(res, path.join(ROOT, 'pages', 'admin-console-tickets.html'));
  }
  // Activities hub + its two sub-views.
  if (urlPath === '/activities') {
    return serveFile(res, path.join(ROOT, 'pages', 'activities.html'));
  }
  if (urlPath === '/task-lists') {
    return serveFile(res, path.join(ROOT, 'pages', 'task-lists.html'));
  }
  if (urlPath === '/tickets') {
    return serveFile(res, path.join(ROOT, 'pages', 'tickets.html'));
  }
  if (urlPath === '/reports') {
    return serveFile(res, path.join(ROOT, 'pages', 'reports.html'));
  }
  // Bookings hub — the new top-level module (Cab/Flight/Hotel/Courier
  // Booking + Vendor Database cards). The legacy single-category "Ground
  // Transportation Bookings" page still exists, completely unchanged, just
  // moved to its own explicit URL so it's no longer what "Bookings"
  // navigation lands on — see pages/bookings.html (untouched) below.
  if (urlPath === '/bookings') {
    return serveFile(res, path.join(ROOT, 'pages', 'bookings-hub.html'));
  }
  if (urlPath === '/bookings/ground-transport') {
    return serveFile(res, path.join(ROOT, 'pages', 'bookings.html'));
  }
  if (urlPath === '/bookings/vendors') {
    return serveFile(res, path.join(ROOT, 'pages', 'booking-vendors.html'));
  }
  // One template page for each of the 4 new booking categories — same
  // pattern as /expenses/<category> and /sop-admin/<sopId>: the category
  // slug is read client-side from location.pathname.
  if (urlPath.indexOf('/bookings/') === 0 && urlPath.length > '/bookings/'.length) {
    return serveFile(res, path.join(ROOT, 'pages', 'booking-category.html'));
  }

  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }
  serveFile(res, filePath);
});

ensureAllFieldConfigs();
ensureAllBookingFieldConfigs();
ensureUsersFile();
ensureNotificationsFile();

server.listen(PORT, () => {
  console.log(`Sears Admin Pro running at http://localhost:${PORT}/`);
  console.log(`  Dashboard:     http://localhost:${PORT}/pages/dashboard.html`);
  console.log(`  Admin Pro Hub: http://localhost:${PORT}/pages/admin-pro-hub.html`);
});
