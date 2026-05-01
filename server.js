// ══════════════════════════════════════════════════════════
// UPPERCRUST ONE CRM — Railway Backend
// server.js
// ══════════════════════════════════════════════════════════
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const XLSX = require('xlsx');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// ── ENV ──
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  JWT_SECRET = 'uc_crm_secret_change_me',
  PORT = 3000,
  ALLOWED_ORIGIN = '*',
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ── MIDDLEWARE ──
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '10mb' }));

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username.toLowerCase().trim())
    .single();

  if (error || !user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role, rm_key: user.rm_key },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role, rm_key: user.rm_key } });
});

// POST /api/seed-users — run once to create default users
app.post('/api/seed-users', async (req, res) => {
  const { admin_secret } = req.body;
  if (admin_secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });

  const USERS = [
    { username: 'admin',     password: 'admin123',   name: 'Admin',              role: 'admin', rm_key: null },
    { username: 'manoj',     password: 'manoj123',   name: 'Manoj Rohit',        role: 'rm',    rm_key: 'UpperCrust Wealth  Manoj Rohit' },
    { username: 'dhaval',    password: 'dhaval123',  name: 'Dhaval Patel',       role: 'rm',    rm_key: 'Dhaval Patel Associates' },
    { username: 'roshan',    password: 'roshan123',  name: 'Roshan Shah',        role: 'rm',    rm_key: 'Uppercrust Wealth Roshan Shah' },
    { username: 'hemant',    password: 'hemant123',  name: 'Hemant Patel',       role: 'rm',    rm_key: 'UpperCrust Wealth Hemant Patel' },
    { username: 'nidhi',     password: 'nidhi123',   name: 'Nidhi Jadav',        role: 'rm',    rm_key: 'Nidhi Jadav Yuvrajsinh Solanki' },
    { username: 'monika',    password: 'monika123',  name: 'Monika Khandelwal',  role: 'rm',    rm_key: 'Khandelwal Monika' },
    { username: 'isha',      password: 'isha123',    name: 'Isha Gil',           role: 'rm',    rm_key: 'UpperCrust Wealth Isha Gil' },
    { username: 'savan',     password: 'savan123',   name: 'Savan Dalsaniya',    role: 'rm',    rm_key: 'Savan Dalsaniya UpperCrust Wealth' },
    { username: 'harshilp',  password: 'harshilp1',  name: 'Harshil Patel',      role: 'rm',    rm_key: 'UpperCrust Wealth Harshil Patel' },
    { username: 'harshilpr', password: 'harshilpr2', name: 'Harshil Prajapati',  role: 'rm',    rm_key: 'UpperCrust Wealth Harshil Prajapati' },
    { username: 'krunal',    password: 'krunal123',  name: 'Krunal Patel',       role: 'rm',    rm_key: 'Krunalkumar Patel' },
  ];

  const results = [];
  for (const u of USERS) {
    const password_hash = await bcrypt.hash(u.password, 10);
    const { error } = await supabase.from('users').upsert(
      { username: u.username, password_hash, name: u.name, role: u.role, rm_key: u.rm_key },
      { onConflict: 'username' }
    );
    results.push({ username: u.username, ok: !error, error: error?.message });
  }
  res.json({ results });
});

// ════════════════════════════════════════════════
// CLIENT ROUTES
// ════════════════════════════════════════════════

// GET /api/clients — paginated, filtered
app.get('/api/clients', auth, async (req, res) => {
  const { page = 1, limit = 50, sort = 'aum', xirr_filter, aum_filter, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let q = supabase.from('clients').select('*', { count: 'exact' });

  // RM filter
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);

  // Search
  if (search) q = q.or(`name.ilike.%${search}%,pan.ilike.%${search}%,mobile.ilike.%${search}%`);

  // XIRR filter
  if (xirr_filter === 'hi') q = q.gte('xirr', 10);
  else if (xirr_filter === 'md') q = q.gte('xirr', 5).lt('xirr', 10);
  else if (xirr_filter === 'lo') q = q.gte('xirr', 0).lt('xirr', 5);
  else if (xirr_filter === 'ng') q = q.lt('xirr', 0);

  // AUM filter
  if (aum_filter === 'cr') q = q.gte('aum', 10000000);
  else if (aum_filter === '50l') q = q.gte('aum', 5000000).lt('aum', 10000000);
  else if (aum_filter === '10l') q = q.gte('aum', 1000000).lt('aum', 5000000);
  else if (aum_filter === 'sm') q = q.lt('aum', 1000000);

  // Sort
  const sortMap = { aum: 'aum', name: 'name', xirr: 'xirr', sip: 'sip_amount', sales: 'net_sales_fy' };
  const col = sortMap[sort] || 'aum';
  q = q.order(col, { ascending: sort === 'name' }).range(offset, offset + parseInt(limit) - 1);

  const { data, count, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data, total: count, page: parseInt(page), limit: parseInt(limit) });
});

// GET /api/clients/:id — single client with reviews, tasks
app.get('/api/clients/:id', auth, async (req, res) => {
  let q = supabase.from('clients').select('*').eq('id', req.params.id);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data: client, error } = await q.single();
  if (error) return res.status(404).json({ error: 'Not found' });

  const [{ data: reviews }, { data: tasks }, { data: meets }, { data: folios }] = await Promise.all([
    supabase.from('reviews').select('*').eq('client_id', req.params.id).order('review_date', { ascending: false }),
    supabase.from('tasks').select('*').eq('client_id', req.params.id).order('due_date'),
    supabase.from('meetings').select('*').eq('client_id', req.params.id).order('meeting_date', { ascending: false }),
    supabase.from('folios').select('*').eq('client_id', req.params.id).order('current_value', { ascending: false }),
  ]);

  res.json({ client, reviews: reviews || [], tasks: tasks || [], meetings: meets || [], folios: folios || [] });
});

// GET /api/clients/search/:q — quick search (for datalist)
app.get('/api/clients/search/:q', auth, async (req, res) => {
  let q = supabase.from('clients')
    .select('id, name, pan, aum, rm_key')
    .or(`name.ilike.%${req.params.q}%,pan.ilike.%${req.params.q}%`)
    .limit(10);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data } = await q;
  res.json(data || []);
});

// ════════════════════════════════════════════════
// IMPORT ROUTES
// ════════════════════════════════════════════════

// POST /api/import/investors — upload investorlist.xlsx
app.post('/api/import/investors', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const df = XLSX.utils.sheet_to_json(ws);

  function sf(v) {
    if (!v && v !== 0) return 0;
    return parseFloat(String(v).replace(/,/g, '').trim()) || 0;
  }

  const rows = df.map(row => ({
    name: (row['Investor'] || '').toString().trim(),
    rm_key: (row['Partner/Employee'] || '').toString().trim(),
    pan: (row['PAN'] || '').toString().trim(),
    email: (row['Investor E-Mail Id.'] || '').toString().trim(),
    mobile: (row['Investor Mobile No.'] || '').toString().trim(),
    dob: (row['Date of Birth'] || '').toString().trim(),
    anniversary: (row['Anniversary Date'] || '').toString().trim(),
    age: sf(row['Investor Age (Years)']),
    location: (row['Location'] || '').toString().trim(),
    gender: (row['Gender'] || '').toString().trim(),
    tax_status: (row['Tax Status'] || '').toString().trim(),
    aum: sf(row['Total MF AUM (₹)']),
    aum_equity: sf(row['Equity AUM (₹)']),
    aum_debt: sf(row['Debt AUM (₹)']),
    aum_gold: sf(row['Gold  AUM (₹)']),
    aum_cash: sf(row['Cash AUM (₹)']),
    aum_pms: sf(row['PMS AUM (₹)']),
    aum_total: sf(row['Total AUM - MF + PMS (₹)']),
    eq_pct: sf(row['Equity AUM (% of Total AUM)']),
    xirr: sf(row['Investor XIRR - MF Total']),
    xirr_equity: sf(row['Investor XIRR - MF Equity']),
    xirr_debt: sf(row['Investor XIRR - MF Debt']),
    sip_amount: sf(row['Live SIP Amount']),
    sip_count: Math.round(sf(row['No. of Live SIPs'])),
    sip_aum: sf(row['MF SIP AUM (₹)']),
    sip_aum_pct: sf(row['MF SIP AUM to Total MF AUM (%)']),
    sip_net_fy: sf(row['MF Net SIP Sales (FY) (₹)']),
    sip_net_cy: sf(row['MF Net SIP Sales (CY) (₹)']),
    sip_gross_fy: sf(row['MF SIP Gross Sales(FY) (₹)']),
    sip_closed_cy: sf(row['MF SIP Closed /Terminated (CY) (₹)']),
    sip_topup: sf(row['Top-Up SIP Amount (₹)']),
    sip_gold: sf(row['Gold SIP Amount (₹)']),
    sip_change_2y: sf(row['Live SIP - Change in 2 Years (₹)']),
    sip_last_date: (row['Latest SIP Started On'] || '').toString().trim(),
    sip_gap: sf(row['Total SIP Gap Amount (₹)']),
    sip_elss: sf(row['Live SIP Amount in Tax Plans - ELSS (₹)']),
    net_sales_fy: sf(row['MF Net Sales (FY) (₹)']),
    net_sales_cy: sf(row['MF Net Sales (CY) (₹)']),
    gross_sales_fy: sf(row['MF Gross Sales (FY) (₹)']),
    redemptions_fy: sf(row['MF Redemptions (FY) (₹)']),
    swp_amount: sf(row['Live SWP Amount (₹)']),
    swp_count: Math.round(sf(row['Live SWP Count'])),
    nfo_fy: sf(row['NFO Gross Sales (FY) (₹)']),
    total_investment: sf(row['Total MF Investment (₹)']),
    net_investment: sf(row['MF Net Investment (₹)']),
    investment_age: sf(row['MF Investment Age in NJ (Years)']),
    fd_sales: sf(row['FD/Bond Sales (FY) (₹)']),
    pms_sales: sf(row['NJ PMS Sales (FY) (₹)']),
    tax_sales_fy: sf(row['Sales In TAX Plans (FY) (₹)']),
    lumpsum_gap: sf(row['Total Lumpsum Gap Amount (₹)']),
    open_tasks: Math.round(sf(row['Open Tasks'])),
    open_meetings: Math.round(sf(row['Open Meetings'])),
    imported_at: new Date().toISOString(),
  })).filter(r => r.name);

  // Upsert in batches of 200
  let inserted = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const batch = rows.slice(i, i + 200);
    const { error } = await supabase.from('clients').upsert(batch, { onConflict: 'pan' });
    if (error) console.error('Batch error:', error.message);
    else inserted += batch.length;
  }

  res.json({ ok: true, total: df.length, inserted });
});

// POST /api/import/portfolio — upload folio report xlsx
app.post('/api/import/portfolio', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
  const ws = wb.Sheets[wb.SheetNames[0]];

  // Detect header row
  const rawData = XLSX.utils.sheet_to_json(ws, { header: 1 });
  let hr = 0;
  for (let i = 0; i < Math.min(10, rawData.length); i++) {
    if (rawData[i].some(c => String(c).includes('Partner') || String(c).includes('Investor'))) { hr = i; break; }
  }
  const df = XLSX.utils.sheet_to_json(ws, { range: hr });

  function cn(v) { if (!v) return 0; return parseFloat(String(v).replace(/'/g, '').replace(/,/g, '').trim()) || 0; }

  const rows = df.map(row => ({
    client_name: (row['Investor'] || '').toString().trim(),
    amc: (row['AMC'] || '').toString().trim(),
    scheme: (row['Scheme'] || '').toString().trim(),
    option: (row['Option'] || '').toString().trim(),
    folio_number: (row['Folio No'] || '').toString().trim(),
    units: cn(row['Balance Units']),
    current_value: cn(row['Current Value']),
    imported_at: new Date().toISOString(),
  })).filter(r => r.client_name && r.amc);

  // Try to link to client IDs
  const { data: clients } = await supabase.from('clients').select('id, name');
  const clientMap = {};
  (clients || []).forEach(c => { clientMap[c.name.toLowerCase().trim()] = c.id; });

  const enriched = rows.map(r => ({
    ...r,
    client_id: clientMap[r.client_name.toLowerCase().trim()] || null,
  }));

  // Delete old and insert fresh
  await supabase.from('folios').delete().neq('id', '00000000-0000-0000-0000-000000000000');

  let inserted = 0;
  for (let i = 0; i < enriched.length; i += 500) {
    const batch = enriched.slice(i, i + 500);
    const { error } = await supabase.from('folios').insert(batch);
    if (!error) inserted += batch.length;
  }

  res.json({ ok: true, total: df.length, inserted });
});

// ════════════════════════════════════════════════
// TASKS ROUTES
// ════════════════════════════════════════════════

app.get('/api/tasks', auth, async (req, res) => {
  let q = supabase.from('tasks').select('*').eq('rm_key', req.user.rm_key).order('due_date');
  if (req.user.role === 'admin' && req.query.all === 'true') {
    q = supabase.from('tasks').select('*').order('due_date');
  }
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/tasks', auth, async (req, res) => {
  const { client_name, client_id, task_type, priority, due_date, notes } = req.body;
  const { data, error } = await supabase.from('tasks').insert({
    rm_key: req.user.rm_key, client_name, client_id, task_type, priority, due_date, notes, status: 'pending'
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('tasks').update(req.body).eq('id', req.params.id).eq('rm_key', req.user.rm_key).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  await supabase.from('tasks').delete().eq('id', req.params.id).eq('rm_key', req.user.rm_key);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════
// MEETINGS ROUTES
// ════════════════════════════════════════════════

app.get('/api/meetings', auth, async (req, res) => {
  const { data, error } = await supabase.from('meetings').select('*').eq('rm_key', req.user.rm_key).order('meeting_date', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/meetings', auth, async (req, res) => {
  const { client_name, client_id, meeting_date, notes, products_discussed, investment_intent, followup_date, status } = req.body;
  const { data, error } = await supabase.from('meetings').insert({
    rm_key: req.user.rm_key, client_name, client_id, meeting_date, notes, products_discussed, investment_intent, followup_date, status
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════
// LEADS ROUTES
// ════════════════════════════════════════════════

app.get('/api/leads', auth, async (req, res) => {
  let q = supabase.from('leads').select('*').eq('rm_key', req.user.rm_key).order('created_at', { ascending: false });
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/leads', auth, async (req, res) => {
  const { name, phone, email, source, intent, products, priority, followup_date, notes } = req.body;
  const { data, error } = await supabase.from('leads').insert({
    rm_key: req.user.rm_key, name, phone, email, source, intent, products, priority, followup_date, notes, stage: 'prospect'
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.patch('/api/leads/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('leads').update(req.body).eq('id', req.params.id).eq('rm_key', req.user.rm_key).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/leads/:id', auth, async (req, res) => {
  await supabase.from('leads').delete().eq('id', req.params.id).eq('rm_key', req.user.rm_key);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════
// REVIEWS ROUTES
// ════════════════════════════════════════════════

app.get('/api/reviews', auth, async (req, res) => {
  // Returns map of client_id -> latest review
  let q = supabase.from('reviews').select('*').order('review_date', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });

  // Deduplicate to latest per client
  const latest = {};
  (data || []).forEach(r => {
    if (!latest[r.client_id] || r.review_date > latest[r.client_id].review_date) {
      latest[r.client_id] = r;
    }
  });
  res.json(latest);
});

app.post('/api/reviews', auth, async (req, res) => {
  const { client_id, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date, sip_reviewed, goal_reviewed, risk_reviewed, nomination_done } = req.body;
  const { data, error } = await supabase.from('reviews').insert({
    rm_key: req.user.rm_key, client_id, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date, sip_reviewed, goal_reviewed, risk_reviewed, nomination_done
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════
// ANALYTICS / DASHBOARD ROUTES
// ════════════════════════════════════════════════

app.get('/api/dashboard', auth, async (req, res) => {
  let q = supabase.from('clients').select('aum, aum_equity, aum_debt, aum_gold, aum_cash, aum_pms, xirr, sip_amount, sip_count, net_sales_fy, gross_sales_fy, redemptions_fy, name, rm_key');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data: clients } = await q;

  const s = (arr, k) => arr.reduce((a, x) => a + (x[k] || 0), 0);
  res.json({
    total_clients: clients.length,
    total_aum: s(clients, 'aum'),
    total_equity: s(clients, 'aum_equity'),
    total_debt: s(clients, 'aum_debt'),
    total_gold: s(clients, 'aum_gold'),
    total_cash: s(clients, 'aum_cash'),
    total_pms: s(clients, 'aum_pms'),
    total_sip: s(clients, 'sip_amount'),
    sip_clients: clients.filter(c => (c.sip_count || 0) > 0).length,
    net_sales_fy: s(clients, 'net_sales_fy'),
    gross_sales_fy: s(clients, 'gross_sales_fy'),
    redemptions_fy: s(clients, 'redemptions_fy'),
    avg_xirr: clients.length ? s(clients, 'xirr') / clients.length : 0,
    hni_count: clients.filter(c => c.aum >= 10000000).length,
    affluent_count: clients.filter(c => c.aum >= 5000000 && c.aum < 10000000).length,
    xirr_buckets: (() => {
      const b = { '<0': 0, '0-5': 0, '5-10': 0, '10-15': 0, '15-20': 0, '>20': 0 };
      clients.forEach(c => {
        const x = c.xirr || 0;
        if (x < 0) b['<0']++;
        else if (x < 5) b['0-5']++;
        else if (x < 10) b['5-10']++;
        else if (x < 15) b['10-15']++;
        else if (x < 20) b['15-20']++;
        else b['>20']++;
      });
      return b;
    })(),
  });
});

// GET /api/portfolio/summary — AMC/scheme aggregates from folios
app.get('/api/portfolio/summary', auth, async (req, res) => {
  let q = supabase.from('folios').select('amc, scheme, current_value, units, client_name, client_id');
  if (req.user.role !== 'admin') {
    // Get client IDs for this RM
    const { data: rmClients } = await supabase.from('clients').select('id').eq('rm_key', req.user.rm_key);
    const ids = (rmClients || []).map(c => c.id);
    q = q.in('client_id', ids);
  }
  const { data: folios } = await q;

  const amcAgg = {}, schAgg = {};
  const clients = new Set();
  let tv = 0;

  (folios || []).forEach(f => {
    tv += f.current_value || 0;
    clients.add(f.client_name);
    if (!amcAgg[f.amc]) amcAgg[f.amc] = { value: 0, folios: 0, clients: new Set(), schemes: new Set() };
    amcAgg[f.amc].value += f.current_value || 0;
    amcAgg[f.amc].folios++;
    amcAgg[f.amc].clients.add(f.client_name);
    amcAgg[f.amc].schemes.add(f.scheme);
    if (!schAgg[f.scheme]) schAgg[f.scheme] = { scheme: f.scheme, amc: f.amc, value: 0, folios: 0, clients: new Set() };
    schAgg[f.scheme].value += f.current_value || 0;
    schAgg[f.scheme].folios++;
    schAgg[f.scheme].clients.add(f.client_name);
  });

  res.json({
    total_value: tv,
    total_folios: folios.length,
    total_clients: clients.size,
    amc: Object.entries(amcAgg)
      .map(([amc, d]) => ({ amc, value: d.value, folios: d.folios, clients: d.clients.size, schemes: d.schemes.size }))
      .sort((a, b) => b.value - a.value),
    top_schemes: Object.values(schAgg)
      .map(s => ({ ...s, clients: s.clients.size }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 50),
  });
});

// GET /api/admin/rm-summary — admin only
app.get('/api/admin/rm-summary', auth, adminOnly, async (req, res) => {
  const { data: clients } = await supabase.from('clients').select('rm_key, aum, net_sales_fy, sip_amount, xirr, redemptions_fy');
  const rmS = {};
  (clients || []).forEach(c => {
    if (!c.rm_key) return;
    if (!rmS[c.rm_key]) rmS[c.rm_key] = { cl: 0, aum: 0, sales: 0, sip: 0, xirr: 0, rd: 0 };
    rmS[c.rm_key].cl++;
    rmS[c.rm_key].aum += c.aum || 0;
    rmS[c.rm_key].sales += c.net_sales_fy || 0;
    rmS[c.rm_key].sip += c.sip_amount || 0;
    rmS[c.rm_key].xirr += c.xirr || 0;
    rmS[c.rm_key].rd += c.redemptions_fy || 0;
  });
  res.json(rmS);
});

// ── HEALTH ──
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.listen(PORT, () => console.log(`Uppercrust CRM backend running on port ${PORT}`));
