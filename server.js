// ══════════════════════════════════════════════════════════
// UPPERCRUST ONE CRM v2 — Railway Backend
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
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

const {
  SUPABASE_URL, SUPABASE_SERVICE_KEY,
  JWT_SECRET = 'uc_crm_secret_change_me',
  PORT = 3000, ALLOWED_ORIGIN = '*',
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '10mb' }));

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  const { data: user, error } = await supabase.from('users').select('*').eq('username', username.toLowerCase().trim()).single();
  if (error || !user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role, rm_key: user.rm_key },
    JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role, rm_key: user.rm_key } });
});

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
// CLIENTS
// ════════════════════════════════════════════════
app.get('/api/clients', auth, async (req, res) => {
  const { page = 1, limit = 1000, sort = 'aum', xirr_filter, aum_filter, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  let q = supabase.from('clients').select('*', { count: 'exact' });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  if (search) q = q.or(`name.ilike.%${search}%,pan.ilike.%${search}%,mobile.ilike.%${search}%`);
  if (xirr_filter === 'hi') q = q.gte('xirr', 10);
  else if (xirr_filter === 'md') q = q.gte('xirr', 5).lt('xirr', 10);
  else if (xirr_filter === 'lo') q = q.gte('xirr', 0).lt('xirr', 5);
  else if (xirr_filter === 'ng') q = q.lt('xirr', 0);
  if (aum_filter === 'cr') q = q.gte('aum', 10000000);
  else if (aum_filter === '50l') q = q.gte('aum', 5000000).lt('aum', 10000000);
  else if (aum_filter === '10l') q = q.gte('aum', 1000000).lt('aum', 5000000);
  else if (aum_filter === 'sm') q = q.lt('aum', 1000000);
  const sortMap = { aum: 'aum', name: 'name', xirr: 'xirr', sip: 'sip_amount', sales: 'net_sales_fy' };
  const col = sortMap[sort] || 'aum';
  q = q.order(col, { ascending: sort === 'name' }).range(offset, offset + parseInt(limit) - 1);
  const { data, count, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data, total: count, page: parseInt(page), limit: parseInt(limit) });
});

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

// ════════════════════════════════════════════════
// IMPORT — INVESTORS LIST (admin only)
// ════════════════════════════════════════════════
app.post('/api/import/investors', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const df = XLSX.utils.sheet_to_json(ws);

  function sf(v) { if (!v && v !== 0) return 0; return parseFloat(String(v).replace(/,/g, '').trim()) || 0; }
  function ss(v) { return (v || '').toString().trim(); }
  function sb(v) { return v === 1 || v === '1' || v === true || v === 'Yes' || v === 'yes'; }

  const rows = df.map(row => ({
    name: ss(row['Investor']),
    rm_key: ss(row['Partner/Employee']),
    group_name: ss(row['Group']),
    pan: ss(row['PAN']),
    ucc: ss(row['UCC']),
    email: ss(row['Investor E-Mail Id.']),
    mobile: ss(row['Investor Mobile No.']),
    dob: ss(row['Date of Birth']),
    anniversary: ss(row['Anniversary Date']),
    age: sf(row['Investor Age (Years)']),
    age_in_nj: sf(row['Age In NJ (Years)']),
    location: ss(row['Location']),
    gender: ss(row['Gender']),
    tax_status: ss(row['Tax Status']),
    tag: ss(row['Tag']),
    status: ss(row['Status']),
    ewa_count: Math.round(sf(row['No. of EWA / EMFs'])),
    active_ewa: Math.round(sf(row['No. of Active E-Wealth Account'])),
    // AUM
    aum: sf(row['Total MF AUM (₹)']),
    aum_equity: sf(row['Equity AUM (₹)']),
    aum_debt: sf(row['Debt AUM (₹)']),
    aum_gold: sf(row['Gold  AUM (₹)']),
    aum_cash: sf(row['Cash AUM (₹)']),
    aum_pms: sf(row['PMS AUM (₹)']),
    aum_total: sf(row['Total AUM - MF + PMS (₹)']),
    aum_nj_rec: sf(row['NJ Rec. MF Portfolio  AUM']),
    eq_pct: sf(row['Equity AUM (% of Total AUM)']),
    sip_aum_pct: sf(row['MF SIP AUM to Total MF AUM (%)']),
    // Direct Equity
    direct_equity_aum: sf(row['Total Direct Equity AUM (₹)']),
    direct_equity_nj: sf(row['Direct Equity AUM (NJ) (₹)']),
    direct_equity_non_nj: sf(row['Direct Equity AUM (Non-NJ) (₹)']),
    // Returns
    xirr: sf(row['Investor XIRR - MF Total']),
    xirr_equity: sf(row['Investor XIRR - MF Equity']),
    xirr_debt: sf(row['Investor XIRR - MF Debt']),
    xirr_other: sf(row['Investor XIRR - MF Other']),
    // SIP
    sip_amount: sf(row['Live SIP Amount']),
    sip_count: Math.round(sf(row['No. of Live SIPs'])),
    sip_aum: sf(row['MF SIP AUM (₹)']),
    sip_net_fy: sf(row['MF Net SIP Sales (FY) (₹)']),
    sip_net_cy: sf(row['MF Net SIP Sales (CY) (₹)']),
    sip_gross_fy: sf(row['MF SIP Gross Sales(FY) (₹)']),
    sip_gross_cy: sf(row['MF SIP Gross Sales(CY) (₹)']),
    sip_closed_cy: sf(row['MF SIP Closed /Terminated (CY) (₹)']),
    sip_closed_fy: sf(row['MF SIP Closed /Terminated (FY) (₹)']),
    sip_topup: sf(row['Top-Up SIP Amount (₹)']),
    sip_gold: sf(row['Gold SIP Amount (₹)']),
    sip_change_2y: sf(row['Live SIP - Change in 2 Years (₹)']),
    sip_last_date: ss(row['Latest SIP Started On']),
    sip_gap: sf(row['Total SIP Gap Amount (₹)']),
    sip_elss: sf(row['Live SIP Amount in Tax Plans - ELSS (₹)']),
    sip_nj_rec: sf(row['NJ Rec. MF Portfolio -  Live SIP Amount']),
    sip_live_fy: sf(row['Total Live SIP Amount (FY) (₹)']),
    // NFO
    nfo_fy: sf(row['NFO Gross Sales (FY) (₹)']),
    nfo_cy: sf(row['NFO Gross Sales (CY) (₹)']),
    nfo_sip_fy: sf(row['NFO SIP Sales (FY) (₹)']),
    nfo_sip_cy: sf(row['NFO SIP Sales (CY) (₹)']),
    // Sales
    net_sales_fy: sf(row['MF Net Sales (FY) (₹)']),
    net_sales_cy: sf(row['MF Net Sales (CY) (₹)']),
    gross_sales_fy: sf(row['MF Gross Sales (FY) (₹)']),
    gross_sales_cy: sf(row['MF Gross Sales (CY) (₹)']),
    redemptions_fy: sf(row['MF Redemptions (FY) (₹)']),
    redemptions_cy: sf(row['MF Redemptions(CY) (₹)']),
    swp_amount: sf(row['Live SWP Amount (₹)']),
    swp_count: Math.round(sf(row['Live SWP Count'])),
    total_investment: sf(row['Total MF Investment (₹)']),
    net_investment: sf(row['MF Net Investment (₹)']),
    investment_age: sf(row['MF Investment Age in NJ (Years)']),
    fd_sales: sf(row['FD/Bond Sales (FY) (₹)']),
    fd_sales_cy: sf(row['FD/Bond Sales (CY) (₹)']),
    pms_sales: sf(row['NJ PMS Sales (FY) (₹)']),
    pms_sales_cy: sf(row['NJ PMS Sales (CY) (₹)']),
    tax_sales_fy: sf(row['Sales In TAX Plans (FY) (₹)']),
    tax_sales_cy: sf(row['Sales In TAX Plans (CY) (₹)']),
    lumpsum_gap: sf(row['Total Lumpsum Gap Amount (₹)']),
    // NJ Planning
    investment_mapping_done: sb(row['Investment mapping done']),
    needs_with_gap: Math.round(sf(row['No. of Mapped Need with gap'])),
    family_needs: Math.round(sf(row['No. of Family Needs'])),
    total_needs: Math.round(sf(row['Total needs Identified'])),
    // CRM
    open_tasks: Math.round(sf(row['Open Tasks'])),
    open_meetings: Math.round(sf(row['Open Meetings'])),
    imported_at: new Date().toISOString(),
  })).filter(r => r.name && r.rm_key);

  // Clear existing clients and insert fresh (daily refresh)
  await supabase.from('clients').delete().gte('imported_at', '2000-01-01');

  let inserted = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const batch = rows.slice(i, i + 200);
    const { error } = await supabase.from('clients').insert(batch);
    if (!error) inserted += batch.length;
    else console.error('Insert error:', error.message, JSON.stringify(batch[0]).slice(0, 200));
  }
  res.json({ ok: true, total: df.length, inserted });
});

// ════════════════════════════════════════════════
// IMPORT — FOLIO REPORT (admin only, HTML-based xls)
// ════════════════════════════════════════════════
app.post('/api/import/portfolio', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  let rows = [];
  const content = req.file.buffer.toString('utf8', 0, 100);

  if (content.includes('<') || content.includes('html') || content.includes('table')) {
    // HTML-based XLS — parse as HTML table
    const htmlContent = req.file.buffer.toString('utf8');
    const rowMatches = htmlContent.match(/<tr[^>]*>([\s\S]*?)<\/tr>/gi) || [];
    let headerRow = null;
    for (const row of rowMatches) {
      const cells = (row.match(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi) || [])
        .map(c => c.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ').trim());
      if (!headerRow && cells.includes('AMC') && cells.includes('Investor')) {
        headerRow = cells;
        continue;
      }
      if (headerRow && cells.length >= headerRow.length - 2 && cells[0] && !isNaN(cells[0])) {
        const obj = {};
        headerRow.forEach((h, i) => { obj[h] = cells[i] || ''; });
        rows.push(obj);
      }
    }
  } else {
    // Real XLS/XLSX
    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const raw = XLSX.utils.sheet_to_json(ws, { header: 1 });
    let hi = 0;
    for (let i = 0; i < Math.min(15, raw.length); i++) {
      if (raw[i].some(c => String(c).includes('AMC') || String(c).includes('Investor'))) { hi = i; break; }
    }
    const df = XLSX.utils.sheet_to_json(ws, { range: hi });
    rows = df;
  }

  function cn(v) { if (!v) return 0; return parseFloat(String(v).replace(/'/g, '').replace(/,/g, '').replace(/\s/g, '').trim()) || 0; }

  const folioRows = rows.map(row => ({
    client_name: (row['Investor'] || '').toString().trim(),
    rm_key: (row['Partner/Employee'] || '').toString().trim(),
    group_name: (row['Group'] || '').toString().trim(),
    client_ucc: (row['Client UCC'] || '').toString().trim(),
    amc: (row['AMC'] || '').toString().trim(),
    scheme: (row['Scheme'] || '').toString().trim(),
    option: (row['Option'] || '').toString().trim(),
    folio_number: (row['Folio No'] || '').toString().replace(/'/g, '').trim(),
    folio_status: (row['Folio Status'] || '').toString().trim(),
    units: cn(row['Balance Units']),
    current_value: cn(row['Current Value']),
    imported_at: new Date().toISOString(),
  })).filter(r => r.client_name && r.amc);

  // Link to client IDs
  const { data: clients } = await supabase.from('clients').select('id, name, pan');
  const clientMap = {};
  (clients || []).forEach(c => { clientMap[c.name?.toLowerCase().trim()] = c.id; });

  const enriched = folioRows.map(r => ({
    ...r,
    client_id: clientMap[r.client_name.toLowerCase().trim()] || null,
  }));

  // Clear old folios and insert fresh
  await supabase.from('folios').delete().gte('id', '00000000-0000-0000-0000-000000000000');

  let inserted = 0;
  for (let i = 0; i < enriched.length; i += 500) {
    const batch = enriched.slice(i, i + 500);
    const { error } = await supabase.from('folios').insert(batch);
    if (!error) inserted += batch.length;
    else console.error('Folio insert error:', error.message);
  }

  res.json({ ok: true, total: folioRows.length, inserted });
});

// ════════════════════════════════════════════════
// TASKS
// ════════════════════════════════════════════════
app.get('/api/tasks', auth, async (req, res) => {
  let q = supabase.from('tasks').select('*').order('due_date');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
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
  let q = supabase.from('tasks').update(req.body).eq('id', req.params.id);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q.select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  let q = supabase.from('tasks').delete().eq('id', req.params.id);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  await q;
  res.json({ ok: true });
});

// ════════════════════════════════════════════════
// MEETINGS
// ════════════════════════════════════════════════
app.get('/api/meetings', auth, async (req, res) => {
  let q = supabase.from('meetings').select('*').order('meeting_date', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q;
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
// LEADS
// ════════════════════════════════════════════════
app.get('/api/leads', auth, async (req, res) => {
  let q = supabase.from('leads').select('*').order('created_at', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
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
  let q = supabase.from('leads').update(req.body).eq('id', req.params.id);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q.select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/leads/:id', auth, async (req, res) => {
  let q = supabase.from('leads').delete().eq('id', req.params.id);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  await q;
  res.json({ ok: true });
});

// ════════════════════════════════════════════════
// REVIEWS
// ════════════════════════════════════════════════
app.get('/api/reviews', auth, async (req, res) => {
  let q = supabase.from('reviews').select('*').order('review_date', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  // Return map of client_id -> latest review
  const latest = {};
  (data || []).forEach(r => {
    if (!latest[r.client_id] || r.review_date > latest[r.client_id].review_date) latest[r.client_id] = r;
  });
  res.json(latest);
});

app.post('/api/reviews', auth, async (req, res) => {
  const { client_id, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date } = req.body;
  // Find client name
  const { data: cl } = await supabase.from('clients').select('name').eq('id', client_id).single();
  const { data, error } = await supabase.from('reviews').insert({
    rm_key: req.user.rm_key, client_id, client_name: cl?.name, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════
// DASHBOARD
// ════════════════════════════════════════════════
app.get('/api/dashboard', auth, async (req, res) => {
  let q = supabase.from('clients').select('aum,aum_equity,aum_debt,aum_gold,aum_cash,aum_pms,xirr,sip_amount,sip_count,net_sales_fy,gross_sales_fy,redemptions_fy,name,rm_key');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data: clients } = await q;
  const s = (arr, k) => arr.reduce((a, x) => a + (x[k] || 0), 0);
  res.json({
    total_clients: clients.length,
    total_aum: s(clients, 'aum'),
    total_equity: s(clients, 'aum_equity'),
    total_sip: s(clients, 'sip_amount'),
    net_sales_fy: s(clients, 'net_sales_fy'),
    avg_xirr: clients.length ? s(clients, 'xirr') / clients.length : 0,
  });
});

// ════════════════════════════════════════════════
// PORTFOLIO SUMMARY
// ════════════════════════════════════════════════
app.get('/api/portfolio/summary', auth, async (req, res) => {
  let q = supabase.from('folios').select('amc,scheme,current_value,units,client_name,client_id,rm_key,folio_status');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
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
    total_value: tv, total_folios: (folios || []).length, total_clients: clients.size,
    amc: Object.entries(amcAgg).map(([amc, d]) => ({ amc, value: d.value, folios: d.folios, clients: d.clients.size, schemes: d.schemes.size })).sort((a, b) => b.value - a.value),
    top_schemes: Object.values(schAgg).map(s => ({ ...s, clients: s.clients.size })).sort((a, b) => b.value - a.value).slice(0, 50),
  });
});

// ════════════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════════════
app.get('/api/admin/rm-summary', auth, adminOnly, async (req, res) => {
  const { data: clients } = await supabase.from('clients').select('rm_key,aum,net_sales_fy,sip_amount,xirr,redemptions_fy');
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

// All reviews — for admin to track RM review activity
app.get('/api/admin/all-reviews', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('reviews').select('*').order('review_date', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// All tasks — for admin activity feed
app.get('/api/admin/all-tasks', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('tasks').select('*').order('updated_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// All meetings — for admin activity feed
app.get('/api/admin/all-meetings', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('meetings').select('*').order('created_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString(), version: '2.0' }));

app.listen(PORT, () => console.log(`Uppercrust CRM v2 backend on port ${PORT}`));
