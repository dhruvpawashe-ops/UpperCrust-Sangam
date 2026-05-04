// ══════════════════════════════════════════════════════════
// UPPERCRUST ONE CRM v2 — Railway Backend COMPLETE
// server.js — Full rebuild with proper RM isolation + Admin
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

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) { console.error('ERROR: Set SUPABASE_URL and SUPABASE_SERVICE_KEY'); process.exit(1); }

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
// CLIENTS — RM ISOLATED
// ════════════════════════════════════════════════
app.get('/api/clients', auth, async (req, res) => {
  const { page = 1, limit = 2000, sort = 'aum' } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  let q = supabase.from('clients').select('*', { count: 'exact' });
  // STRICT RM isolation — RM sees ONLY their clients
  if (req.user.role !== 'admin') {
    if (!req.user.rm_key) return res.json({ data: [], total: 0, page: 1, limit: parseInt(limit) });
    q = q.eq('rm_key', req.user.rm_key);
  }
  const sortMap = { aum: 'aum', name: 'name', xirr: 'xirr', sip: 'sip_amount', sales: 'net_sales_fy' };
  q = q.order(sortMap[sort] || 'aum', { ascending: sort === 'name' }).range(offset, offset + parseInt(limit) - 1);
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
// IMPORT — INVESTORS (admin only, daily refresh)
// ════════════════════════════════════════════════
app.post('/api/import/investors', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const df = XLSX.utils.sheet_to_json(ws);

  function sf(v) { if (!v && v !== 0) return 0; return parseFloat(String(v).replace(/,/g, '').trim()) || 0; }
  function ss(v) { return (v || '').toString().trim(); }
  function sb(v) { return v === 1 || v === '1' || v === true || String(v).toLowerCase() === 'yes'; }

  const rows = df.map(row => ({
    name: ss(row['Investor']),
    rm_key: ss(row['Partner/Employee']),
    group_name: ss(row['Group']),
    pan: ss(row['PAN']) || null,
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
    direct_equity_aum: sf(row['Total Direct Equity AUM (₹)']),
    direct_equity_nj: sf(row['Direct Equity AUM (NJ) (₹)']),
    direct_equity_non_nj: sf(row['Direct Equity AUM (Non-NJ) (₹)']),
    xirr: sf(row['Investor XIRR - MF Total']),
    xirr_equity: sf(row['Investor XIRR - MF Equity']),
    xirr_debt: sf(row['Investor XIRR - MF Debt']),
    xirr_other: sf(row['Investor XIRR - MF Other']),
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
    nfo_fy: sf(row['NFO Gross Sales (FY) (₹)']),
    nfo_cy: sf(row['NFO Gross Sales (CY) (₹)']),
    nfo_sip_fy: sf(row['NFO SIP Sales (FY) (₹)']),
    nfo_sip_cy: sf(row['NFO SIP Sales (CY) (₹)']),
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
    investment_mapping_done: sb(row['Investment mapping done']),
    needs_with_gap: Math.round(sf(row['No. of Mapped Need with gap'])),
    family_needs: Math.round(sf(row['No. of Family Needs'])),
    total_needs: Math.round(sf(row['Total needs Identified'])),
    open_tasks: Math.round(sf(row['Open Tasks'])),
    open_meetings: Math.round(sf(row['Open Meetings'])),
    imported_at: new Date().toISOString(),
  })).filter(r => r.name && r.rm_key);

  // Clear old and insert fresh
  const { error: delErr } = await supabase.from('clients').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  if (delErr) console.error('Delete error:', delErr.message);

  let inserted = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const batch = rows.slice(i, i + 200);
    const { error } = await supabase.from('clients').insert(batch);
    if (!error) inserted += batch.length;
    else console.error('Insert error:', error.message);
  }
  res.json({ ok: true, total: df.length, inserted });
});

// ════════════════════════════════════════════════
// IMPORT — FOLIO REPORT (admin only)
// ════════════════════════════════════════════════
app.post('/api/import/portfolio', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  let rows = [];
  const content = req.file.buffer.toString('latin1', 0, 500);

  if (content.includes('<') || content.includes('html') || content.includes('table')) {
    const htmlContent = req.file.buffer.toString('utf8');
    // Parse HTML table - find all TR elements
    const trRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
    const tdRegex = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;
    let trMatch;
    let headerRow = null;
    while ((trMatch = trRegex.exec(htmlContent)) !== null) {
      const rowHtml = trMatch[1];
      const cells = [];
      let tdMatch;
      const tdReg = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;
      while ((tdMatch = tdReg.exec(rowHtml)) !== null) {
        cells.push(tdMatch[1].replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ').replace(/&#39;/g, '').replace(/'/g, '').trim());
      }
      if (!headerRow && cells.some(c => c === 'AMC') && cells.some(c => c === 'Investor')) {
        headerRow = cells;
        continue;
      }
      if (headerRow && cells.length >= 10 && cells[0] && /^\d+$/.test(cells[0].trim())) {
        const obj = {};
        headerRow.forEach((h, i) => { obj[h] = (cells[i] || '').trim(); });
        rows.push(obj);
      }
    }
  } else {
    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const raw = XLSX.utils.sheet_to_json(ws, { header: 1 });
    let hi = 0;
    for (let i = 0; i < Math.min(15, raw.length); i++) {
      if (raw[i]?.some(c => String(c).includes('AMC'))) { hi = i; break; }
    }
    rows = XLSX.utils.sheet_to_json(ws, { range: hi });
  }

  function cn(v) { return parseFloat(String(v || 0).replace(/'/g, '').replace(/,/g, '').replace(/\s/g, '').trim()) || 0; }

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

  // Get all clients for ID mapping (paginated)
  let allClients = []; let cfrom = 0;
  while (true) {
    const { data: cd } = await supabase.from('clients').select('id, name').range(cfrom, cfrom + 999);
    if (!cd || cd.length === 0) break;
    allClients = allClients.concat(cd);
    if (cd.length < 1000) break;
    cfrom += 1000;
  }
  const clientMap = {};
  allClients.forEach(c => { clientMap[c.name?.toLowerCase().trim()] = c.id; });
  const enriched = folioRows.map(r => ({ ...r, client_id: clientMap[r.client_name.toLowerCase().trim()] || null }));

  await supabase.from('folios').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  let inserted = 0;
  for (let i = 0; i < enriched.length; i += 500) {
    const { error } = await supabase.from('folios').insert(enriched.slice(i, i + 500));
    if (!error) inserted += 500;
  }
  res.json({ ok: true, total: folioRows.length, inserted: Math.min(inserted, folioRows.length) });
});

// ════════════════════════════════════════════════
// TASKS — RM ISOLATED
// ════════════════════════════════════════════════
app.get('/api/tasks', auth, async (req, res) => {
  const { rm_key } = req.query; // admin can filter by rm_key
  let q = supabase.from('tasks').select('*').order('due_date');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  else if (rm_key) q = q.eq('rm_key', rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/tasks', auth, async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admin cannot create tasks' });
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
// MEETINGS — RM ISOLATED
// ════════════════════════════════════════════════
app.get('/api/meetings', auth, async (req, res) => {
  const { rm_key } = req.query;
  let q = supabase.from('meetings').select('*').order('meeting_date', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  else if (rm_key) q = q.eq('rm_key', rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/meetings', auth, async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admin cannot log meetings' });
  const { client_name, client_id, meeting_date, notes, products_discussed, investment_intent, followup_date, status } = req.body;
  const { data, error } = await supabase.from('meetings').insert({
    rm_key: req.user.rm_key, client_name, client_id, meeting_date, notes, products_discussed, investment_intent, followup_date, status
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════
// LEADS — RM ISOLATED
// ════════════════════════════════════════════════
app.get('/api/leads', auth, async (req, res) => {
  const { rm_key } = req.query;
  let q = supabase.from('leads').select('*').order('created_at', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  else if (rm_key) q = q.eq('rm_key', rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/leads', auth, async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admin cannot create leads' });
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
// REVIEWS — RM ISOLATED
// ════════════════════════════════════════════════
app.get('/api/reviews', auth, async (req, res) => {
  const { rm_key } = req.query;
  let q = supabase.from('reviews').select('*').order('review_date', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  else if (rm_key) q = q.eq('rm_key', rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  const latest = {};
  (data || []).forEach(r => {
    if (!latest[r.client_id] || r.review_date > latest[r.client_id].review_date) latest[r.client_id] = r;
  });
  res.json(latest);
});

app.post('/api/reviews', auth, async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admin cannot log reviews' });
  const { client_id, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date } = req.body;
  const { data: cl } = await supabase.from('clients').select('name').eq('id', client_id).single();
  const { data, error } = await supabase.from('reviews').insert({
    rm_key: req.user.rm_key, client_id, client_name: cl?.name, review_date, xirr_at_review, aum_at_review, products_discussed, notes, next_review_date
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════
// PORTFOLIO SUMMARY
// ════════════════════════════════════════════════
app.get('/api/portfolio/summary', auth, async (req, res) => {
  const { rm_key } = req.query;
  // Paginate folios - can be 15000+ rows
  let folios = []; let ffrom = 0;
  while (true) {
    let q = supabase.from('folios').select('amc,scheme,current_value,units,client_name,client_id,rm_key,folio_status').range(ffrom, ffrom + 999);
    if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
    else if (rm_key) q = q.eq('rm_key', rm_key);
    const { data } = await q;
    if (!data || data.length === 0) break;
    folios = folios.concat(data);
    if (data.length < 1000) break;
    ffrom += 1000;
  }
  const amcAgg = {}, schAgg = {};
  const clients = new Set();
  let tv = 0;
  (folios || []).forEach(f => {
    tv += f.current_value || 0;
    clients.add(f.client_name);
    if (!amcAgg[f.amc]) amcAgg[f.amc] = { value: 0, folios: 0, clients: new Set(), schemes: new Set() };
    amcAgg[f.amc].value += f.current_value || 0; amcAgg[f.amc].folios++; amcAgg[f.amc].clients.add(f.client_name); amcAgg[f.amc].schemes.add(f.scheme);
    if (!schAgg[f.scheme]) schAgg[f.scheme] = { scheme: f.scheme, amc: f.amc, value: 0, folios: 0, clients: new Set() };
    schAgg[f.scheme].value += f.current_value || 0; schAgg[f.scheme].folios++; schAgg[f.scheme].clients.add(f.client_name);
  });
  res.json({
    total_value: tv, total_folios: (folios || []).length, total_clients: clients.size,
    amc: Object.entries(amcAgg).map(([amc, d]) => ({ amc, value: d.value, folios: d.folios, clients: d.clients.size, schemes: d.schemes.size })).sort((a, b) => b.value - a.value),
    top_schemes: Object.values(schAgg).map(s => ({ ...s, clients: s.clients.size })).sort((a, b) => b.value - a.value).slice(0, 50),
  });
});

// ════════════════════════════════════════════════
// ADMIN — COMPREHENSIVE RM ANALYTICS
// ════════════════════════════════════════════════

// Full RM summary from client data
app.get('/api/admin/rm-summary', auth, adminOnly, async (req, res) => {
  // Paginate to get ALL clients past Supabase 1000 row limit
  let clients = [];
  let from = 0;
  while (true) {
    const { data, error } = await supabase.from('clients').select(
      'rm_key,aum,aum_total,aum_equity,aum_debt,aum_pms,aum_gold,net_sales_fy,net_sales_cy,gross_sales_fy,gross_sales_cy,redemptions_fy,redemptions_cy,sip_amount,sip_count,sip_net_fy,sip_gross_fy,sip_closed_cy,sip_change_2y,sip_gap,lumpsum_gap,xirr,nfo_fy,fd_sales,pms_sales,tax_sales_fy,investment_mapping_done,family_needs,direct_equity_aum'
    ).range(from, from + 999);
    if (error || !data || data.length === 0) break;
    clients = clients.concat(data);
    if (data.length < 1000) break;
    from += 1000;
  }
  const rmS = {};
  (clients || []).forEach(c => {
    if (!c.rm_key) return;
    if (!rmS[c.rm_key]) rmS[c.rm_key] = {
      cl: 0, aum: 0, aum_total: 0, eq: 0, dbt: 0, pms: 0, gld: 0,
      net_fy: 0, net_cy: 0, gross_fy: 0, gross_cy: 0,
      rd_fy: 0, rd_cy: 0,
      sip: 0, sip_cl: 0, sip_net_fy: 0, sip_gross_fy: 0, sip_closed_cy: 0, sip_change_2y: 0,
      sip_gap: 0, lumpsum_gap: 0,
      xirr: 0, nfo_fy: 0, fd_sales: 0, pms_sales: 0, tax_sales: 0,
      mapped: 0, family_needs: 0, direct_eq: 0,
      hni: 0, affluent: 0, mid: 0, retail: 0,
    };
    const r = rmS[c.rm_key];
    r.cl++; r.aum += c.aum || 0; r.aum_total += c.aum_total || 0;
    r.eq += c.aum_equity || 0; r.dbt += c.aum_debt || 0; r.pms += c.aum_pms || 0; r.gld += c.aum_gold || 0;
    r.net_fy += c.net_sales_fy || 0; r.net_cy += c.net_sales_cy || 0;
    r.gross_fy += c.gross_sales_fy || 0; r.gross_cy += c.gross_sales_cy || 0;
    r.rd_fy += c.redemptions_fy || 0; r.rd_cy += c.redemptions_cy || 0;
    r.sip += c.sip_amount || 0; if ((c.sip_count || 0) > 0) r.sip_cl++;
    r.sip_net_fy += c.sip_net_fy || 0; r.sip_gross_fy += c.sip_gross_fy || 0;
    r.sip_closed_cy += c.sip_closed_cy || 0; r.sip_change_2y += c.sip_change_2y || 0;
    r.sip_gap += c.sip_gap || 0; r.lumpsum_gap += c.lumpsum_gap || 0;
    r.xirr += c.xirr || 0; r.nfo_fy += c.nfo_fy || 0;
    r.fd_sales += c.fd_sales || 0; r.pms_sales += c.pms_sales || 0; r.tax_sales += c.tax_sales_fy || 0;
    if (c.investment_mapping_done) r.mapped++;
    r.family_needs += c.family_needs || 0; r.direct_eq += c.direct_equity_aum || 0;
    const a = c.aum_total || c.aum || 0;
    if (a >= 1e7) r.hni++; else if (a >= 5e6) r.affluent++; else if (a >= 1e6) r.mid++; else r.retail++;
  });
  // Add avg xirr
  Object.keys(rmS).forEach(k => { rmS[k].avg_xirr = rmS[k].cl ? rmS[k].xirr / rmS[k].cl : 0; });
  res.json(rmS);
});

// All reviews with client names — for admin tracking
app.get('/api/admin/all-reviews', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('reviews').select('*').order('created_at', { ascending: false }).limit(1000);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// All tasks — for admin to see what each RM is doing
app.get('/api/admin/all-tasks', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('tasks').select('*').order('updated_at', { ascending: false }).limit(1000);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// All meetings
app.get('/api/admin/all-meetings', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('meetings').select('*').order('created_at', { ascending: false }).limit(1000);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// All leads — for admin to see RM pipeline
app.get('/api/admin/all-leads', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('leads').select('*').order('created_at', { ascending: false }).limit(1000);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── HEALTH ──
// ════════════════════════════════════════════════
// TARGETS — Admin sets per RM per period
// ════════════════════════════════════════════════

// GET all targets (admin sees all, RM sees own)
app.get('/api/targets', auth, async (req, res) => {
  const { period } = req.query;
  let q = supabase.from('rm_targets').select('*').order('rm_key');
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  if (period) q = q.eq('period', period);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// GET targets + actuals for a specific period (combines target with live Excel data)
app.get('/api/targets/progress', auth, async (req, res) => {
  const { period, rm_key } = req.query;
  const targetRM = (req.user.role !== 'admin') ? req.user.rm_key : (rm_key || null);

  // Get targets
  let tq = supabase.from('rm_targets').select('*');
  if (targetRM) tq = tq.eq('rm_key', targetRM);
  if (period) tq = tq.eq('period', period);
  const { data: targets } = await tq;

  // Get actuals from clients table (latest Excel data)
  let aq = supabase.from('clients').select(
    'rm_key,net_sales_fy,gross_sales_fy,net_sales_cy,sip_amount,sip_gross_fy,sip_net_fy,nfo_fy,fd_sales,pms_sales,tax_sales_fy,aum_total'
  );
  if (targetRM) aq = aq.eq('rm_key', targetRM);
  let clients = []; let fr = 0;
  while (true) {
    const { data } = await aq.range(fr, fr + 999);
    if (!data || data.length === 0) break;
    clients = clients.concat(data);
    if (data.length < 1000) break;
    fr += 1000;
  }

  // Aggregate actuals by RM
  const actuals = {};
  clients.forEach(c => {
    if (!c.rm_key) return;
    if (!actuals[c.rm_key]) actuals[c.rm_key] = {
      net_sales_fy: 0, gross_sales_fy: 0, net_sales_cy: 0,
      sip_amount: 0, sip_gross_fy: 0, sip_net_fy: 0,
      nfo_fy: 0, fd_sales: 0, pms_sales: 0, tax_sales_fy: 0, aum_total: 0
    };
    const a = actuals[c.rm_key];
    a.net_sales_fy += c.net_sales_fy || 0;
    a.gross_sales_fy += c.gross_sales_fy || 0;
    a.net_sales_cy += c.net_sales_cy || 0;
    a.sip_amount += c.sip_amount || 0;
    a.sip_gross_fy += c.sip_gross_fy || 0;
    a.sip_net_fy += c.sip_net_fy || 0;
    a.nfo_fy += c.nfo_fy || 0;
    a.fd_sales += c.fd_sales || 0;
    a.pms_sales += c.pms_sales || 0;
    a.tax_sales_fy += c.tax_sales_fy || 0;
    a.aum_total += c.aum_total || 0;
  });

  // Also get CRM actuals (reviews, meetings, leads)
  const [{ data: allRevs }, { data: allMeets }, { data: allLeads }] = await Promise.all([
    supabase.from('reviews').select('rm_key,created_at'),
    supabase.from('meetings').select('rm_key,created_at'),
    supabase.from('leads').select('rm_key,stage,created_at'),
  ]);

  const crmActuals = {};
  (allRevs || []).forEach(r => { if (!crmActuals[r.rm_key]) crmActuals[r.rm_key] = { reviews: 0, meetings: 0, leads: 0 }; crmActuals[r.rm_key].reviews++; });
  (allMeets || []).forEach(m => { if (!crmActuals[m.rm_key]) crmActuals[m.rm_key] = { reviews: 0, meetings: 0, leads: 0 }; crmActuals[m.rm_key].meetings++; });
  (allLeads || []).forEach(l => { if (!crmActuals[l.rm_key]) crmActuals[l.rm_key] = { reviews: 0, meetings: 0, leads: 0 }; crmActuals[l.rm_key].leads++; });

  // Merge targets with actuals
  const result = (targets || []).map(t => ({
    ...t,
    actuals: { ...(actuals[t.rm_key] || {}), ...(crmActuals[t.rm_key] || {}) }
  }));

  res.json(result);
});

// UPSERT target for a specific RM + period (admin only)
app.post('/api/targets', auth, adminOnly, async (req, res) => {
  const { rm_key, period, period_type, ...rest } = req.body;
  if (!rm_key || !period) return res.status(400).json({ error: 'rm_key and period required' });
  const { data, error } = await supabase.from('rm_targets').upsert(
    { rm_key, period, period_type: period_type || 'monthly', ...rest, updated_at: new Date().toISOString() },
    { onConflict: 'rm_key,period' }
  ).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/targets/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('rm_targets').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// GET all unique RM keys from clients (for target setting UI)
app.get('/api/admin/rm-list', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('clients').select('rm_key').limit(5000);
  const unique = [...new Set((data || []).map(c => c.rm_key).filter(Boolean))].sort();
  res.json(unique);
});

// Folios by scheme (for drill-down)
app.get('/api/folios/by-scheme', auth, async (req, res) => {
  const { scheme } = req.query;
  if (!scheme) return res.status(400).json({ error: 'scheme required' });
  let q = supabase.from('folios').select('client_name,client_id,folio_number,units,current_value,rm_key,folio_status')
    .eq('scheme', scheme).order('current_value', { ascending: false }).limit(100);
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Folios by client (for client profile)
app.get('/api/folios/by-client', auth, async (req, res) => {
  const { client_id } = req.query;
  if (!client_id) return res.status(400).json({ error: 'client_id required' });
  let q = supabase.from('folios').select('*').eq('client_id', client_id).order('current_value', { ascending: false });
  if (req.user.role !== 'admin') q = q.eq('rm_key', req.user.rm_key);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Token verify endpoint
app.get('/api/verify', auth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString(), version: '2.1' }));
app.listen(PORT, () => console.log(`Uppercrust CRM v2.1 on port ${PORT}`));
