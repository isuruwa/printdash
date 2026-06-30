'use strict';
const express = require('express');
const snmp    = require('net-snmp');
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const os      = require('os');
const { execFile, exec } = require('child_process');
const crypto  = require('crypto');
const app  = express();
const PORT = 3003;

// ── Auth: users + sessions ──────────────────────────────────────────────────────
const USERS_FILE = process.env.USERS_FILE || './users.json';
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(check,'hex')); } catch { return false; }
}
function loadUsers() {
  try { if (fs.existsSync(USERS_FILE)) return JSON.parse(fs.readFileSync(USERS_FILE,'utf8')); } catch {}
  // first-run defaults — CHANGE THESE PASSWORDS after first login
  const defaults = [
    { username:'admin', role:'admin', password: hashPassword('admin123') },
    { username:'user',  role:'user',  password: hashPassword('user123') },
  ];
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(defaults,null,2)); } catch {}
  return defaults;
}
function saveUsers() { try { fs.writeFileSync(USERS_FILE, JSON.stringify(USERS,null,2)); } catch {} }
let USERS = loadUsers();

const sessions = new Map(); // token -> {username, role, exp}
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username:user.username, role:user.role, exp:Date.now()+SESSION_TTL_MS });
  return token;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i>-1) out[p.slice(0,i).trim()] = decodeURIComponent(p.slice(i+1).trim());
  });
  return out;
}
function getSession(req) {
  const token = parseCookies(req).session;
  if (!token) return null;
  const s = sessions.get(token);
  if (!s || s.exp < Date.now()) { sessions.delete(token); return null; }
  return s;
}
// API routes the 'user' role IS allowed to use (everything else is admin-only)
const USER_ALLOWED = [
  /^\/api\/me$/, /^\/api\/logout$/,
  /^\/api\/printers$/, /^\/api\/printers\/refresh$/,
  /^\/api\/cups\/printers$/, /^\/api\/print$/, /^\/api\/cups\/jobs$/,
  /^\/api\/scans/,
];
app.use((req, res, next) => {
  if (req.path === '/login' || req.path === '/api/login') return next();
  const session = getSession(req);
  if (!session) {
    if (req.path.startsWith('/api/')) return res.status(401).json({error:'Not authenticated'});
    return res.redirect('/login');
  }
  req.user = session;
  if (req.path.startsWith('/api/') && session.role !== 'admin') {
    const allowed = USER_ALLOWED.some(re => re.test(req.path));
    if (!allowed) return res.status(403).json({error:'Forbidden — admin access required'});
  }
  next();
});
app.get('/login', (_req,res) => res.send(LOGIN_HTML));
app.post('/api/login', express.json(), (req,res) => {
  const { username, password } = req.body || {};
  const user = USERS.find(u => u.username === username);
  if (!user || !verifyPassword(password||'', user.password)) {
    return res.status(401).json({error:'Invalid username or password'});
  }
  const token = createSession(user);
  res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS/1000}; SameSite=Lax`);
  res.json({ok:true, role:user.role});
});
app.post('/api/logout', (req,res) => {
  const token = parseCookies(req).session;
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ok:true});
});
app.get('/api/me', (req,res) => res.json({username:req.user.username, role:req.user.role}));
app.get('/api/users', (_req,res) => {
  res.json({users: USERS.map(u=>({username:u.username, role:u.role}))});
});
app.post('/api/users', express.json(), (req,res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || !['admin','user'].includes(role)) return res.status(400).json({error:'username, password, and valid role required'});
  if (USERS.find(u=>u.username===username)) return res.status(409).json({error:'username already exists'});
  USERS.push({ username, role, password: hashPassword(password) });
  saveUsers();
  res.json({ok:true});
});
app.put('/api/users/:username', express.json(), (req,res) => {
  const u = USERS.find(x=>x.username===req.params.username);
  if (!u) return res.status(404).json({error:'not found'});
  const { password, role } = req.body || {};
  if (role) { if (!['admin','user'].includes(role)) return res.status(400).json({error:'invalid role'}); u.role = role; }
  if (password) u.password = hashPassword(password);
  saveUsers();
  res.json({ok:true});
});
app.delete('/api/users/:username', (req,res) => {
  if (req.params.username === req.user.username) return res.status(400).json({error:"can't delete your own account"});
  if (USERS.filter(u=>u.role==='admin').length<=1 && USERS.find(u=>u.username===req.params.username)?.role==='admin')
    return res.status(400).json({error:'cannot delete the last admin'});
  USERS = USERS.filter(x=>x.username!==req.params.username);
  saveUsers();
  for (const [token,s] of sessions) if (s.username===req.params.username) sessions.delete(token);
  res.json({ok:true});
});

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>PrintDash Login</title>
<style>
body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0f172a;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:32px;width:300px}
h1{color:#f1f5f9;font-size:1.1rem;margin:0 0 20px;display:flex;align-items:center;gap:8px}
label{color:#94a3b8;font-size:.8rem;display:block;margin-bottom:4px}
input{width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:9px 10px;color:#f1f5f9;margin-bottom:14px;font-size:.85rem}
button{width:100%;background:#3b82f6;color:#fff;border:none;border-radius:8px;padding:10px;font-weight:600;cursor:pointer;font-size:.85rem}
button:disabled{opacity:.6}
#err{color:#f87171;font-size:.78rem;margin-bottom:10px;min-height:14px}
</style></head><body>
<div class="card">
  <h1>🖨 PrintDash</h1>
  <div id="err"></div>
  <label>Username</label><input id="u" autofocus/>
  <label>Password</label><input id="p" type="password"/>
  <button id="btn" onclick="doLogin()">Sign In</button>
</div>
<script>
document.getElementById('p').addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); });
async function doLogin(){
  const btn=document.getElementById('btn'), err=document.getElementById('err');
  btn.disabled=true; err.textContent='';
  try{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    const d = await r.json();
    if (d.ok) location.href='/'; else { err.textContent=d.error||'Login failed'; btn.disabled=false; }
  } catch(e){ err.textContent='Network error'; btn.disabled=false; }
}
</script></body></html>`;

const DATA_FILE  = process.env.DATA_FILE  || './printers.json';
const SCAN_DIR   = process.env.SCAN_DIR   || '/opt/scans';
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/tmp/printdash-uploads';

[SCAN_DIR, UPLOAD_DIR].forEach(d => { try { fs.mkdirSync(d, { recursive: true }); } catch {} });

// ── Persistence ───────────────────────────────────────────────────────────────
function loadPrinters() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch {}
  return [{ id:1, name:'Canon-IT', ip:'192.168.18.211', brand:'canon', location:'IT Dept', community:'public' }];
}
function savePrinters() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(PRINTERS,null,2)); } catch {}
}
let PRINTERS = loadPrinters();

// ── Settings (Telegram + discovery) ────────────────────────────────────────────
const SETTINGS_FILE = process.env.SETTINGS_FILE || './settings.json';
const DEFAULT_SETTINGS = {
  telegram: { enabled:false, botToken:'', chatId:'', alertToner:true, tonerThreshold:20,
              alertOffline:true, alertJams:true, alertTrayEmpty:true, cooldownMinutes:240 },
  network: { scanSubnet:'' }
};
function loadSettings() {
  try { if (fs.existsSync(SETTINGS_FILE)) return {...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE,'utf8'))}; } catch {}
  return {...DEFAULT_SETTINGS};
}
function saveSettings() { try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(SETTINGS,null,2)); } catch {} }
let SETTINGS = loadSettings();

// ── Telegram ──────────────────────────────────────────────────────────────────
function sendTelegram(text, tokenOverride, chatIdOverride) {
  const token = tokenOverride || SETTINGS.telegram.botToken;
  const chatId = chatIdOverride || SETTINGS.telegram.chatId;
  return new Promise(resolve => {
    if (!token || !chatId) return resolve({ok:false,error:'Missing bot token or chat ID'});
    const payload = JSON.stringify({chat_id:chatId, text, parse_mode:'HTML'});
    const req = https.request({
      hostname:'api.telegram.org', path:`/bot${token}/sendMessage`, method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)},
      timeout:8000,
    }, res => {
      let data=''; res.on('data',c=>data+=c);
      res.on('end',()=>{ try { resolve(JSON.parse(data)); } catch { resolve({ok:false,raw:data}); } });
    });
    req.on('error', e => resolve({ok:false,error:e.message}));
    req.on('timeout', () => { req.destroy(); resolve({ok:false,error:'timeout'}); });
    req.write(payload); req.end();
  });
}

// Dedup/cooldown tracker so we don't spam every 3-minute poll
const lastSent = {}; // key -> timestamp ms
function shouldSend(key) {
  const cd = (SETTINGS.telegram.cooldownMinutes||240)*60*1000;
  const now = Date.now();
  if (lastSent[key] && now-lastSent[key] < cd) return false;
  lastSent[key] = now;
  return true;
}

async function checkAlerts(newP, oldP) {
  const t = SETTINGS.telegram;
  if (!t.enabled || !t.botToken || !t.chatId) return;
  const tag = `<b>${esc(newP.name)}</b> (${newP.ip})`;

  // Offline / back online
  if (t.alertOffline) {
    if (newP.online===false && (!oldP || oldP.online!==false)) {
      if (shouldSend(`${newP.id}:offline`)) await sendTelegram(`🔴 ${tag} went OFFLINE`);
    } else if (newP.online===true && oldP && oldP.online===false) {
      delete lastSent[`${newP.id}:offline`];
      await sendTelegram(`🟢 ${tag} is back ONLINE`);
    }
  }

  // Low toner (with hysteresis: re-alert only after cooldown)
  if (t.alertToner && newP.online && newP.toners) {
    for (const tn of newP.toners) {
      if (tn.unknown) continue;
      if (tn.pct < (t.tonerThreshold||20)) {
        const key = `${newP.id}:toner:${tn.name}`;
        if (shouldSend(key)) await sendTelegram(`🟡 ${tag} — <b>${esc(tn.name)}</b> low: ${tn.pct}%`);
      }
    }
  }

  // Tray empty
  if (t.alertTrayEmpty && newP.online && newP.trays) {
    for (const tr of newP.trays) {
      if (tr.pct===0) {
        const key = `${newP.id}:tray:${tr.name}`;
        if (shouldSend(key)) await sendTelegram(`📄 ${tag} — <b>${esc(tr.name)}</b> is empty`);
      }
    }
  }

  // New alerts (jams, cover open, service requested, etc.)
  if (t.alertJams && newP.online && newP.alerts && newP.alerts.length) {
    const oldDescs = new Set((oldP&&oldP.alerts||[]).map(a=>a.desc));
    for (const a of newP.alerts) {
      if (!oldDescs.has(a.desc)) {
        const key = `${newP.id}:alert:${a.desc}`;
        if (shouldSend(key)) await sendTelegram(`⚠️ ${tag} — ${esc(a.severity)}: ${esc(a.desc)}`);
      }
    }
  }
}
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── Page history ───────────────────────────────────────────────────────────────
const pageHistory = {};

// ── SNMP OIDs ─────────────────────────────────────────────────────────────────
const OID = {
  sysDescr:'1.3.6.1.2.1.1.1.0', sysUpTime:'1.3.6.1.2.1.1.3.0',
  sysContact:'1.3.6.1.2.1.1.4.0', sysName:'1.3.6.1.2.1.1.5.0', sysLocation:'1.3.6.1.2.1.1.6.0',
  macAddress:'1.3.6.1.2.1.2.2.1.6.1', memSize:'1.3.6.1.2.1.25.2.2.0',
  deviceDesc:'1.3.6.1.2.1.25.3.2.1.3.1', deviceState:'1.3.6.1.2.1.25.3.2.1.5.1',
  deviceErrors:'1.3.6.1.2.1.25.3.2.1.6.1', printerStatus:'1.3.6.1.2.1.25.3.5.1.1.1',
  serialNumber:'1.3.6.1.2.1.43.5.1.1.17.1', pageCount:'1.3.6.1.2.1.43.10.2.1.4.1.1',
  tonerName:'1.3.6.1.2.1.43.11.1.1.6.1', tonerMax:'1.3.6.1.2.1.43.11.1.1.8.1',
  tonerCurrent:'1.3.6.1.2.1.43.11.1.1.9.1', colorant:'1.3.6.1.2.1.43.12.1.1.4.1',
  consoleDisplay:'1.3.6.1.2.1.43.16.5.1.2.1.1', alertTable:'1.3.6.1.2.1.43.18.1.1',
  trayName:'1.3.6.1.2.1.43.8.2.1.13.1', trayCapacity:'1.3.6.1.2.1.43.8.2.1.9.1',
  trayLevel:'1.3.6.1.2.1.43.8.2.1.10.1', trayStatus:'1.3.6.1.2.1.43.8.2.1.11.1',
};
const PRINTER_STATUS = {1:'Other',2:'Unknown',3:'Idle',4:'Printing',5:'Warmup',6:'Stopped',7:'Offline'};
const ALERT_SEVERITY = {1:'Other',2:'Critical',3:'Warning',4:'Informational'};
const ALERT_CODES    = {1:'Cover Open',3:'Paper Jam',4:'Paper Out',5:'Offline',6:'Service Requested',
  7:'Input Tray Missing',8:'Output Full',9:'Marker Supply Empty',11:'Output Near Full',12:'Input Tray Empty'};

function bufToStr(v) {
  if (!v) return null;
  if (Buffer.isBuffer(v)) return v.toString('utf8').replace(/\0/g,'').trim();
  return String(v).trim();
}
function snmpGetMulti(ip, community, oids) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:4000,retries:1,version:snmp.Version1});
    s.get(oids, (err, vb) => {
      s.close();
      if (err) return resolve(null);
      const r = {};
      vb.forEach((v,i) => { r[oids[i]] = snmp.isVarbindError(v) ? null : v.value; });
      resolve(r);
    });
  });
}
function snmpWalk(ip, community, oid) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:4000,retries:1,version:snmp.Version1});
    const res = [];
    s.subtree(oid, 30, vb => vb.forEach(v => { if (!snmp.isVarbindError(v)) res.push({oid:v.oid,value:v.value}); }),
      () => { s.close(); resolve(res); });
  });
}

function formatUptime(sec) {
  const d=Math.floor(sec/86400), h=Math.floor((sec%86400)/3600), m=Math.floor((sec%3600)/60);
  return d>0?`${d}d ${h}h ${m}m`:h>0?`${h}h ${m}m`:`${m}m`;
}

function parseAlerts(walk) {
  const groups = {};
  walk.forEach(e => {
    const p=e.oid.split('.'), col=parseInt(p[p.length-2]), idx=p[p.length-1];
    if (!groups[idx]) groups[idx]={};
    groups[idx][col]=e.value;
  });
  return Object.values(groups).map(g => {
    const severity = ALERT_SEVERITY[g[2]]||'Info';
    const code     = g[4] ? ALERT_CODES[Number(g[4])] : null;
    const desc     = bufToStr(g[8])||code||'Unknown Alert';
    return desc && desc!=='Sleep' && desc!=='Unknown Alert' ? {severity,desc} : null;
  }).filter(Boolean);
}

async function getPrinterData(printer) {
  const {ip,community} = printer;
  try {
    const basic = await snmpGetMulti(ip, community, [
      OID.sysDescr,OID.sysUpTime,OID.sysContact,OID.sysName,OID.sysLocation,
      OID.macAddress,OID.memSize,OID.deviceDesc,OID.deviceState,OID.deviceErrors,
      OID.printerStatus,OID.serialNumber,OID.pageCount,OID.consoleDisplay,
    ]);
    if (!basic) return {...printer,online:false,status:'Offline',toners:[],trays:[],alerts:[],pages:null,pageHistory:pageHistory[printer.id]||[]};

    const uptimeSec = basic[OID.sysUpTime] ? Math.floor(Number(basic[OID.sysUpTime])/100) : 0;
    let mac = basic[OID.macAddress];
    if (Buffer.isBuffer(mac)) mac = Array.from(mac).map(b=>b.toString(16).padStart(2,'0')).join(':').toUpperCase();
    const status = PRINTER_STATUS[basic[OID.printerStatus]]||'Unknown';
    const pages  = basic[OID.pageCount]!=null ? Number(basic[OID.pageCount]) : null;
    const model  = bufToStr(basic[OID.deviceDesc])||bufToStr(basic[OID.sysDescr])||printer.name;
    const serial = bufToStr(basic[OID.serialNumber]);
    const console_msg = bufToStr(basic[OID.consoleDisplay]);
    const memKB  = basic[OID.memSize] ? Number(basic[OID.memSize]) : null;

    const [nameW,maxW,curW,colorW,trayNW,trayCW,trayLW,traySW,alertW] = await Promise.all([
      snmpWalk(ip,community,OID.tonerName), snmpWalk(ip,community,OID.tonerMax),
      snmpWalk(ip,community,OID.tonerCurrent), snmpWalk(ip,community,OID.colorant),
      snmpWalk(ip,community,OID.trayName), snmpWalk(ip,community,OID.trayCapacity),
      snmpWalk(ip,community,OID.trayLevel), snmpWalk(ip,community,OID.trayStatus),
      snmpWalk(ip,community,OID.alertTable),
    ]);

    const toners = nameW.map((n,i) => {
      let name = bufToStr(n.value)||`Supply ${i+1}`;
      const max = maxW[i]?Number(maxW[i].value):100;
      const cur = curW[i]?Number(curW[i].value):0;
      const pct = max>0 ? Math.max(0,Math.round((cur/max)*100)) : (cur===-3?-1:0);
      const colorStr = colorW[i] ? bufToStr(colorW[i].value)||'' : '';
      const nl=(name+colorStr).toLowerCase();
      let color='#64748b';
      if (nl.includes('black')||nl.includes('bk')||nl.includes('mono')) color='#1e293b';
      else if (nl.includes('cyan')||nl.includes(' c ')||nl.includes('cy')) color='#0ea5e9';
      else if (nl.includes('magenta')||nl.includes(' m ')||nl.includes('mg')) color='#d946ef';
      else if (nl.includes('yellow')||nl.includes(' y ')||nl.includes('yl')) color='#eab308';
      else if (nl.includes('fuser')||nl.includes('drum')||nl.includes('kit')||nl.includes('waste')) color='#f97316';
      return {name,pct:pct===-1?100:pct,color,unknown:pct===-1};
    });

    const trays = trayNW.map((t,i) => {
      const name=bufToStr(t.value)||`Tray ${i+1}`;
      const cap=trayCW[i]?Number(trayCW[i].value):0;
      const lvl=trayLW[i]?Number(trayLW[i].value):0;
      const stat=traySW[i]?Number(traySW[i].value):0;
      const pct=cap>0?Math.min(100,Math.max(0,Math.round((lvl/cap)*100))):(lvl>0?50:0);
      const statusMap={1:'Other',2:'Unknown',3:'Available',4:'Printing',5:'Busy',6:'Offline'};
      return {name,capacity:cap,level:lvl,pct,status:statusMap[stat]||'Unknown'};
    });

    const alerts = parseAlerts(alertW);

    if (pages!==null) {
      if (!pageHistory[printer.id]) pageHistory[printer.id]=[];
      const hist=pageHistory[printer.id], last=hist[hist.length-1];
      if (!last||last.pages!==pages) { hist.push({time:new Date().toISOString(),pages}); if(hist.length>48)hist.shift(); }
    }

    return {...printer,online:true,status,model:model.substring(0,60),serial,mac,memKB,
      uptime:formatUptime(uptimeSec),uptimeSec,pages,pageHistory:pageHistory[printer.id]||[],
      console_msg,toners,trays,alerts,lastChecked:new Date().toISOString()};
  } catch { return {...printer,online:false,status:'Offline',toners:[],trays:[],alerts:[],pages:null,pageHistory:pageHistory[printer.id]||[]}; }
}

// ── Cache ─────────────────────────────────────────────────────────────────────
let cache = {data:[],updatedAt:null};
let polling = false;
async function refreshAll() {
  if (polling) return;
  polling=true;
  try {
    const oldData = cache.data;
    const newData = await Promise.all(PRINTERS.map(getPrinterData));
    cache.data=newData; cache.updatedAt=new Date().toISOString();
    for (const p of newData) {
      const old = oldData.find(o=>o.id===p.id);
      checkAlerts(p, old).catch(()=>{});
    }
  }
  finally { polling=false; }
}
refreshAll();
setInterval(refreshAll, 1*60*1000);

// ── Multer ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req,_file,cb) => cb(null, UPLOAD_DIR),
  filename: (_req,file,cb) => cb(null, Date.now()+'-'+file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_')),
});
const upload = multer({ storage, limits:{fileSize:50*1024*1024} });

// ── CUPS helpers ──────────────────────────────────────────────────────────────
function listCupsPrinters() {
  return new Promise(resolve => {
    exec('lpstat -p 2>/dev/null || echo ""', (err,stdout) => {
      const printers=[];
      (stdout||'').split('\n').forEach(line => {
        const m=line.match(/^printer\s+(\S+)\s+/);
        if (m) printers.push(m[1]);
      });
      resolve(printers);
    });
  });
}

function printFile(filePath, printerName, copies, duplex) {
  return new Promise((resolve,reject) => {
    const args=['-d', printerName, '-n', String(copies||1)];
    if (duplex==='long') args.push('-o','sides=two-sided-long-edge');
    else if (duplex==='short') args.push('-o','sides=two-sided-short-edge');
    args.push(filePath);
    execFile('lp', args, (err,stdout,stderr) => {
      if (err) return reject(new Error(stderr||err.message));
      const m=(stdout||'').match(/request id is (\S+)/);
      resolve({jobId:m?m[1]:null,message:stdout.trim()});
    });
  });
}

function getJobStatus() {
  return new Promise(resolve => {
    exec('lpstat -o 2>/dev/null || echo ""', (err,stdout) => {
      const jobs=[];
      (stdout||'').split('\n').forEach(line => {
        if (line.trim()) jobs.push(line.trim());
      });
      resolve(jobs);
    });
  });
}
function getCompletedJobs() {
  return new Promise(resolve => {
    exec('lpstat -W completed -o 2>/dev/null || echo ""', (err,stdout) => {
      const jobs=(stdout||'').split('\n').map(l=>l.trim()).filter(Boolean);
      resolve(jobs);
    });
  });
}
function cancelJob(jobId) {
  return new Promise((resolve,reject) => {
    execFile('cancel', [jobId], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function setPrinterEnabled(name, enabled) {
  return new Promise((resolve,reject) => {
    execFile(enabled?'cupsenable':'cupsdisable', [name], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function setDefaultPrinter(name) {
  return new Promise((resolve,reject) => {
    execFile('lpadmin', ['-d', name], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function getCupsPrinterDetail() {
  return new Promise(resolve => {
    exec('lpstat -p -d 2>/dev/null || echo ""', (err,stdout) => {
      const lines=(stdout||'').split('\n');
      let defaultPrinter=null;
      const printers=[];
      lines.forEach(line=>{
        const dm=line.match(/system default destination:\s*(\S+)/i);
        if (dm) defaultPrinter=dm[1];
        const pm=line.match(/^printer\s+(\S+)\s+(is idle|is printing|disabled)/i);
        if (pm) printers.push({name:pm[1], state:pm[2]});
      });
      resolve({defaultPrinter, printers});
    });
  });
}
// Discover printers CUPS can see (network/IPP/DNS-SD) without adding them yet
function lpinfoDiscover() {
  return new Promise(resolve => {
    exec('lpinfo -v 2>/dev/null || echo ""', (err,stdout) => {
      const found=[];
      (stdout||'').split('\n').forEach(line=>{
        const m=line.trim().match(/^(network|direct)\s+(\S+)$/);
        if (m) found.push({kind:m[1], uri:m[2]});
      });
      resolve(found);
    });
  });
}
function lpadminAddPrinter(name, uri) {
  return new Promise((resolve,reject) => {
    const safe = name.replace(/[^a-zA-Z0-9_-]/g,'_');
    execFile('lpadmin', ['-p', safe, '-E', '-v', uri, '-m', 'everywhere'], (err,stdout,stderr) => {
      if (err) return reject(new Error(stderr||err.message));
      resolve(safe);
    });
  });
}

// ── SNMP subnet discovery ──────────────────────────────────────────────────────
function guessLocalSubnet() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const ifc of ifaces[name]) {
      if (ifc.family==='IPv4' && !ifc.internal) {
        const parts = ifc.address.split('.');
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      }
    }
  }
  return '192.168.1.0/24';
}
function snmpProbe(ip, community) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:600,retries:0,version:snmp.Version1});
    s.get([OID.sysDescr], (err, vb) => {
      s.close();
      if (err || !vb || snmp.isVarbindError(vb[0])) return resolve(null);
      resolve(bufToStr(vb[0].value));
    });
  });
}
async function discoverSnmpDevices(cidr, community) {
  const base = (cidr||'').split('/')[0].split('.').slice(0,3).join('.');
  if (!base) return [];
  const ips = Array.from({length:254}, (_,i)=>`${base}.${i+1}`);
  const results = [];
  const BATCH=32;
  for (let i=0;i<ips.length;i+=BATCH) {
    const batch = ips.slice(i,i+BATCH);
    const res = await Promise.all(batch.map(async ip => {
      const descr = await snmpProbe(ip, community);
      return descr ? {ip, descr} : null;
    }));
    res.forEach(r=>{ if (r) results.push(r); });
  }
  return results;
}

// ── Scan folder helpers ───────────────────────────────────────────────────────
function listScans() {
  try {
    return fs.readdirSync(SCAN_DIR)
      .filter(f => /\.(pdf|jpg|jpeg|png|tiff?|bmp)$/i.test(f))
      .map(f => {
        const stat = fs.statSync(path.join(SCAN_DIR,f));
        return {name:f, size:stat.size, mtime:stat.mtime.toISOString()};
      })
      .sort((a,b) => new Date(b.mtime)-new Date(a.mtime));
  } catch { return []; }
}

// ── eSCL scan trigger (scanimage / sane-airscan) ───────────────────────────────
function listScanDevices() {
  return new Promise(resolve => {
    exec('scanimage -L 2>/dev/null', (err, stdout) => {
      const devices = [];
      (stdout || '').split('\n').forEach(line => {
        const m = line.match(/device `([^']+)' is a (.+)/);
        if (m) devices.push({ id: m[1], label: m[2] });
      });
      resolve(devices);
    });
  });
}
function triggerScan(deviceId, source) {
  return new Promise((resolve, reject) => {
    if (!deviceId) return reject(new Error('No scanner device specified'));
    const file = path.join(SCAN_DIR, `scan-${Date.now()}.pdf`);
    const args = ['-d', deviceId, '--format=pdf', '-o', file];
    if (source && source !== 'Flatbed') args.push('--source', source);
    execFile('scanimage', args, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      resolve(path.basename(file));
    });
  });
}

// ── API routes ────────────────────────────────────────────────────────────────
app.use(express.json());

// Printers CRUD
app.get('/api/printers',         (_req,res) => res.json(cache));
app.get('/api/printers/refresh', async (_req,res) => { await refreshAll(); res.json(cache); });
app.post('/api/printers', (req,res) => {
  const {name,ip,brand,location,community}=req.body;
  if (!name||!ip) return res.status(400).json({error:'name and ip required'});
  const id=Date.now();
  PRINTERS.push({id,name,ip,brand:brand||'generic',location:location||'',community:community||'public'});
  savePrinters(); refreshAll(); res.json({ok:true,id});
});
app.put('/api/printers/:id', (req,res) => {
  const idx=PRINTERS.findIndex(p=>p.id===Number(req.params.id));
  if (idx===-1) return res.status(404).json({error:'not found'});
  PRINTERS[idx]={...PRINTERS[idx],...req.body,id:PRINTERS[idx].id};
  savePrinters(); refreshAll(); res.json({ok:true});
});
app.delete('/api/printers/:id', (req,res) => {
  PRINTERS=PRINTERS.filter(p=>p.id!==Number(req.params.id));
  cache.data=cache.data.filter(p=>p.id!==Number(req.params.id));
  savePrinters(); res.json({ok:true});
});

// Print jobs
app.get('/api/cups/printers', async (_req,res) => {
  const list = await listCupsPrinters();
  res.json({printers:list});
});
app.get('/api/cups/jobs', async (_req,res) => {
  const jobs = await getJobStatus();
  res.json({jobs});
});
app.post('/api/print', upload.single('file'), async (req,res) => {
  if (!req.file) return res.status(400).json({error:'No file uploaded'});
  const {printer, copies, duplex} = req.body;
  if (!printer) return res.status(400).json({error:'printer name required'});
  try {
    const result = await printFile(req.file.path, printer, copies||1, duplex||'none');
    res.json({ok:true,...result});
  } catch(e) {
    res.status(500).json({error:e.message});
  } finally {
    try { fs.unlinkSync(req.file.path); } catch {}
  }
});

// Scans
app.get('/api/scans', (_req,res) => res.json({scans:listScans(), dir:SCAN_DIR}));
app.get('/api/scans/download/:name', (req,res) => {
  const name = path.basename(req.params.name);
  const full = path.join(SCAN_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({error:'not found'});
  res.download(full);
});
app.delete('/api/scans/:name', (req,res) => {
  const name = path.basename(req.params.name);
  const full = path.join(SCAN_DIR, name);
  try { fs.unlinkSync(full); res.json({ok:true}); }
  catch { res.status(500).json({error:'could not delete'}); }
});
app.get('/api/scans/devices', async (_req,res) => {
  res.json({devices: await listScanDevices()});
});
app.post('/api/scans/trigger', async (req,res) => {
  const { device, source } = req.body || {};
  try { const name = await triggerScan(device, source); res.json({ok:true, name}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

// Samba setup helper — returns config snippet
app.get('/api/samba-config', (_req,res) => {
  const conf=`[scans]\n   path = ${SCAN_DIR}\n   browseable = yes\n   read only = no\n   guest ok = yes\n   create mask = 0777\n   directory mask = 0777`;
  res.json({config:conf, dir:SCAN_DIR});
});

// Settings + Telegram
app.get('/api/settings', (_req,res) => res.json(SETTINGS));
app.post('/api/settings', (req,res) => {
  SETTINGS = {...SETTINGS, ...req.body,
    telegram:{...SETTINGS.telegram, ...(req.body.telegram||{})},
    network:{...SETTINGS.network, ...(req.body.network||{})}};
  saveSettings();
  res.json({ok:true, settings:SETTINGS});
});
app.post('/api/settings/test-telegram', async (req,res) => {
  const {botToken, chatId} = req.body;
  const r = await sendTelegram('✅ PrintDash test message — Telegram alerts are working.', botToken, chatId);
  if (r && r.ok) res.json({ok:true});
  else res.status(400).json({ok:false, error:(r&&(r.description||r.error))||'Failed to send'});
});

// SNMP subnet discovery
app.get('/api/discover/snmp', async (req,res) => {
  const cidr = req.query.cidr || SETTINGS.network.scanSubnet || guessLocalSubnet();
  const community = req.query.community || 'public';
  try {
    const found = await discoverSnmpDevices(cidr, community);
    const existingIps = new Set(PRINTERS.map(p=>p.ip));
    res.json({cidr, results: found.map(f=>({...f, alreadyAdded: existingIps.has(f.ip)}))});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.get('/api/discover/subnet-guess', (_req,res) => res.json({cidr: guessLocalSubnet()}));

// CUPS network discovery (lpinfo) + one-click add via lpadmin
app.get('/api/cups/discover', async (_req,res) => {
  try { res.json({found: await lpinfoDiscover()}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/discover/add', async (req,res) => {
  const {name, uri} = req.body;
  if (!name||!uri) return res.status(400).json({error:'name and uri required'});
  try { const finalName = await lpadminAddPrinter(name, uri); res.json({ok:true, name:finalName}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

// CUPS job management
app.get('/api/cups/jobs/history', async (_req,res) => res.json({jobs: await getCompletedJobs()}));
app.post('/api/cups/jobs/:jobId/cancel', async (req,res) => {
  try { await cancelJob(req.params.jobId); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

// CUPS printer management
app.get('/api/cups/printers/detail', async (_req,res) => res.json(await getCupsPrinterDetail()));
app.post('/api/cups/printers/:name/pause', async (req,res) => {
  try { await setPrinterEnabled(req.params.name, false); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/printers/:name/resume', async (req,res) => {
  try { await setPrinterEnabled(req.params.name, true); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/printers/:name/default', async (req,res) => {
  try { await setDefaultPrinter(req.params.name); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

// ── (more routes appended below) ──────────────────────────────────────────────


app.get('/', (_req,res) => res.send(HTML.replace('</head>', `<script>window.USER_ROLE=${JSON.stringify(_req.user.role)};window.USERNAME=${JSON.stringify(_req.user.username)};</script></head>`)));

// ── HTML ──────────────────────────────────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PrintDash</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--surface:#1e293b;--surface2:#0f172a;--border:#334155;--border2:#1e3a5f;
  --text:#e2e8f0;--muted:#64748b;--subtle:#94a3b8;
  --blue:#3b82f6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--orange:#f97316;
}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.layout{display:flex;min-height:100vh}
.sidebar{width:224px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:20;overflow-y:auto}
.sidebar-logo{padding:18px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;font-weight:700;font-size:1rem;color:#f1f5f9}
.sidebar-logo svg{color:var(--blue);flex-shrink:0}
.sidebar-nav{flex:1;padding:12px 8px;overflow-y:auto}
.nav-section{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:10px 12px 4px;margin-top:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:.84rem;color:var(--subtle);transition:all .15s;margin-bottom:2px;user-select:none}
.nav-item:hover{background:rgba(255,255,255,.06);color:var(--text)}
.nav-item.active{background:rgba(59,130,246,.15);color:var(--blue)}
.nav-item svg{flex-shrink:0;opacity:.7}.nav-item.active svg{opacity:1}
.nbadge{margin-left:auto;background:#ef444433;color:#f87171;border:1px solid #7f1d1d;border-radius:999px;padding:1px 7px;font-size:.7rem}
.sidebar-footer{padding:12px;border-top:1px solid var(--border);font-size:.72rem;color:var(--muted)}
.main{margin-left:224px;flex:1;display:flex;flex-direction:column}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.header-title{font-size:1.05rem;font-weight:700;color:#f1f5f9}
.header-sub{font-size:.75rem;color:var(--muted);margin-top:1px}
.hactions{display:flex;gap:8px;align-items:center}
.content{padding:24px;max-width:1400px;margin:0 auto;width:100%}
button{cursor:pointer;border:none;border-radius:8px;padding:8px 16px;font-size:.84rem;font-weight:600;transition:all .15s}
.btn-primary{background:var(--blue);color:#fff}.btn-primary:hover{background:#2563eb}
.btn-outline{background:transparent;color:var(--subtle);border:1px solid var(--border)}.btn-outline:hover{background:rgba(255,255,255,.05);color:var(--text)}
.btn-sm{padding:5px 12px;font-size:.78rem}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#dc2626}
.data-table{width:100%;border-collapse:collapse;margin-top:8px}
.data-table th{text-align:left;font-size:.72rem;text-transform:uppercase;color:var(--muted);padding:8px;border-bottom:1px solid var(--border)}
.data-table td{padding:10px 8px;border-bottom:1px solid var(--border);font-size:.84rem}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.74rem;font-weight:600}
.btn-ghost{background:transparent;color:var(--subtle);padding:6px 10px}.btn-ghost:hover{color:var(--text)}
.btn-green{background:#16a34a;color:#fff}.btn-green:hover{background:#15803d}
.btn-amber{background:#b45309;color:#fff}.btn-amber:hover{background:#92400e}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
.stat-label{font-size:.7rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
.stat-value{font-size:1.9rem;font-weight:700;color:#f1f5f9;line-height:1}
.stat-value.green{color:var(--green)}.stat-value.red{color:var(--red)}.stat-value.amber{color:var(--amber)}.stat-value.blue{color:var(--blue)}
.stat-sub{font-size:.7rem;color:var(--muted);margin-top:4px}
.printer-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:20px}
.pcard{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;transition:border-color .2s}
.pcard:hover{border-color:#475569}.pcard.offline{opacity:.65}
.pcard-header{padding:16px 18px 12px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.pcard-name{font-size:1rem;font-weight:700;color:#f1f5f9}
.pcard-model{font-size:.74rem;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:230px}
.pcard-badges{display:flex;gap:6px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:.7rem;font-weight:600;white-space:nowrap}
.badge.idle{background:#0c4a6e33;color:#38bdf8;border:1px solid #0c4a6e}
.badge.printing{background:#78350f33;color:#fbbf24;border:1px solid #78350f}
.badge.online{background:#14532d33;color:#4ade80;border:1px solid #14532d}
.badge.offline{background:#450a0a33;color:#f87171;border:1px solid #450a0a}
.badge.warn{background:#78350f33;color:#fcd34d;border:1px solid #92400e}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dot.on{background:#4ade80;animation:pulse 2s infinite}.dot.off{background:#ef4444}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.pcard-tabs{display:flex;border-bottom:1px solid var(--border);padding:0 18px;overflow-x:auto}
.tab{padding:9px 13px;font-size:.76rem;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap;flex-shrink:0}
.tab:hover{color:var(--text)}.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.pcard-body{padding:14px 18px}
.tab-panel{display:none}.tab-panel.active{display:block}
.toner-list,.tray-list{display:flex;flex-direction:column;gap:9px}
.toner-row,.tray-row{}
.toner-meta,.tray-meta{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.toner-name,.tray-name{font-size:.77rem;color:var(--subtle)}
.toner-pct{font-size:.77rem;font-weight:600}.toner-pct.warn{color:var(--red)}
.tray-stat{font-size:.77rem;color:var(--muted)}
.track{height:9px;background:#0f172a;border-radius:999px;overflow:hidden;border:1px solid var(--border2)}
.fill{height:100%;border-radius:999px;transition:width .6s ease}
.fill.low{animation:blink 1.4s infinite}
.fill.tray{background:var(--blue)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.info-item{background:var(--surface2);border-radius:8px;padding:9px 12px}
.info-label{font-size:.68rem;color:var(--muted);margin-bottom:3px;text-transform:uppercase;letter-spacing:.04em}
.info-value{font-size:.8rem;color:var(--text);word-break:break-all;font-family:monospace}
.alert-list{display:flex;flex-direction:column;gap:7px}
.alert-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;font-size:.8rem}
.alert-item.Critical{background:#450a0a33;border:1px solid #7f1d1d;color:#fca5a5}
.alert-item.Warning{background:#78350f33;border:1px solid #92400e;color:#fcd34d}
.alert-item.Informational{background:#0c4a6e33;border:1px solid #075985;color:#7dd3fc}
.no-data{color:var(--muted);font-size:.8rem;padding:16px 0;text-align:center}
.ok-icon{font-size:2rem;display:block;margin-bottom:8px}
.pages-big{text-align:center;padding:12px 0}
.pages-num{font-size:2.8rem;font-weight:700;color:#f1f5f9;line-height:1}
.pages-label{font-size:.77rem;color:var(--muted);margin-top:4px}
.mini-chart{display:flex;align-items:flex-end;gap:2px;height:50px;padding:0 2px;margin-top:12px}
.mini-bar{flex:1;background:var(--blue);border-radius:2px 2px 0 0;opacity:.7;min-height:3px}
.console-msg{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--amber);font-family:monospace}
.pcard-footer{padding:10px 18px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.footer-ip{font-size:.72rem;color:var(--muted);font-family:monospace}
.footer-actions{display:flex;gap:6px}

/* Print panel */
.print-panel{display:flex;flex-direction:column;gap:12px}
.drop-zone{border:2px dashed var(--border);border-radius:10px;padding:24px;text-align:center;cursor:pointer;transition:border-color .2s;color:var(--muted);font-size:.84rem}
.drop-zone:hover,.drop-zone.drag{border-color:var(--blue);color:var(--text)}
.drop-zone input{display:none}
.drop-zone .icon{font-size:2rem;margin-bottom:8px}
.print-opts{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.field-sm label{display:block;font-size:.72rem;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.field-sm select,.field-sm input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:7px 10px;color:var(--text);font-size:.84rem;outline:none}
.field-sm select:focus,.field-sm input:focus{border-color:var(--blue)}
.print-status{padding:9px 12px;border-radius:8px;font-size:.8rem}
.print-status.ok{background:#14532d33;color:#4ade80;border:1px solid #14532d}
.print-status.err{background:#450a0a33;color:#fca5a5;border:1px solid #7f1d1d}

/* Scan view */
.scan-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.scan-table{width:100%;border-collapse:collapse}
.scan-table th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)}
.scan-table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:.83rem}
.scan-table tr:hover td{background:rgba(255,255,255,.02)}
.scan-name{font-weight:600;color:#f1f5f9;font-family:monospace;font-size:.8rem}
.scan-size{color:var(--muted);white-space:nowrap}
.scan-time{color:var(--muted);white-space:nowrap}
.scan-actions{display:flex;gap:6px;justify-content:flex-end}
.samba-box{background:var(--surface2);border:1px solid var(--border2);border-radius:10px;padding:16px;margin-bottom:20px}
.samba-box h3{font-size:.84rem;font-weight:700;color:#f1f5f9;margin-bottom:8px}
.samba-box p{font-size:.78rem;color:var(--muted);margin-bottom:10px}
.code-block{background:#0a0f1a;border:1px solid var(--border);border-radius:7px;padding:10px 14px;font-family:monospace;font-size:.78rem;color:#7dd3fc;white-space:pre;overflow-x:auto}

/* Jobs view */
.jobs-list{display:flex;flex-direction:column;gap:8px}
.job-item{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:.82rem;font-family:monospace;color:var(--subtle);display:flex;justify-content:space-between;align-items:center;gap:10px}
.job-text{overflow-wrap:anywhere}
.cups-printer-row{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:8px}
.cups-printer-name{font-weight:700;color:#f1f5f9;font-size:.86rem}
.cups-printer-state{font-size:.74rem;color:var(--muted);margin-top:2px}
.cups-actions{display:flex;gap:6px}
.default-star{color:var(--amber);margin-left:6px}
.section-title{font-size:.82rem;font-weight:700;color:#f1f5f9;text-transform:uppercase;letter-spacing:.04em;margin:22px 0 10px}
.section-title:first-child{margin-top:0}

/* Settings view */
.settings-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:20px;max-width:640px}
.settings-card h3{font-size:.92rem;font-weight:700;color:#f1f5f9;margin-bottom:4px}
.settings-card .desc{font-size:.78rem;color:var(--muted);margin-bottom:16px}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border)}
.toggle-row:last-child{border-bottom:none}
.toggle-label{font-size:.83rem;color:var(--text)}
.switch{position:relative;width:40px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:#374151;border-radius:999px;transition:.2s}
.slider:before{position:absolute;content:"";height:16px;width:16px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
input:checked + .slider{background:var(--blue)}
input:checked + .slider:before{transform:translateX(18px)}
.settings-status{margin-top:12px;padding:9px 12px;border-radius:8px;font-size:.8rem;display:none}
.help-box{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:12px 14px;font-size:.78rem;color:var(--subtle);margin-top:14px;line-height:1.5}
.help-box code{color:#7dd3fc}

/* Discover view */
.discover-row{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:8px;gap:12px}
.discover-info{min-width:0}
.discover-ip{font-weight:700;color:#f1f5f9;font-family:monospace;font-size:.84rem}
.discover-descr{font-size:.76rem;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.discover-controls{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px}
.discover-controls .field-sm{min-width:160px}

#modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;width:100%;max-width:460px;max-height:90vh;overflow-y:auto}
.modal h2{font-size:1.05rem;font-weight:700;margin-bottom:20px;color:#f1f5f9}
.field{margin-bottom:13px}
.field label{display:block;font-size:.75rem;color:var(--subtle);margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.field input,.field select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;color:var(--text);font-size:.88rem;outline:none}
.field input:focus,.field select:focus{border-color:var(--blue)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.spin{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
select option{background:var(--surface)}
@media(max-width:760px){.main{margin-left:0}.sidebar{transform:translateX(-224px)}.printer-grid{grid-template-columns:1fr}.info-grid{grid-template-columns:1fr}.field-row{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="layout">
<nav class="sidebar">
  <div class="sidebar-logo">
    <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>
    PrintDash
  </div>
  <div class="sidebar-nav">
    <div class="nav-section">Monitor</div>
    <div class="nav-item active" onclick="showView('overview')" id="nav-overview">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Overview
    </div>
    <div class="nav-item" onclick="showView('alerts')" id="nav-alerts">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Alerts
      <span id="alert-badge" class="nbadge" style="display:none"></span>
    </div>
    <div class="nav-item" onclick="showView('supplies')" id="nav-supplies">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>Supplies
    </div>
    <div class="nav-section">Actions</div>
    <div class="nav-item" onclick="showView('print')" id="nav-print">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>Print
    </div>
    <div class="nav-item" onclick="showView('scans')" id="nav-scans">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>Scans
    </div>
    <div class="nav-item" onclick="showView('jobs')" id="nav-jobs">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>Print Jobs
    </div>
    <div class="nav-section">Tools</div>
    <div class="nav-item" onclick="showView('discover')" id="nav-discover">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Discover Printers
    </div>
    <div class="nav-item" onclick="showView('settings')" id="nav-settings">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Settings
    </div>
    <div class="nav-section">Manage</div>
    <div class="nav-item" onclick="showView('users')" id="nav-users">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Users
    </div>
    <div class="nav-item" onclick="openModal()">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>Add Printer
    </div>
  </div>
  <div class="sidebar-footer" id="sidebar-updated">Loading…</div>
  <div class="sidebar-footer" style="display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--border)">
    <span id="whoami" style="color:var(--subtle)"></span>
    <a href="#" onclick="doLogout();return false" style="color:var(--blue)">Logout</a>
  </div>
</nav>

<div class="main">
  <header>
    <div>
      <div class="header-title" id="view-title">Overview</div>
      <div class="header-sub" id="view-sub">All printers</div>
    </div>
    <div class="hactions">
      <button class="btn-outline btn-sm" onclick="doRefresh()" id="refresh-btn"><span id="refresh-icon">↻</span> Refresh</button>
      <button class="btn-primary btn-sm" onclick="openModal()">+ Add Printer</button>
    </div>
  </header>
  <div class="content" id="content"><div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span> Loading…</div></div>
</div>
</div>

<!-- Modal -->
<div id="modal-overlay">
  <div class="modal">
    <h2 id="modal-title">Add Printer</h2>
    <input type="hidden" id="edit-id"/>
    <div class="field-row">
      <div class="field"><label>Name *</label><input id="f-name" placeholder="Canon-Floor2"/></div>
      <div class="field"><label>IP Address *</label><input id="f-ip" placeholder="192.168.18.x"/></div>
    </div>
    <div class="field-row">
      <div class="field"><label>Brand</label>
        <select id="f-brand">
          <option value="canon">Canon</option><option value="hp">HP</option>
          <option value="brother">Brother</option><option value="epson">Epson</option>
          <option value="ricoh">Ricoh</option><option value="xerox">Xerox</option>
          <option value="generic">Other</option>
        </select>
      </div>
      <div class="field"><label>SNMP Community</label><input id="f-community" value="public"/></div>
    </div>
    <div class="field"><label>Location / Department</label><input id="f-location" placeholder="Floor 2, HR Dept…"/></div>
    <div class="modal-footer">
      <button class="btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn-primary" onclick="savePrinter()">Save</button>
    </div>
  </div>
</div>

<script>
let state = {data:[], updatedAt:null};
let currentView = 'overview';
let cupsPrinters = [];
let settingsCache = null;

async function load(refresh=false) {
  try {
    const r = await fetch(refresh?'/api/printers/refresh':'/api/printers');
    state = await r.json();
    render();
  } catch { document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load data</div>'; }
}

async function doRefresh() {
  const btn=document.getElementById('refresh-btn'), icon=document.getElementById('refresh-icon');
  btn.disabled=true; icon.innerHTML='<span class="spin"></span>';
  await load(true);
  btn.disabled=false; icon.textContent='↻';
}

setInterval(()=>load(false), 3*60*1000);

async function loadCupsPrinters() {
  try { const r=await fetch('/api/cups/printers'); const d=await r.json(); cupsPrinters=d.printers||[]; }
  catch { cupsPrinters=[]; }
}

const ADMIN_ONLY_VIEWS = ['overview','alerts','supplies','jobs','discover','settings','users'];
function applyRoleUI() {
  const isAdmin = window.USER_ROLE === 'admin';
  document.getElementById('whoami').textContent = (window.USERNAME||'') + ' ('+(window.USER_ROLE||'')+')';
  ADMIN_ONLY_VIEWS.forEach(v=>{
    const el=document.getElementById('nav-'+v);
    if (el) el.style.display = isAdmin ? '' : 'none';
  });
  document.querySelectorAll('.nav-section').forEach(s=>{
    if (!isAdmin && (s.textContent==='Monitor'||s.textContent==='Tools'||s.textContent==='Manage')) s.style.display='none';
  });
  if (!isAdmin) {
    document.querySelector('.hactions .btn-primary').style.display='none';
    if (ADMIN_ONLY_VIEWS.includes(currentView)) currentView='print';
  }
}
async function doLogout(){ await fetch('/api/logout',{method:'POST'}); location.href='/login'; }

function showView(v) {
  if (window.USER_ROLE!=='admin' && ADMIN_ONLY_VIEWS.includes(v)) return;
  currentView=v;
  ['overview','alerts','supplies','print','scans','jobs','discover','settings','users'].forEach(id=>{
    const el=document.getElementById('nav-'+id);
    if (el) el.classList.toggle('active',id===v);
  });
  render();
}

function render() {
  updateSidebar();
  if (currentView==='overview') renderOverview();
  else if (currentView==='alerts') renderAlertsView();
  else if (currentView==='supplies') renderSuppliesView();
  else if (currentView==='print') renderPrintView();
  else if (currentView==='scans') renderScansView();
  else if (currentView==='jobs') renderJobsView();
  else if (currentView==='discover') renderDiscoverView();
  else if (currentView==='settings') renderSettingsView();
  else if (currentView==='users') renderUsersView();
}

function updateSidebar() {
  const printers=state.data||[];
  const ac=printers.reduce((a,p)=>a+(p.alerts?p.alerts.filter(x=>x.severity==='Critical'||x.severity==='Warning').length:0),0);
  const badge=document.getElementById('alert-badge');
  badge.style.display=ac>0?'':'none'; badge.textContent=ac;
  const upEl=document.getElementById('sidebar-updated');
  if (upEl&&state.updatedAt) upEl.textContent='Updated '+new Date(state.updatedAt).toLocaleTimeString();
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview() {
  document.getElementById('view-title').textContent='Overview';
  document.getElementById('view-sub').textContent='All printers — status, toner, trays';
  const printers=state.data||[];
  const total=printers.length, online=printers.filter(p=>p.online).length;
  const printing=printers.filter(p=>p.status==='Printing').length;
  const lowToner=printers.filter(p=>p.toners&&p.toners.some(t=>t.pct<20&&!t.unknown)).length;
  const alerts=printers.reduce((a,p)=>a+(p.alerts?p.alerts.length:0),0);
  const stats=\`<div class="stats-grid">
    <div class="stat-card"><div class="stat-label">Printers</div><div class="stat-value blue">\${total}</div></div>
    <div class="stat-card"><div class="stat-label">Online</div><div class="stat-value green">\${online}</div><div class="stat-sub">\${total-online} offline</div></div>
    <div class="stat-card"><div class="stat-label">Printing</div><div class="stat-value amber">\${printing}</div></div>
    <div class="stat-card"><div class="stat-label">Low Toner</div><div class="stat-value \${lowToner>0?'red':''}">\${lowToner}</div></div>
    <div class="stat-card"><div class="stat-label">Alerts</div><div class="stat-value \${alerts>0?'red':''}">\${alerts}</div></div>
  </div>\`;
  const cards=printers.length?printers.map(printerCard).join(''):'<div class="empty">No printers. Click <strong>Add Printer</strong> to start, or try <strong>Discover Printers</strong> in the sidebar.</div>';
  document.getElementById('content').innerHTML=stats+'<div class="printer-grid">'+cards+'</div>';
}

function printerCard(p) {
  const sc=!p.online?'offline':p.status==='Printing'?'printing':'idle';
  const alertBadge=(p.alerts&&p.alerts.length)?'<span class="badge warn">⚠ '+p.alerts.length+'</span>':'';
  return \`<div class="pcard \${p.online?'':'offline'}" id="pcard-\${p.id}">
    <div class="pcard-header">
      <div style="min-width:0">
        <div class="pcard-name">🖨 \${esc(p.name)}</div>
        <div class="pcard-model">\${esc(p.model||p.ip)} · \${esc(p.location||'—')}</div>
      </div>
      <div class="pcard-badges">\${alertBadge}<span class="badge \${sc}"><span class="dot \${p.online?'on':'off'}"></span>\${p.status||'Offline'}</span></div>
    </div>
    <div class="pcard-tabs">
      <div class="tab active" onclick="switchTab(\${p.id},'toner',this)">Toner</div>
      <div class="tab" onclick="switchTab(\${p.id},'trays',this)">Trays</div>
      <div class="tab" onclick="switchTab(\${p.id},'info',this)">Info</div>
      <div class="tab" onclick="switchTab(\${p.id},'alerts',this)">Alerts\${p.alerts&&p.alerts.length?' ('+p.alerts.length+')':''}</div>
      <div class="tab" onclick="switchTab(\${p.id},'pages',this)">Pages</div>
      <div class="tab" onclick="switchTab(\${p.id},'printcard',this)">🖨 Print</div>
    </div>
    <div class="pcard-body">
      <div class="tab-panel active" id="tp-\${p.id}-toner">\${tonerPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-trays">\${traysPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-info">\${infoPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-alerts">\${alertsPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-pages">\${pagesPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-printcard">\${printCardPanel(p)}</div>
    </div>
    <div class="pcard-footer">
      <span class="footer-ip">\${p.ip} · \${(p.brand||'').toUpperCase()}</span>
      <div class="footer-actions">
        <button class="btn-ghost btn-sm" onclick="editPrinter(\${p.id})">✏</button>
        <button class="btn-danger btn-sm" onclick="delPrinter(\${p.id})">✕</button>
      </div>
    </div>
  </div>\`;
}

function switchTab(id,tab,el) {
  const card=document.getElementById('pcard-'+id);
  card.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  card.querySelectorAll('.tab-panel').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  const panel=document.getElementById('tp-'+id+'-'+tab);
  if (panel) panel.classList.add('active');
}

function tonerPanel(p) {
  if (!p.online) return '<div class="no-data">Printer offline</div>';
  if (!p.toners||!p.toners.length) return '<div class="no-data">No toner data — enable SNMP on printer</div>';
  return '<div class="toner-list">'+p.toners.map(t=>{
    const warn=t.pct<20&&!t.unknown;
    return \`<div class="toner-row">
      <div class="toner-meta"><span class="toner-name">\${esc(t.name)}</span><span class="toner-pct \${warn?'warn':''}">\${t.unknown?'OK':t.pct+'%'}</span></div>
      <div class="track"><div class="fill \${warn?'low':''}" style="width:\${t.unknown?100:t.pct}%;background:\${t.color}"></div></div>
    </div>\`}).join('')+'</div>';
}

function traysPanel(p) {
  if (!p.online) return '<div class="no-data">Printer offline</div>';
  if (!p.trays||!p.trays.length) return '<div class="no-data">No tray data available</div>';
  return '<div class="tray-list">'+p.trays.map(t=>\`<div class="tray-row">
    <div class="tray-meta"><span class="tray-name">\${esc(t.name)}</span><span class="tray-stat">\${t.pct}% · \${t.status}</span></div>
    <div class="track"><div class="fill tray" style="width:\${t.pct}%"></div></div>
  </div>\`).join('')+'</div>';
}

function infoPanel(p) {
  const items=[['IP',p.ip],['Model',p.model],['Serial',p.serial||'—'],['MAC',p.mac||'—'],
    ['Uptime',p.uptime||'—'],['Memory',p.memKB?Math.round(p.memKB/1024)+'MB':'—'],
    ['Location',p.location||'—'],['Brand',(p.brand||'—').toUpperCase()],
    ['Community',p.community||'public'],['Checked',p.lastChecked?new Date(p.lastChecked).toLocaleTimeString():'—']];
  const grid=items.map(([l,v])=>\`<div class="info-item"><div class="info-label">\${l}</div><div class="info-value">\${esc(String(v||'—'))}</div></div>\`).join('');
  const con=p.console_msg?'<div style="margin-top:10px"><div class="info-label" style="font-size:.68rem;color:var(--muted);text-transform:uppercase;margin-bottom:5px">Console</div><div class="console-msg">'+esc(p.console_msg)+'</div></div>':'';
  return '<div class="info-grid">'+grid+'</div>'+con;
}

function alertsPanel(p) {
  if (!p.online) return '<div class="no-data">Printer offline</div>';
  if (!p.alerts||!p.alerts.length) return '<div class="no-data"><span class="ok-icon">✅</span>No active alerts</div>';
  return '<div class="alert-list">'+p.alerts.map(a=>\`<div class="alert-item \${a.severity}">
    <span>\${a.severity==='Critical'?'🔴':a.severity==='Warning'?'🟡':'ℹ️'}</span>
    <div><strong>\${a.severity}</strong> · \${esc(a.desc)}</div>
  </div>\`).join('')+'</div>';
}

function pagesPanel(p) {
  const hist=p.pageHistory||[];
  let chart='';
  if (hist.length>1) {
    const vals=hist.map(h=>h.pages), maxV=Math.max(...vals), minV=Math.min(...vals), range=maxV-minV||1;
    chart='<div class="mini-chart">'+vals.map(v=>{
      const h=Math.max(4,Math.round(((v-minV)/range)*46));
      return '<div class="mini-bar" style="height:'+h+'px" title="'+v+'"></div>';
    }).join('')+'</div>';
  }
  return '<div class="pages-big"><div class="pages-num">'+(p.pages!=null?p.pages.toLocaleString():'—')+'</div><div class="pages-label">Total pages printed</div></div>'+chart;
}

function printCardPanel(p) {
  const pid=p.id;
  return \`<div class="print-panel" id="pp-\${pid}">
    <div class="drop-zone" id="dz-\${pid}" onclick="document.getElementById('pf-\${pid}').click()" ondragover="dzDrag(event,'\${pid}')" ondragleave="dzLeave('\${pid}')" ondrop="dzDrop(event,'\${pid}')">
      <input type="file" id="pf-\${pid}" accept=".pdf,.doc,.docx,.txt,.jpg,.png" onchange="dzFile('\${pid}',this.files[0])"/>
      <div class="icon">📄</div>
      <div id="dz-label-\${pid}">Drop file here or click to browse</div>
      <div style="font-size:.72rem;margin-top:4px;color:var(--muted)">PDF, DOC, TXT, JPG, PNG</div>
    </div>
    <div class="print-opts">
      <div class="field-sm"><label>CUPS Printer</label>
        <select id="po-printer-\${pid}"><option value="">Loading…</option></select>
      </div>
      <div class="field-sm"><label>Copies</label>
        <input type="number" id="po-copies-\${pid}" value="1" min="1" max="99"/>
      </div>
      <div class="field-sm"><label>Duplex</label>
        <select id="po-duplex-\${pid}">
          <option value="none">Single sided</option>
          <option value="long">Double (long edge)</option>
          <option value="short">Double (short edge)</option>
        </select>
      </div>
    </div>
    <button class="btn-primary" onclick="submitPrint('\${pid}')">🖨 Send to Printer</button>
    <div id="pstatus-\${pid}" style="display:none" class="print-status ok"></div>
  </div>\`;
}

// ── Print view ─────────────────────────────────────────────────────────────────
function renderPrintView() {
  document.getElementById('view-title').textContent='Print';
  document.getElementById('view-sub').textContent='Send a file to any CUPS printer';
  const html=\`<div style="max-width:520px">
    <div class="print-panel" id="pp-main">
      <div class="drop-zone" id="dz-main" onclick="document.getElementById('pf-main').click()" ondragover="dzDrag(event,'main')" ondragleave="dzLeave('main')" ondrop="dzDrop(event,'main')">
        <input type="file" id="pf-main" accept=".pdf,.doc,.docx,.txt,.jpg,.png" onchange="dzFile('main',this.files[0])"/>
        <div class="icon">📄</div>
        <div id="dz-label-main">Drop file here or click to browse</div>
        <div style="font-size:.72rem;margin-top:4px;color:var(--muted)">PDF, DOC, TXT, JPG, PNG — max 50MB</div>
      </div>
      <div class="print-opts">
        <div class="field-sm"><label>Printer</label>
          <select id="po-printer-main"><option value="">Loading…</option></select>
        </div>
        <div class="field-sm"><label>Copies</label>
          <input type="number" id="po-copies-main" value="1" min="1" max="99"/>
        </div>
        <div class="field-sm"><label>Duplex</label>
          <select id="po-duplex-main">
            <option value="none">Single sided</option>
            <option value="long">Double (long edge)</option>
            <option value="short">Double (short edge)</option>
          </select>
        </div>
      </div>
      <button class="btn-primary" style="width:100%;padding:12px" onclick="submitPrint('main')">🖨 Send to Printer</button>
      <div id="pstatus-main" style="display:none" class="print-status ok"></div>
    </div>
  </div>\`;
  document.getElementById('content').innerHTML=html;
  populatePrinterSelects();
}

// ── Scans view ────────────────────────────────────────────────────────────────
async function renderScansView() {
  document.getElementById('view-title').textContent='Scans';
  document.getElementById('view-sub').textContent='Files scanned to the server share folder';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span> Loading scans…</div>';
  try {
    const r=await fetch('/api/scans'); const d=await r.json();
    const smbaConf=await fetch('/api/samba-config').then(x=>x.json());
    const scans=d.scans||[];
    let rows=scans.length?scans.map(s=>\`<tr>
      <td><span class="scan-name">\${esc(s.name)}</span></td>
      <td class="scan-size">\${fmtSize(s.size)}</td>
      <td class="scan-time">\${new Date(s.mtime).toLocaleString()}</td>
      <td><div class="scan-actions">
        <a href="/api/scans/download/\${encodeURIComponent(s.name)}" class="btn-green btn-sm" style="text-decoration:none;display:inline-flex;align-items:center;gap:4px">⬇ Download</a>
        <button class="btn-danger btn-sm" onclick="deleteScan('\${esc(s.name)}')">✕</button>
      </div></td>
    </tr>\`).join(''):'<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px">No scan files yet</td></tr>';
    document.getElementById('content').innerHTML=\`
      <div class="samba-box">
        <h3>📁 Scan-to-Folder Setup</h3>
        <p>Configure your Canon/HP printer's web UI to scan directly to this server. Add this to <code>/etc/samba/smb.conf</code> and run <code>systemctl restart smbd</code>:</p>
        <div class="code-block">\${esc(smbaConf.config)}</div>
        <div style="margin-top:10px;font-size:.78rem;color:var(--muted)">Then on the printer web UI: <strong>Scan → Scan to Folder → \\\\\\\\SERVER_IP\\\\scans</strong></div>
        <div style="margin-top:6px;font-size:.78rem;color:var(--muted)">Scan folder on server: <code>\${esc(d.dir)}</code></div>
      </div>
      <div class="scan-header">
        <div style="font-weight:700;color:#f1f5f9">\${scans.length} file\${scans.length!==1?'s':''} in scan folder</div>
        <div style="display:flex;gap:8px">
          <select id="scan-device" class="btn-outline btn-sm" style="cursor:pointer"></select>
          <select id="scan-source" class="btn-outline btn-sm" style="cursor:pointer">
            <option value="Flatbed">Flatbed (Glass)</option>
            <option value="ADF">ADF Simplex</option>
            <option value="ADF Duplex">ADF Duplex</option>
          </select>
          <button class="btn-primary btn-sm" id="scan-now-btn" onclick="triggerScanNow()">🖨 Scan Now</button>
          <button class="btn-outline btn-sm" onclick="renderScansView()">↻ Refresh</button>
        </div>
      </div>
      <div id="scan-now-status"></div>
      <table class="scan-table">
        <thead><tr><th>File Name</th><th>Size</th><th>Date</th><th style="text-align:right">Actions</th></tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
    const devs = await fetch('/api/scans/devices').then(x=>x.json()).then(x=>x.devices||[]).catch(()=>[]);
    const devSel = document.getElementById('scan-device');
    devSel.innerHTML = devs.length
      ? devs.map(d=>'<option value="'+esc(d.id)+'">'+esc(d.label)+'</option>').join('')
      : '<option value="">No scanners found</option>';
  } catch { document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load scans</div>'; }
}

async function deleteScan(name) {
  if (!confirm('Delete '+name+'?')) return;
  await fetch('/api/scans/'+encodeURIComponent(name),{method:'DELETE'});
  renderScansView();
}

async function triggerScanNow() {
  const device = document.getElementById('scan-device').value;
  const source = document.getElementById('scan-source').value;
  const btn = document.getElementById('scan-now-btn');
  const status = document.getElementById('scan-now-status');
  if (!device) { status.innerHTML = '<div style="margin-top:8px;color:var(--red);font-size:.8rem">⚠ No scanner selected</div>'; return; }
  btn.disabled = true; btn.textContent = '⏳ Scanning…';
  status.innerHTML = '<div style="margin-top:8px;color:var(--muted);font-size:.8rem">Scanning in progress, this can take up to a minute…</div>';
  try {
    const r = await fetch('/api/scans/trigger', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({device, source})});
    const d = await r.json();
    if (d.ok) { status.innerHTML = '<div style="margin-top:8px;color:var(--green);font-size:.8rem">✅ Saved '+esc(d.name)+'</div>'; renderScansView(); }
    else status.innerHTML = '<div style="margin-top:8px;color:var(--red);font-size:.8rem">❌ '+esc(d.error)+'</div>';
  } catch(e) {
    status.innerHTML = '<div style="margin-top:8px;color:var(--red);font-size:.8rem">❌ '+esc(e.message)+'</div>';
  } finally {
    btn.disabled = false; btn.textContent = '🖨 Scan Now';
  }
}

// ── Jobs view ─────────────────────────────────────────────────────────────────
async function renderJobsView() {
  document.getElementById('view-title').textContent='Print Jobs';
  document.getElementById('view-sub').textContent='CUPS printers, active queue, and history';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  try {
    const [detail,jobsD,histD]=await Promise.all([
      fetch('/api/cups/printers/detail').then(x=>x.json()),
      fetch('/api/cups/jobs').then(x=>x.json()),
      fetch('/api/cups/jobs/history').then(x=>x.json()),
    ]);
    const printers=detail.printers||[], def=detail.defaultPrinter;
    const printerRows=printers.length?printers.map(pr=>\`<div class="cups-printer-row">
      <div>
        <div class="cups-printer-name">\${esc(pr.name)}\${pr.name===def?'<span class="default-star">★ default</span>':''}</div>
        <div class="cups-printer-state">\${esc(pr.state)}</div>
      </div>
      <div class="cups-actions">
        \${pr.state.toLowerCase().includes('disabled')
          ?'<button class="btn-green btn-sm" onclick="resumePrinter(\\''+esc(pr.name)+'\\')">▶ Resume</button>'
          :'<button class="btn-amber btn-sm" onclick="pausePrinter(\\''+esc(pr.name)+'\\')">⏸ Pause</button>'}
        \${pr.name!==def?'<button class="btn-outline btn-sm" onclick="setDefaultPrinter(\\''+esc(pr.name)+'\\')">Set Default</button>':''}
      </div>
    </div>\`).join(''):'<div class="no-data">No CUPS printers configured yet — add one from Discover Printers.</div>';

    const jobs=jobsD.jobs||[];
    const jobRows=jobs.length?jobs.map(j=>{
      const jobId=j.split(/\\s+/)[0];
      return \`<div class="job-item"><span class="job-text">\${esc(j)}</span><button class="btn-danger btn-sm" onclick="cancelJob('\${esc(jobId)}')">✕ Cancel</button></div>\`;
    }).join(''):'<div class="no-data" style="padding:24px 0;text-align:center"><span class="ok-icon">✅</span>Print queue is empty</div>';

    const hist=histD.jobs||[];
    const histRows=hist.length?hist.slice(0,15).map(j=>'<div class="job-item">'+esc(j)+'</div>').join(''):'<div class="no-data">No completed jobs yet</div>';

    document.getElementById('content').innerHTML=\`
      <div class="section-title">CUPS Printers</div>
      \${printerRows}
      <div class="section-title">Active Queue (\${jobs.length})</div>
      <div class="jobs-list">\${jobRows}</div>
      <div class="section-title">Recent History</div>
      <div class="jobs-list">\${histRows}</div>
    \`;
  } catch { document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load jobs</div>'; }
}

async function cancelJob(jobId) {
  await fetch('/api/cups/jobs/'+encodeURIComponent(jobId)+'/cancel',{method:'POST'});
  renderJobsView();
}
async function pausePrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/pause',{method:'POST'});
  renderJobsView();
}
async function resumePrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/resume',{method:'POST'});
  renderJobsView();
}
async function setDefaultPrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/default',{method:'POST'});
  renderJobsView();
}

// ── Discover view ─────────────────────────────────────────────────────────────
async function renderDiscoverView() {
  document.getElementById('view-title').textContent='Discover Printers';
  document.getElementById('view-sub').textContent='Find printers on your network automatically';
  let guess='192.168.1.0/24';
  try { const g=await fetch('/api/discover/subnet-guess').then(x=>x.json()); guess=g.cidr||guess; } catch {}
  document.getElementById('content').innerHTML=\`
    <div class="section-title">SNMP Scan (for monitoring — toner, trays, alerts)</div>
    <div class="discover-controls">
      <div class="field-sm"><label>Subnet (CIDR)</label><input id="disc-cidr" value="\${esc(guess)}"/></div>
      <div class="field-sm"><label>SNMP Community</label><input id="disc-community" value="public"/></div>
      <button class="btn-primary" onclick="runSnmpDiscover()">🔍 Scan Network</button>
    </div>
    <div id="snmp-results"><div class="no-data">Click "Scan Network" — this checks ~254 addresses, takes 10-30s.</div></div>

    <div class="section-title">CUPS Network Discovery (for printing/scanning)</div>
    <div class="discover-controls">
      <button class="btn-primary" onclick="runCupsDiscover()">🔍 Scan via CUPS (lpinfo)</button>
    </div>
    <div id="cups-results"><div class="no-data">Finds printers via IPP/DNS-SD/network broadcast that CUPS can register directly.</div></div>
  \`;
}

async function runSnmpDiscover() {
  const cidr=document.getElementById('disc-cidr').value.trim();
  const community=document.getElementById('disc-community').value.trim()||'public';
  document.getElementById('snmp-results').innerHTML='<div style="text-align:center;padding:30px;color:var(--muted)"><span class="spin"></span> Scanning \${esc(cidr)}…</div>'.replace('\${esc(cidr)}',esc(cidr));
  try {
    const r=await fetch('/api/discover/snmp?cidr='+encodeURIComponent(cidr)+'&community='+encodeURIComponent(community));
    const d=await r.json();
    const results=d.results||[];
    if (!results.length) { document.getElementById('snmp-results').innerHTML='<div class="no-data">No SNMP-responding devices found on '+esc(cidr)+'</div>'; return; }
    document.getElementById('snmp-results').innerHTML=results.map(rr=>\`<div class="discover-row">
      <div class="discover-info"><div class="discover-ip">\${esc(rr.ip)}</div><div class="discover-descr">\${esc(rr.descr)}</div></div>
      \${rr.alreadyAdded?'<span class="badge online">✓ Added</span>':'<button class="btn-green btn-sm" onclick="addSnmpResult(\\''+esc(rr.ip)+'\\',\\''+esc(rr.descr).replace(/'/g,"&#39;")+'\\')">+ Add Printer</button>'}
    </div>\`).join('');
  } catch { document.getElementById('snmp-results').innerHTML='<div class="empty">⚠ Scan failed</div>'; }
}

async function addSnmpResult(ip, descr) {
  const name=prompt('Printer name:', descr.substring(0,30)||ip)||ip;
  const community=document.getElementById('disc-community').value.trim()||'public';
  await fetch('/api/printers',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name, ip, brand:'generic', community})});
  alert('Added! Check the Overview tab.');
  runSnmpDiscover();
}

async function runCupsDiscover() {
  document.getElementById('cups-results').innerHTML='<div style="text-align:center;padding:30px;color:var(--muted)"><span class="spin"></span> Asking CUPS…</div>';
  try {
    const r=await fetch('/api/cups/discover'); const d=await r.json();
    const found=d.found||[];
    if (!found.length) { document.getElementById('cups-results').innerHTML='<div class="no-data">CUPS found nothing. Printer may need to be on and IPP-capable.</div>'; return; }
    document.getElementById('cups-results').innerHTML=found.map((f,i)=>\`<div class="discover-row">
      <div class="discover-info"><div class="discover-ip">\${esc(f.kind)}</div><div class="discover-descr">\${esc(f.uri)}</div></div>
      <button class="btn-green btn-sm" onclick="addCupsResult('\${esc(f.uri).replace(/'/g,"&#39;")}')">+ Add to CUPS</button>
    </div>\`).join('');
  } catch { document.getElementById('cups-results').innerHTML='<div class="empty">⚠ Scan failed</div>'; }
}

async function addCupsResult(uri) {
  const name=prompt('CUPS printer name (letters/numbers/dashes only):','Printer'+Math.floor(Math.random()*1000));
  if (!name) return;
  try {
    const r=await fetch('/api/cups/discover/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,uri})});
    const d=await r.json();
    if (d.ok) { alert('Added to CUPS as "'+d.name+'". It will now appear in Print and Print Jobs.'); populatePrinterSelects(); }
    else alert('Failed: '+(d.error||'unknown error'));
  } catch(e) { alert('Failed: '+e.message); }
}

// ── Settings view ─────────────────────────────────────────────────────────────
async function renderSettingsView() {
  document.getElementById('view-title').textContent='Settings';
  document.getElementById('view-sub').textContent='Telegram alerts & network defaults';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  try { settingsCache = await fetch('/api/settings').then(x=>x.json()); } catch { settingsCache=null; }
  const t = (settingsCache&&settingsCache.telegram) || {};
  const n = (settingsCache&&settingsCache.network) || {};
  document.getElementById('content').innerHTML=\`
    <div class="settings-card">
      <h3>📲 Telegram Alerts</h3>
      <div class="desc">Get notified instantly when toner is low, a printer goes offline, or a jam is reported.</div>
      <div class="toggle-row">
        <span class="toggle-label">Enable Telegram alerts</span>
        <label class="switch"><input type="checkbox" id="s-enabled" \${t.enabled?'checked':''}><span class="slider"></span></label>
      </div>
      <div class="field" style="margin-top:14px"><label>Bot Token</label><input id="s-token" placeholder="123456:ABC-DEF..." value="\${esc(t.botToken||'')}"/></div>
      <div class="field"><label>Chat ID</label><input id="s-chatid" placeholder="-1001234567890 or your user id" value="\${esc(t.chatId||'')}"/></div>
      <div class="field-row">
        <div class="field"><label>Toner alert threshold (%)</label><input type="number" id="s-threshold" value="\${t.tonerThreshold!=null?t.tonerThreshold:20}" min="1" max="90"/></div>
        <div class="field"><label>Re-alert cooldown (minutes)</label><input type="number" id="s-cooldown" value="\${t.cooldownMinutes!=null?t.cooldownMinutes:240}" min="5"/></div>
      </div>
      <div class="toggle-row"><span class="toggle-label">Alert on low toner</span><label class="switch"><input type="checkbox" id="s-toner" \${t.alertToner!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert when printer goes offline</span><label class="switch"><input type="checkbox" id="s-offline" \${t.alertOffline!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on jams / cover open / service</span><label class="switch"><input type="checkbox" id="s-jams" \${t.alertJams!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert when a paper tray is empty</span><label class="switch"><input type="checkbox" id="s-tray" \${t.alertTrayEmpty!==false?'checked':''}><span class="slider"></span></label></div>
      <div style="display:flex;gap:10px;margin-top:16px">
        <button class="btn-primary" onclick="saveTelegramSettings()">Save Settings</button>
        <button class="btn-outline" onclick="testTelegram()">Send Test Message</button>
      </div>
      <div id="settings-status" class="settings-status"></div>
      <div class="help-box">
        <strong>How to set this up:</strong><br/>
        1. In Telegram, message <code>@BotFather</code> → <code>/newbot</code> → copy the token it gives you.<br/>
        2. Message your new bot once (anything), then open <code>https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code> in a browser — your Chat ID is the <code>chat.id</code> field. For a group, add the bot to the group first.<br/>
        3. Paste both above, hit Save, then Send Test Message.
      </div>
    </div>

    <div class="settings-card">
      <h3>🌐 Network Discovery Default</h3>
      <div class="desc">Used as the default subnet when scanning for printers.</div>
      <div class="field"><label>Default Subnet (CIDR)</label><input id="s-subnet" placeholder="192.168.18.0/24" value="\${esc(n.scanSubnet||'')}"/></div>
      <button class="btn-primary" onclick="saveNetworkSettings()">Save</button>
    </div>
  \`;
}

async function renderUsersView() {
  document.getElementById('view-title').textContent='Users';
  document.getElementById('view-sub').textContent='Manage admin & user accounts';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  let users=[];
  try { users = (await fetch('/api/users').then(x=>x.json())).users||[]; } catch {}
  const rows = users.map(u=>\`
    <tr>
      <td style="font-weight:600;color:#f1f5f9">\${esc(u.username)}</td>
      <td><span class="chip" style="background:\${u.role==='admin'?'rgba(59,130,246,.15);color:var(--blue)':'rgba(148,163,184,.15);color:var(--subtle)'}">\${esc(u.role)}</span></td>
      <td style="display:flex;gap:6px">
        <button class="btn-outline btn-sm" onclick="resetUserPassword('\${esc(u.username)}')">Reset Password</button>
        <button class="btn-outline btn-sm" onclick="toggleUserRole('\${esc(u.username)}','\${u.role==='admin'?'user':'admin'}')">Make \${u.role==='admin'?'User':'Admin'}</button>
        <button class="btn-danger btn-sm" onclick="deleteUser('\${esc(u.username)}')">Delete</button>
      </td>
    </tr>\`).join('');
  document.getElementById('content').innerHTML=\`
    <div class="settings-card">
      <h3>➕ Add User</h3>
      <div class="field-row">
        <div class="field"><label>Username</label><input id="nu-username" placeholder="jdoe"/></div>
        <div class="field"><label>Password</label><input id="nu-password" type="password" placeholder="••••••••"/></div>
      </div>
      <div class="field" style="max-width:200px"><label>Role</label>
        <select id="nu-role"><option value="user">User (Print + Scans only)</option><option value="admin">Admin (Full access)</option></select>
      </div>
      <button class="btn-primary" onclick="addUser()">Create User</button>
      <div id="users-status" class="settings-status"></div>
    </div>
    <div class="settings-card">
      <h3>👥 Existing Users</h3>
      <table class="data-table">
        <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody>\${rows || '<tr><td colspan="3" style="color:var(--muted)">No users</td></tr>'}</tbody>
      </table>
    </div>
  \`;
}

function showUsersStatus(msg,type) {
  const el=document.getElementById('users-status');
  if (!el) return;
  el.style.display=''; el.className='settings-status '+(type==='ok'?'print-status ok':'print-status err'); el.textContent=msg;
}

async function addUser() {
  const username=document.getElementById('nu-username').value.trim();
  const password=document.getElementById('nu-password').value;
  const role=document.getElementById('nu-role').value;
  if (!username||!password) { showUsersStatus('Username and password required','err'); return; }
  const r = await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,role})});
  const d = await r.json();
  if (d.ok) { showUsersStatus('✅ User created','ok'); renderUsersView(); }
  else showUsersStatus('❌ '+(d.error||'Failed'),'err');
}

async function toggleUserRole(username, newRole) {
  await fetch('/api/users/'+encodeURIComponent(username), {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:newRole})});
  renderUsersView();
}

async function resetUserPassword(username) {
  const pw = prompt('New password for '+username+':');
  if (!pw) return;
  const r = await fetch('/api/users/'+encodeURIComponent(username), {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  showUsersStatus(d.ok?'✅ Password updated':'❌ '+(d.error||'Failed'), d.ok?'ok':'err');
}

async function deleteUser(username) {
  if (!confirm('Delete user '+username+'?')) return;
  const r = await fetch('/api/users/'+encodeURIComponent(username), {method:'DELETE'});
  const d = await r.json();
  if (d.ok) renderUsersView(); else showUsersStatus('❌ '+(d.error||'Failed'),'err');
}

function showSettingsStatus(msg,type) {
  const el=document.getElementById('settings-status');
  el.style.display=''; el.className='settings-status '+(type==='ok'?'print-status ok':'print-status err'); el.textContent=msg;
}

async function saveTelegramSettings() {
  const body={telegram:{
    enabled:document.getElementById('s-enabled').checked,
    botToken:document.getElementById('s-token').value.trim(),
    chatId:document.getElementById('s-chatid').value.trim(),
    tonerThreshold:Number(document.getElementById('s-threshold').value)||20,
    cooldownMinutes:Number(document.getElementById('s-cooldown').value)||240,
    alertToner:document.getElementById('s-toner').checked,
    alertOffline:document.getElementById('s-offline').checked,
    alertJams:document.getElementById('s-jams').checked,
    alertTrayEmpty:document.getElementById('s-tray').checked,
  }};
  try {
    const r=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if (r.ok) showSettingsStatus('✅ Settings saved','ok'); else showSettingsStatus('❌ Failed to save','err');
  } catch(e) { showSettingsStatus('❌ '+e.message,'err'); }
}

async function saveNetworkSettings() {
  const body={network:{scanSubnet:document.getElementById('s-subnet').value.trim()}};
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  showSettingsStatus('✅ Network settings saved','ok');
}

async function testTelegram() {
  const botToken=document.getElementById('s-token').value.trim();
  const chatId=document.getElementById('s-chatid').value.trim();
  if (!botToken||!chatId) return showSettingsStatus('⚠ Enter bot token and chat ID first','err');
  showSettingsStatus('Sending…','ok');
  try {
    const r=await fetch('/api/settings/test-telegram',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botToken,chatId})});
    const d=await r.json();
    if (d.ok) showSettingsStatus('✅ Test message sent — check Telegram','ok');
    else showSettingsStatus('❌ '+(d.error||'Failed'),'err');
  } catch(e) { showSettingsStatus('❌ '+e.message,'err'); }
}

// ── Alerts view ───────────────────────────────────────────────────────────────
function renderAlertsView() {
  document.getElementById('view-title').textContent='Alerts';
  document.getElementById('view-sub').textContent='Active alerts across all printers';
  const printers=state.data||[];
  let html='';
  printers.forEach(p=>{
    (p.alerts||[]).forEach(a=>{
      html+=\`<div class="alert-item \${a.severity}" style="margin-bottom:8px">
        <span>\${a.severity==='Critical'?'🔴':a.severity==='Warning'?'🟡':'ℹ️'}</span>
        <div><strong>\${esc(p.name)}</strong> · \${esc(a.desc)}</div>
      </div>\`;
    });
  });
  if (!html) html='<div class="no-data" style="padding:60px 20px;text-align:center"><span class="ok-icon">✅</span>No active alerts</div>';
  document.getElementById('content').innerHTML=html;
}

// ── Supplies view ─────────────────────────────────────────────────────────────
function renderSuppliesView() {
  document.getElementById('view-title').textContent='Supplies';
  document.getElementById('view-sub').textContent='Toner & ink — all printers';
  const printers=state.data||[];
  const html='<div class="printer-grid">'+printers.map(p=>\`<div class="pcard \${p.online?'':'offline'}">
    <div class="pcard-header">
      <div><div class="pcard-name">🖨 \${esc(p.name)}</div><div class="pcard-model">\${esc(p.model||p.ip)}</div></div>
      <span class="badge \${p.online?'idle':'offline'}"><span class="dot \${p.online?'on':'off'}"></span>\${p.status||'Offline'}</span>
    </div>
    <div class="pcard-body">\${tonerPanel(p)}</div>
  </div>\`).join('')+'</div>';
  document.getElementById('content').innerHTML=html;
}

// ── Print helpers ─────────────────────────────────────────────────────────────
let printFiles = {};

function dzDrag(e,id){ e.preventDefault(); document.getElementById('dz-'+id).classList.add('drag'); }
function dzLeave(id){ document.getElementById('dz-'+id).classList.remove('drag'); }
function dzDrop(e,id){ e.preventDefault(); dzLeave(id); if(e.dataTransfer.files[0]) dzFile(id,e.dataTransfer.files[0]); }
function dzFile(id,f){ if(!f)return; printFiles[id]=f; document.getElementById('dz-label-'+id).textContent='📎 '+f.name+' ('+fmtSize(f.size)+')'; }

async function populatePrinterSelects() {
  await loadCupsPrinters();
  document.querySelectorAll('[id^="po-printer-"]').forEach(sel=>{
    sel.innerHTML=cupsPrinters.length
      ?cupsPrinters.map(p=>'<option value="'+esc(p)+'">'+esc(p)+'</option>').join('')
      +'<option value="">-- manual entry --</option>'
      :'<option value="">No CUPS printers found</option>';
  });
}

async function submitPrint(id) {
  const file=printFiles[id];
  const printer=document.getElementById('po-printer-'+id)?.value;
  const copies=document.getElementById('po-copies-'+id)?.value||'1';
  const duplex=document.getElementById('po-duplex-'+id)?.value||'none';
  if (!file) { showPrintStatus(id,'⚠ Please select a file first','err'); return; }
  if (!printer) { showPrintStatus(id,'⚠ Please select a printer','err'); return; }
  showPrintStatus(id,'<span class="spin"></span> Sending to printer…','ok');
  const fd=new FormData();
  fd.append('file',file); fd.append('printer',printer); fd.append('copies',copies); fd.append('duplex',duplex);
  try {
    const r=await fetch('/api/print',{method:'POST',body:fd});
    const d=await r.json();
    if (d.ok) { showPrintStatus(id,'✅ Sent! Job ID: '+(d.jobId||'—'),'ok'); printFiles[id]=null; document.getElementById('dz-label-'+id).textContent='Drop file here or click to browse'; }
    else showPrintStatus(id,'❌ Error: '+esc(d.error),'err');
  } catch(e) { showPrintStatus(id,'❌ '+e.message,'err'); }
}

function showPrintStatus(id,msg,type) {
  const el=document.getElementById('pstatus-'+id);
  if (!el) return;
  el.style.display=''; el.className='print-status '+type; el.innerHTML=msg;
}

// ── CRUD ──────────────────────────────────────────────────────────────────────
function openModal(id) {
  document.getElementById('modal-title').textContent=id?'Edit Printer':'Add Printer';
  document.getElementById('edit-id').value=id||'';
  if (id) {
    const p=state.data.find(x=>x.id===id);
    if (p) { document.getElementById('f-name').value=p.name||''; document.getElementById('f-ip').value=p.ip||'';
      document.getElementById('f-brand').value=p.brand||'generic'; document.getElementById('f-community').value=p.community||'public';
      document.getElementById('f-location').value=p.location||''; }
  } else {
    ['f-name','f-ip','f-location'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('f-brand').value='canon'; document.getElementById('f-community').value='public';
  }
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal(){ document.getElementById('modal-overlay').classList.remove('open'); }
document.getElementById('modal-overlay').addEventListener('click',e=>{if(e.target===e.currentTarget)closeModal();});

async function savePrinter() {
  const name=document.getElementById('f-name').value.trim(), ip=document.getElementById('f-ip').value.trim();
  if (!name||!ip) return alert('Name and IP are required');
  const body={name,ip,brand:document.getElementById('f-brand').value,community:document.getElementById('f-community').value.trim()||'public',location:document.getElementById('f-location').value.trim()};
  const editId=document.getElementById('edit-id').value;
  await fetch(editId?'/api/printers/'+editId:'/api/printers',{method:editId?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  closeModal(); await load(false);
}

async function delPrinter(id){ if(!confirm('Remove printer?'))return; await fetch('/api/printers/'+id,{method:'DELETE'}); load(); }
function editPrinter(id){ openModal(id); }

function fmtSize(b){ if(b<1024)return b+'B'; if(b<1024*1024)return Math.round(b/1024)+'KB'; return (b/1024/1024).toFixed(1)+'MB'; }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

applyRoleUI();
if (window.USER_ROLE!=='admin') { currentView='print'; }
load();
loadCupsPrinters();
</script>
</body>
</html>`;

app.listen(PORT, '0.0.0.0', () => {
  console.log('=======================================');
  console.log('  PrintDash v4 -> http://0.0.0.0:'+PORT);
  console.log('  Scan folder  -> '+SCAN_DIR);
  console.log('  Upload dir   -> '+UPLOAD_DIR);
  console.log('  Telegram     -> '+(SETTINGS.telegram.enabled?'enabled':'disabled (configure in Settings tab)'));
  console.log('=======================================');
});
