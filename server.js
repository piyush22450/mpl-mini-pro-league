require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = path.join(__dirname, "mpl.sqlite");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','host')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS teams (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 team_name TEXT NOT NULL,
 captain_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 email TEXT,
 town TEXT NOT NULL,
 notes TEXT,
 payment_status TEXT NOT NULL DEFAULT 'Pending' CHECK(payment_status IN ('Pending','Paid')),
 registration_status TEXT NOT NULL DEFAULT 'Pending' CHECK(registration_status IN ('Pending','Approved','Rejected')),
 age_review_status TEXT NOT NULL DEFAULT 'Pending' CHECK(age_review_status IN ('Pending','Verified','Needs review')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS players (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
 player_name TEXT NOT NULL,
 date_of_birth TEXT NOT NULL,
 player_type TEXT NOT NULL CHECK(player_type IN ('Player','Substitute'))
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 team_id INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function escapeHtml(v) {
 return String(v ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function layout(title, body, user=null) {
 const nav = user
  ? `<a href="/dashboard">Dashboard</a><span class="nav-user">${escapeHtml(user.username)} · ${escapeHtml(user.role)}</span><form method="post" action="/logout" class="inline"><input type="hidden" name="_csrf" value="${csrfToken()}"><button class="navbtn">Log out</button></form>`
  : `<a href="/#register">Register a team</a><a href="/login">Host login</a>`;
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="MPL Mini Pro League Under-19 cricket tournament"><title>${escapeHtml(title)} · MPL Mini Pro League</title><link rel="stylesheet" href="/styles.css"></head><body><header><a class="brand" href="/"><span class="logo">🏏</span><span>MPL <b>MINI PRO LEAGUE</b></span></a><nav>${nav}</nav></header>${body}<footer>© MPL Mini Pro League · Keep under-19 player information private</footer></body></html>`;
}
function csrfToken() {
 if (!currentReq || !currentReq.session) return "";
 if (!currentReq.session.csrf) currentReq.session.csrf = crypto.randomBytes(24).toString("hex");
 return currentReq.session.csrf;
}
let currentReq = null;
app.use((req,res,next)=>{ currentReq=req; next(); });
app.use(helmet({contentSecurityPolicy:{directives:{
 defaultSrc:["'self'"], styleSrc:["'self'","'unsafe-inline'"], scriptSrc:["'self'"],
 imgSrc:["'self'","data:"], formAction:["'self'"], frameAncestors:["'none'"]
}}}));
app.use(express.urlencoded({extended:false, limit:"40kb"}));
app.use(express.static(path.join(__dirname,"public"), {maxAge:"1h"}));
app.use(session({
 store: new SQLiteStore({db:"sessions.sqlite", dir:__dirname}),
 name:"mpl.sid",
 secret:process.env.SESSION_SECRET || "development-only-change-me",
 resave:false, saveUninitialized:false,
 cookie:{httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:8*60*60*1000}
}));
app.use((req,res,next)=>{ currentReq=req; res.setHeader("Cache-Control","no-store"); next(); });
const loginLimiter = rateLimit({windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false});
function requireLogin(req,res,next){ if(!req.session.user) return res.redirect("/login"); next(); }
function requireAdmin(req,res,next){ if(!req.session.user) return res.redirect("/login"); if(req.session.user.role!=="admin") return res.status(403).send(pageMessage("Access denied","Only the special administrator can manage host accounts.")); next(); }
function csrf(req,res,next){
 const supplied=req.body && req.body._csrf;
 if(!req.session.csrf || !supplied || supplied!==req.session.csrf) return res.status(403).send(pageMessage("Request expired","Refresh the page and try again."));
 next();
}
function pageMessage(title,message,link="/"){ return layout(title,`<main class="narrow"><section class="panel"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a class="button" href="${escapeHtml(link)}">Continue</a></section></main>`); }
function audit(actor,action,teamId=null){ db.prepare("INSERT INTO audit_log(actor,action,team_id) VALUES(?,?,?)").run(actor,action,teamId); }

function initializeAdmin(){
 const username=(process.env.ADMIN_USERNAME||"sujal").trim().toLowerCase();
 const password=process.env.ADMIN_PASSWORD;
 if(!password || password==="replace-with-a-strong-unique-password"){
   console.warn("ADMIN SETUP REQUIRED: set ADMIN_PASSWORD in .env before first launch. No default password is created.");
   return;
 }
 const existing=db.prepare("SELECT id FROM users WHERE username=?").get(username);
 if(!existing){
   const hash=bcrypt.hashSync(password,12);
   db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,hash,"admin");
   console.log(`Created initial administrator account: ${username}`);
 }
}
initializeAdmin();

app.get("/",(req,res)=>{
 const fee=escapeHtml(process.env.REGISTRATION_FEE||"2200");
 const name=escapeHtml(process.env.TOURNAMENT_NAME||"MPL Mini Pro League");
 res.send(layout("Home",`<section class="hero"><div class="hero-copy"><span class="eyebrow">UNDER-19 CRICKET TOURNAMENT</span><h1>Play bold.<br><em>Play together.</em></h1><p>Register your squad for ${name}. Team details are visible only to authorized hosts.</p><a class="button" href="#register">Register your team →</a></div><aside class="hero-card"><span class="pill">TEAM REGISTRATION</span><h2>₹${fee}</h2><p>Registration fee per team</p><hr><b>11 players + 4 substitutes</b><p>U-19 eligibility and host approval required.</p></aside></section>
<main><div class="stats"><article class="stat"><b>U-19</b><span>Age category</span></article><article class="stat"><b>15 players</b><span>11 players + 4 substitutes</span></article><article class="stat"><b>₹${fee}</b><span>Fee per team</span></article></div>
<section class="section"><h2>Register your team</h2><p class="muted">Complete the team and player roster. The organizer will review eligibility and registration.</p>
<div class="notice"><b>Age and privacy:</b> Do not enter Aadhaar numbers or upload Aadhaar documents. This site records dates of birth for eligibility review; any Aadhaar-based check must be performed separately through an appropriate authorized service.</div>
<form class="panel form" method="post" action="/register" autocomplete="on">
<input type="hidden" name="_csrf" value="${csrfToken()}">
<div class="form-grid">
<label>Team name *<input name="team_name" maxlength="80" required></label>
<label>Captain full name *<input name="captain_name" maxlength="100" required></label>
<label>Captain mobile number *<input name="phone" inputmode="tel" maxlength="20" pattern="[0-9+ ()-]{8,20}" required></label>
<label>Email (optional)<input name="email" type="email" maxlength="150"></label>
<label>City / village *<input name="town" maxlength="100" required></label>
<label>Message to organizers (optional)<input name="notes" maxlength="500"></label></div>
<h3>Player roster</h3><div class="form-grid"><label>Total squad size (including substitutes) *<select name="player_count" id="player_count" required><option value="11" selected>11 players total (11 playing, 0 substitutes)</option><option value="12">12 players total (11 playing, 1 substitute)</option><option value="13">13 players total (11 playing, 2 substitutes)</option></select></label><p class="muted">The total squad must be 11–13 players, including substitutes. Date of birth is used for U-19 eligibility review.</p></div>
<div id="players"></div>
<script src="/roster.js" defer></script>
<label class="consent"><input type="checkbox" name="confirm" value="yes" required> I confirm these details are accurate and understand that eligibility and registration require host review.</label>
<button class="button" type="submit">Submit team registration</button>
<p class="muted small">Payment status starts as Pending. The UPI QR code will be added when provided. This site does not process online payments.</p>
</form></section></main>`));
});

app.post("/register",csrf,(req,res)=>{
 const teamName=(req.body.team_name||"").trim();
 const captain=(req.body.captain_name||"").trim();
 const phone=(req.body.phone||"").trim();
 const email=(req.body.email||"").trim();
 const town=(req.body.town||"").trim();
 const notes=(req.body.notes||"").trim();
 const playerCount=Number(req.body.player_count);
 const names=Array.isArray(req.body.player_name)?req.body.player_name:[req.body.player_name];
 const dobs=Array.isArray(req.body.dob)?req.body.dob:[req.body.dob];
 const rosterCount=playerCount;
 if(!teamName||!captain||!phone||!town||req.body.confirm!=="yes"||![11,12,13].includes(playerCount)||names.length!==rosterCount||dobs.length!==rosterCount) return res.status(400).send(pageMessage("Check your form","Choose a total squad size of 11, 12, or 13 players, including substitutes.","/#register"));
 for(let i=0;i<rosterCount;i++){
  if(!String(names[i]||"").trim()||!/^\d{4}-\d{2}-\d{2}$/.test(dobs[i]||"")||dobs[i]>new Date().toISOString().slice(0,10)) return res.status(400).send(pageMessage("Check your roster","Please enter a valid name and date of birth for every player in the selected squad.","/#register"));
 }
 const insertTeam=db.prepare("INSERT INTO teams(team_name,captain_name,phone,email,town,notes) VALUES(?,?,?,?,?,?)");
 const insertPlayer=db.prepare("INSERT INTO players(team_id,player_name,date_of_birth,player_type) VALUES(?,?,?,?)");
 const tx=db.transaction(()=>{
  const result=insertTeam.run(teamName,captain,phone,email,town,notes);
  for(let i=0;i<rosterCount;i++) insertPlayer.run(result.lastInsertRowid,String(names[i]).trim(),dobs[i],i<11?"Player":"Substitute");
  return result.lastInsertRowid;
 });
 const id=tx();
 res.send(layout("Registration received",`<main class="narrow"><section class="panel success"><span class="pill">SUBMITTED</span><h1>Registration received</h1><p>Your team registration reference is <b>MPL-${String(id).padStart(5,"0")}</b>.</p><p>Your registration is <b>Pending host review</b>, and payment is <b>Pending</b>. Save this reference for follow-up.</p><p>For privacy, team and player details are not shown publicly.</p><a class="button" href="/">Back to home</a></section></main>`));
});

app.get("/login",(req,res)=>{
 res.send(layout("Host Login",`<main class="narrow"><section class="panel"><h1>Host login</h1><p class="muted">Authorized hosts only. Your password is never shown or stored in plain text.</p><form method="post" action="/login" class="form"><input type="hidden" name="_csrf" value="${csrfToken()}"><label>Username<input name="username" autocomplete="username" required maxlength="80"></label><label>Password<input type="password" name="password" autocomplete="current-password" required maxlength="200"></label><button class="button" type="submit">Sign in</button></form></section></main>`));
});
app.post("/login",loginLimiter,csrf,(req,res)=>{
 const username=String(req.body.username||"").trim().toLowerCase();
 const password=String(req.body.password||"");
 const user=db.prepare("SELECT id,username,password_hash,role,active FROM users WHERE username=?").get(username);
 if(!user||!user.active||!bcrypt.compareSync(password,user.password_hash)){
  return res.status(401).send(layout("Login failed",`<main class="narrow"><section class="panel"><h1>Login failed</h1><p>Username or password was not accepted.</p><a class="button" href="/login">Try again</a></section></main>`));
 }
 req.session.regenerate(err=>{
  if(err) return res.status(500).send(pageMessage("Error","Could not start a secure session."));
  req.session.user={id:user.id,username:user.username,role:user.role};
  req.session.csrf=crypto.randomBytes(24).toString("hex");
  res.redirect("/dashboard");
 });
});
app.post("/logout",csrf,(req,res)=>req.session.destroy(()=>res.redirect("/")));

function isU19(dob){
 // Default eligibility is under 19 on the registration date; organizers must set the official cutoff rules before launch.
 const birth=new Date(dob+"T00:00:00Z"); const now=new Date();
 let age=now.getUTCFullYear()-birth.getUTCFullYear();
 const m=now.getUTCMonth()-birth.getUTCMonth();
 if(m<0||(m===0&&now.getUTCDate()<birth.getUTCDate())) age--;
 return age<19;
}
app.get("/dashboard",requireLogin,(req,res)=>{
 const user=req.session.user;
 const teams=db.prepare("SELECT * FROM teams ORDER BY id DESC").all();
 const total=teams.length, pending=teams.filter(t=>t.registration_status==="Pending").length, paid=teams.filter(t=>t.payment_status==="Paid").length;
 const rows=teams.map(t=>`<tr><td><b>MPL-${String(t.id).padStart(5,"0")}</b><br>${escapeHtml(t.team_name)}<small>${escapeHtml(t.captain_name)} · ${escapeHtml(t.phone)}</small></td><td><span class="status">${escapeHtml(t.registration_status)}</span></td><td>${escapeHtml(t.payment_status)}</td><td>${escapeHtml(t.age_review_status)}</td><td><a href="/team/${t.id}">View</a></td></tr>`).join("");
 const adminTools=user.role==="admin"?`<section class="panel"><h2>Manage host accounts</h2><p class="muted">Create host accounts. Share credentials securely and require hosts to change passwords before operational use.</p><form method="post" action="/hosts" class="form form-grid"><input type="hidden" name="_csrf" value="${csrfToken()}"><label>New host username<input name="username" minlength="3" maxlength="50" pattern="[a-zA-Z0-9._-]+" required></label><label>Temporary password<input type="password" name="password" minlength="12" required></label><button class="button" type="submit">Create host</button></form><h3>Existing accounts</h3><div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Active</th></tr></thead><tbody>${db.prepare("SELECT username,role,active FROM users ORDER BY id").all().map(u=>`<tr><td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.role)}</td><td>${u.active?"Yes":"No"}</td></tr>`).join("")}</tbody></table></div></section>`:"";
 res.send(layout("Dashboard",`<main><div class="dash-head"><div><span class="eyebrow dark">PRIVATE MANAGEMENT</span><h1>Host dashboard</h1><p class="muted">Visible only to signed-in authorized hosts.</p></div><a class="button secondary" href="/export.csv">Export CSV</a></div><div class="stats"><article class="stat"><b>${total}</b><span>Registered teams</span></article><article class="stat"><b>${pending}</b><span>Pending review</span></article><article class="stat"><b>${paid}</b><span>Payments marked paid</span></article></div><section class="panel section"><h2>Team registrations</h2><div class="table-wrap"><table><thead><tr><th>Team / captain</th><th>Registration</th><th>Payment</th><th>Age review</th><th>Details</th></tr></thead><tbody>${rows||'<tr><td colspan="5">No teams registered yet.</td></tr>'}</tbody></table></div></section>${adminTools}</main>`,user));
});
app.get("/team/:id",requireLogin,(req,res)=>{
 const team=db.prepare("SELECT * FROM teams WHERE id=?").get(Number(req.params.id));
 if(!team) return res.status(404).send(pageMessage("Not found","Team not found.","/dashboard"));
 const players=db.prepare("SELECT * FROM players WHERE team_id=? ORDER BY id").all(team.id);
 const user=req.session.user;
 const playerRows=players.map(p=>`<tr><td>${escapeHtml(p.player_type)}</td><td>${escapeHtml(p.player_name)}</td><td>${escapeHtml(p.date_of_birth)}</td><td>${isU19(p.date_of_birth)?"Under 19 by current-date check":"Needs age review"}</td></tr>`).join("");
 const adminActions=user.role==="admin"?`<form method="post" action="/team/${team.id}/update" class="form"><input type="hidden" name="_csrf" value="${csrfToken()}"><div class="form-grid"><label>Registration status<select name="registration_status">${["Pending","Approved","Rejected"].map(s=>`<option ${team.registration_status===s?"selected":""}>${s}</option>`).join("")}</select></label><label>Payment status<select name="payment_status">${["Pending","Paid"].map(s=>`<option ${team.payment_status===s?"selected":""}>${s}</option>`).join("")}</select></label><label>Age review status<select name="age_review_status">${["Pending","Verified","Needs review"].map(s=>`<option ${team.age_review_status===s?"selected":""}>${s}</option>`).join("")}</select></label></div><p class="muted small">Mark age as Verified only after completing an appropriate authorized check outside this site.</p><button class="button" type="submit">Save changes</button></form>`:`<p class="muted">Hosts can view this team. Only the special administrator can change status fields.</p>`;
 res.send(layout("Team details",`<main><a href="/dashboard">← Back to dashboard</a><section class="panel section"><h1>${escapeHtml(team.team_name)}</h1><p><b>Reference:</b> MPL-${String(team.id).padStart(5,"0")}</p><div class="form-grid"><p><b>Captain</b><br>${escapeHtml(team.captain_name)}</p><p><b>Phone</b><br>${escapeHtml(team.phone)}</p><p><b>Email</b><br>${escapeHtml(team.email||"Not provided")}</p><p><b>City / village</b><br>${escapeHtml(team.town)}</p><p><b>Registration</b><br>${escapeHtml(team.registration_status)}</p><p><b>Payment</b><br>${escapeHtml(team.payment_status)}</p><p><b>Age review</b><br>${escapeHtml(team.age_review_status)}</p><p><b>Submitted</b><br>${escapeHtml(team.created_at)}</p></div><h2>Player roster</h2><div class="table-wrap"><table><thead><tr><th>Type</th><th>Name</th><th>Date of birth</th><th>Eligibility helper</th></tr></thead><tbody>${playerRows}</tbody></table></div><p class="muted small">This age helper uses today's date, not an official tournament cutoff date. It is not an official age verification. Set and apply the tournament's published cutoff rule before approving players.</p><hr><h2>Update status</h2>${adminActions}</section></main>`,user));
});
app.post("/team/:id/update",requireAdmin,csrf,(req,res)=>{
 const id=Number(req.params.id);
 const allowedReg=["Pending","Approved","Rejected"], allowedPay=["Pending","Paid"], allowedAge=["Pending","Verified","Needs review"];
 if(!allowedReg.includes(req.body.registration_status)||!allowedPay.includes(req.body.payment_status)||!allowedAge.includes(req.body.age_review_status)) return res.status(400).send(pageMessage("Invalid status","Choose a valid status.","/dashboard"));
 db.prepare("UPDATE teams SET registration_status=?,payment_status=?,age_review_status=? WHERE id=?").run(req.body.registration_status,req.body.payment_status,req.body.age_review_status,id);
 audit(req.session.user.username,"Updated team status",id);
 res.redirect(`/team/${id}`);
});
app.post("/hosts",requireAdmin,csrf,(req,res)=>{
 const username=String(req.body.username||"").trim().toLowerCase();
 const password=String(req.body.password||"");
 if(!/^[a-z0-9._-]{3,50}$/.test(username)||password.length<12) return res.status(400).send(pageMessage("Invalid host details","Use a username of 3–50 letters/numbers/._- and a password of at least 12 characters.","/dashboard"));
 try{
  db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,bcrypt.hashSync(password,12),"host");
  audit(req.session.user.username,`Created host ${username}`);
  res.redirect("/dashboard");
 }catch(e){res.status(409).send(pageMessage("Username unavailable","That username already exists.","/dashboard"));}
});
app.get("/export.csv",requireLogin,(req,res)=>{
 const teams=db.prepare("SELECT * FROM teams ORDER BY id").all();
 const q=s=>`"${String(s??"").replace(/"/g,'""')}"`;
 const lines=[["Reference","Team","Captain","Phone","Email","City/Village","Registration Status","Payment Status","Age Review","Created At"].map(q).join(",")];
 for(const t of teams) lines.push([`MPL-${String(t.id).padStart(5,"0")}`,t.team_name,t.captain_name,t.phone,t.email,t.town,t.registration_status,t.payment_status,t.age_review_status,t.created_at].map(q).join(","));
 res.setHeader("Content-Type","text/csv; charset=utf-8");
 res.setHeader("Content-Disposition",'attachment; filename="mpl-team-registrations.csv"');
 res.send("\uFEFF"+lines.join("\r\n"));
});
app.use((err,req,res,next)=>{console.error(err);res.status(500).send(pageMessage("Something went wrong","The request could not be completed. Please try again."));});
app.listen(PORT,()=>console.log(`MPL Mini Pro League running at http://localhost:${PORT}`));
