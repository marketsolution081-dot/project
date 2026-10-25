from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import sqlite3, hashlib, hmac, base64, json, time, os, csv, io, calendar, urllib.request, urllib.error
from datetime import date, datetime
from typing import Optional

app = FastAPI(title="HCM Lite")
DB = "hcm_lite.db"
SECRET = os.getenv("HCM_SECRET", "change-this-secret-before-deployment")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, role TEXT NOT NULL, active INTEGER DEFAULT 1,
      employee_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS departments(
      id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS employees(
      id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL, department TEXT NOT NULL, designation TEXT DEFAULT '',
      basic_salary REAL NOT NULL, phone TEXT DEFAULT '', address TEXT DEFAULT '',
      join_date TEXT NOT NULL, active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS attendance(
      id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, day TEXT NOT NULL,
      check_in TEXT NOT NULL, check_out TEXT, status TEXT NOT NULL,
      UNIQUE(employee_id, day)
    );
    CREATE TABLE IF NOT EXISTS leaves(
      id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, leave_type TEXT NOT NULL,
      start_date TEXT NOT NULL, end_date TEXT NOT NULL, reason TEXT NOT NULL,
      status TEXT DEFAULT 'Pending', comment TEXT DEFAULT '', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS payroll(
      id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, month TEXT NOT NULL,
      gross REAL NOT NULL, deductions REAL NOT NULL, net REAL NOT NULL,
      status TEXT DEFAULT 'Draft', UNIQUE(employee_id, month)
    );
    CREATE TABLE IF NOT EXISTS announcements(
      id INTEGER PRIMARY KEY, title TEXT NOT NULL, message TEXT NOT NULL,
      created_at TEXT NOT NULL, author TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY, actor TEXT, action TEXT, details TEXT, created_at TEXT
    );
    """)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS holidays(day TEXT PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, email TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL, is_read INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS corrections(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, day TEXT NOT NULL, requested_check_in TEXT, requested_check_out TEXT, reason TEXT NOT NULL, status TEXT DEFAULT 'Pending', comment TEXT DEFAULT '', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ai_logs(id INTEGER PRIMARY KEY, email TEXT, question TEXT, created_at TEXT NOT NULL);
    """)
    con.commit()
    con.close()

init_db()
# Safe schema migration for databases created by earlier versions.
with db() as _migration_con:
    _cols={r["name"] for r in _migration_con.execute("PRAGMA table_info(payroll)").fetchall()}
    if "tax" not in _cols:
        _migration_con.execute("ALTER TABLE payroll ADD COLUMN tax REAL NOT NULL DEFAULT 0")

def password_hash(password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180000)
    return base64.b64encode(salt + key).decode()

def password_ok(password, saved):
    try:
        raw = base64.b64decode(saved)
        salt, expected = raw[:16], raw[16:]
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def make_token(user):
    payload = {"id": user["id"], "role": user["role"], "exp": int(time.time()) + 86400}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig

def current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")
    token = authorization[7:]
    try:
        body, sig = token.split(".")
        good = hmac.compare_digest(sig, hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest())
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if not good or payload["exp"] < time.time():
            raise ValueError()
        con = db()
        user = con.execute("SELECT * FROM users WHERE id=? AND active=1", (payload["id"],)).fetchone()
        con.close()
        if not user:
            raise ValueError()
        return user
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

def role(user, *allowed):
    if user["role"] not in allowed:
        raise HTTPException(403, "You do not have permission")

def audit(actor, action, details=""):
    con = db()
    con.execute("INSERT INTO audit(actor,action,details,created_at) VALUES(?,?,?,?)",
                (actor, action, details, datetime.now().isoformat(timespec="seconds")))
    con.commit()
    con.close()

class SetupIn(BaseModel):
    company_name: str
    name: str
    email: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class DeptIn(BaseModel):
    name: str

class EmployeeIn(BaseModel):
    code: str
    name: str
    email: str
    password: str
    department: str
    designation: str = ""
    basic_salary: float
    phone: str = ""
    address: str = ""
    join_date: str = str(date.today())

class LeaveIn(BaseModel):
    leave_type: str
    start_date: str
    end_date: str
    reason: str

class DecisionIn(BaseModel):
    status: str
    comment: str = ""

class AnnouncementIn(BaseModel):
    title: str
    message: str

class ChatIn(BaseModel):
    question: str

class MonthIn(BaseModel):
    month: str

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse("""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>HCM Lite</title><style>
    body{font-family:Arial;background:#f2f5fb;margin:0;color:#172033}header{background:#162b55;color:white;padding:22px}
    main{max-width:900px;margin:22px auto;padding:16px}.card{background:white;padding:18px;border-radius:14px;margin:12px 0;box-shadow:0 4px 16px #0001}
    input,select,button,textarea{padding:11px;margin:5px 0;border:1px solid #ccd4e2;border-radius:8px;width:100%;box-sizing:border-box}
    button{background:#315bd6;color:white;border:0;font-weight:bold;cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
    pre{white-space:pre-wrap;word-break:break-word}.muted{color:#667085}</style></head><body>
    <header><h1>HCM Lite</h1><div>Human Capital Management · Admin / HR / Employee</div></header><main>
    <div class="card"><h2>First-time setup</h2><p class="muted">Sirf fresh database par ek dafa Admin account banayein.</p>
    <input id="company" placeholder="Company name"><input id="adminname" placeholder="Admin name">
    <input id="setupemail" placeholder="Admin email"><input id="setuppass" type="password" placeholder="Password (minimum 8 characters)">
    <button onclick="setup()">Create Admin</button></div>
    <div class="card"><h2>Login</h2><input id="email" placeholder="Email"><input id="pass" type="password" placeholder="Password">
    <button onclick="login()">Login</button><p id="msg"></p></div>
    <div id="panel" class="card" style="display:none"><h2>Dashboard</h2><button onclick="dashboard()">Refresh dashboard</button>
    <div id="stats" class="grid"></div><h3>Add department (Admin)</h3><input id="dept" placeholder="Department name"><button onclick="addDept()">Add department</button>
    <h3>Register employee (HR)</h3><div class="grid"><input id="ecode" placeholder="Employee code"><input id="ename" placeholder="Full name">
    <input id="eemail" placeholder="Employee email"><input id="epass" placeholder="Temporary password">
    <input id="edep" placeholder="Department"><input id="edesig" placeholder="Designation">
    <input id="salary" type="number" placeholder="Basic salary"><input id="phone" placeholder="Phone"></div><button onclick="addEmployee()">Register employee</button>
    <h3>Attendance</h3><button onclick="checkin()">Check in</button><button onclick="checkout()">Check out</button>
    <h3>Apply for leave</h3><div class="grid"><select id="ltype"><option>casual</option><option>sick</option><option>annual</option><option>unpaid</option></select>
    <input id="lstart" type="date"><input id="lend" type="date"></div><textarea id="reason" placeholder="Leave reason"></textarea><button onclick="applyLeave()">Apply leave</button>
    <h3>Pending leaves (HR/Admin)</h3><button onclick="leaves()">Load leave requests</button><pre id="leaveout"></pre>
    <h3>Run payroll draft (HR/Admin)</h3><input id="month" placeholder="Month, e.g. 2026-10"><button onclick="payroll()">Run payroll</button>
    <h3>AI helper (basic policy/data Q&A)</h3><input id="question" placeholder="Ask a question"><button onclick="askAI()">Ask</button><pre id="aiout"></pre>
    <h3>Announcements</h3><input id="atitle" placeholder="Title"><textarea id="amessage" placeholder="Message"></textarea><button onclick="postAnnouncement()">Post (Admin/HR)</button><button onclick="getAnnouncements()">View announcements</button><pre id="annout"></pre>
    <button onclick="logout()">Logout</button></div></main>
    <script>
    let token=localStorage.getItem('hcm_token')||'';
    async function req(path,method='GET',data=null){let r=await fetch(path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:data?JSON.stringify(data):null});let d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
    function show(s){document.getElementById('msg').innerText=s}
    async function setup(){try{let d=await req('/setup','POST',{company_name:company.value,name:adminname.value,email:setupemail.value,password:setuppass.value});show(d.message)}catch(e){show(e.message)}}
    async function login(){try{let d=await req('/login','POST',{email:email.value,password:pass.value});token=d.access_token;localStorage.setItem('hcm_token',token);panel.style.display='block';show('Login successful');dashboard()}catch(e){show(e.message)}}
    function logout(){token='';localStorage.removeItem('hcm_token');panel.style.display='none';show('Logged out')}
    async function dashboard(){try{let d=await req('/dashboard');stats.innerHTML=Object.entries(d).map(([k,v])=>`<div class="card"><b>${k.replaceAll('_',' ')}</b><h2>${v}</h2></div>`).join('')}catch(e){show(e.message)}}
    async function addDept(){try{show(JSON.stringify(await req('/departments','POST',{name:dept.value})))}catch(e){show(e.message)}}
    async function addEmployee(){try{let d={code:ecode.value,name:ename.value,email:eemail.value,password:epass.value,department:edep.value,designation:edesig.value,basic_salary:Number(salary.value),phone:phone.value};show(JSON.stringify(await req('/employees','POST',d)))}catch(e){show(e.message)}}
    async function checkin(){try{show(JSON.stringify(await req('/attendance/checkin','POST',{})));dashboard()}catch(e){show(e.message)}}
    async function checkout(){try{show(JSON.stringify(await req('/attendance/checkout','POST',{})));dashboard()}catch(e){show(e.message)}}
    async function applyLeave(){try{show(JSON.stringify(await req('/leaves','POST',{leave_type:ltype.value,start_date:lstart.value,end_date:lend.value,reason:reason.value})))}catch(e){show(e.message)}}
    async function leaves(){try{leaveout.innerText=JSON.stringify(await req('/leaves'),null,2)}catch(e){leaveout.innerText=e.message}}
    async function payroll(){try{show(JSON.stringify(await req('/payroll/run','POST',{month:month.value})))}catch(e){show(e.message)}}
    async function askAI(){try{aiout.innerText=(await req('/ai/chat','POST',{question:question.value})).answer}catch(e){aiout.innerText=e.message}}
    async function postAnnouncement(){try{show(JSON.stringify(await req('/announcements','POST',{title:atitle.value,message:amessage.value})))}catch(e){show(e.message)}}
    async function getAnnouncements(){try{annout.innerText=JSON.stringify(await req('/announcements'),null,2)}catch(e){annout.innerText=e.message}}
    if(token){panel.style.display='block';dashboard()}
    </script></body></html>""")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/setup/status")
def setup_status():
    con=db()
    count=con.execute("SELECT COUNT(*) n FROM users WHERE role='Admin'").fetchone()["n"]
    con.close()
    return {"setup_complete": count > 0}

@app.post("/setup")
def setup(data: SetupIn):
    if len(data.password) < 8:
        raise HTTPException(422, "Password must be at least 8 characters")
    con=db()
    if con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
        con.close()
        raise HTTPException(409, "Setup already complete")
    con.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'Admin')",
                (data.name,data.email.strip().lower(),password_hash(data.password)))
    con.execute("INSERT INTO departments(name) VALUES(?)", ("General",))
    con.commit(); con.close()
    with open("company.json","w",encoding="utf-8") as f:
        json.dump({"company_name":data.company_name},f)
    audit(data.email,"first_run_setup",data.company_name)
    return {"message":"Admin created. Ab login karein."}

@app.post("/login")
def login(data: LoginIn):
    con=db(); user=con.execute("SELECT * FROM users WHERE email=? AND active=1",(data.email.strip().lower(),)).fetchone(); con.close()
    if not user or not password_ok(data.password,user["password"]):
        raise HTTPException(401,"Email ya password ghalat hai")
    return {"access_token":make_token(user),"token_type":"bearer","role":user["role"],"name":user["name"]}

@app.get("/me")
def me(authorization: Optional[str]=Header(None)):
    u=current_user(authorization)
    return {"name":u["name"],"email":u["email"],"role":u["role"]}

@app.post("/departments")
def add_department(data: DeptIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    con=db()
    try:
        con.execute("INSERT INTO departments(name) VALUES(?)",(data.name.strip(),)); con.commit()
    except sqlite3.IntegrityError:
        con.close(); raise HTTPException(409,"Department already exists")
    con.close(); audit(u["email"],"department_created",data.name)
    return {"message":"Department added"}

@app.get("/departments")
def departments(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    con=db(); rows=con.execute("SELECT * FROM departments ORDER BY name").fetchall(); con.close()
    return [dict(r) for r in rows]

@app.post("/employees")
def add_employee(data: EmployeeIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    if data.basic_salary <= 0: raise HTTPException(422,"Salary must be greater than zero")
    if len(data.password)<8: raise HTTPException(422,"Temporary password must be at least 8 characters")
    con=db()
    try:
        cur=con.execute("""INSERT INTO employees(code,name,email,department,designation,basic_salary,phone,address,join_date)
          VALUES(?,?,?,?,?,?,?,?,?)""",(data.code,data.name,data.email,data.department,data.designation,data.basic_salary,data.phone,data.address,data.join_date))
        eid=cur.lastrowid
        con.execute("INSERT INTO users(name,email,password,role,employee_id) VALUES(?,?,?,'Employee',?)",
                    (data.name,data.email,password_hash(data.password),eid))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); raise HTTPException(409,"Employee code/email pehle se use ho raha hai")
    con.close(); audit(u["email"],"employee_created",data.email)
    return {"message":"Employee aur uska login create ho gaya. Employee should change the temporary password.","employee_id":eid}

@app.get("/employees")
def employees(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"] in ("Admin","HR"):
        rows=con.execute("SELECT id,code,name,email,department,designation,phone,join_date,active FROM employees ORDER BY name").fetchall()
    else:
        rows=con.execute("SELECT id,code,name,email,department,designation,phone,join_date,active FROM employees WHERE id=?",(u["employee_id"],)).fetchall()
    con.close(); return [dict(r) for r in rows]

def employee_for(user):
    if user["role"]=="Employee":
        if not user["employee_id"]: raise HTTPException(400,"Employee profile missing")
        return user["employee_id"]
    raise HTTPException(403,"Employee role required")

def attendance_cutoff():
    con=db()
    values={r["key"]:r["value"] for r in con.execute("SELECT key,value FROM settings").fetchall()}
    con.close()
    try:
        start=datetime.strptime(values.get("office_start","09:00"),"%H:%M")
        grace=int(values.get("grace_minutes","15"))
        from datetime import timedelta
        return (start+timedelta(minutes=grace)).strftime("%H:%M")
    except Exception:
        return "09:15"

@app.post("/attendance/checkin")
def checkin(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); eid=employee_for(u); now=datetime.now()
    status="Late" if now.strftime("%H:%M") > attendance_cutoff() else "Present"
    con=db()
    try:
        con.execute("INSERT INTO attendance(employee_id,day,check_in,status) VALUES(?,?,?,?)",
                    (eid,str(date.today()),now.isoformat(timespec="seconds"),status)); con.commit()
    except sqlite3.IntegrityError:
        con.close(); raise HTTPException(409,"Aaj check-in pehle ho chuka hai")
    con.close(); audit(u["email"],"checkin",str(date.today()))
    return {"message":"Check-in successful","status":status,"time":now.strftime("%H:%M:%S")}

@app.post("/attendance/checkout")
def checkout(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); eid=employee_for(u); con=db()
    row=con.execute("SELECT * FROM attendance WHERE employee_id=? AND day=?",(eid,str(date.today()))).fetchone()
    if not row: con.close(); raise HTTPException(404,"Pehle check-in karein")
    if row["check_out"]: con.close(); raise HTTPException(409,"Check-out pehle ho chuka hai")
    now=datetime.now().isoformat(timespec="seconds")
    con.execute("UPDATE attendance SET check_out=? WHERE id=?",(now,row["id"])); con.commit(); con.close()
    audit(u["email"],"checkout",str(date.today()))
    return {"message":"Check-out successful","time":now}

@app.get("/attendance")
def attendance(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"] in ("Admin","HR"):
        rows=con.execute("""SELECT a.*,e.name,e.department FROM attendance a JOIN employees e ON e.id=a.employee_id ORDER BY day DESC""").fetchall()
    else:
        rows=con.execute("SELECT * FROM attendance WHERE employee_id=? ORDER BY day DESC",(u["employee_id"],)).fetchall()
    con.close(); return [dict(r) for r in rows]

@app.post("/leaves")
def apply_leave(data: LeaveIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); eid=employee_for(u)
    try:
        start=date.fromisoformat(data.start_date); end=date.fromisoformat(data.end_date)
    except ValueError: raise HTTPException(422,"Dates YYYY-MM-DD honi chahiye")
    if end<start: raise HTTPException(422,"End date start date se pehle nahi ho sakti")
    if data.leave_type not in ("casual","sick","annual","unpaid"): raise HTTPException(422,"Invalid leave type")
    con=db()
    overlap=con.execute("""SELECT id FROM leaves WHERE employee_id=? AND status='Approved'
      AND NOT(end_date<? OR start_date>?)""",(eid,data.start_date,data.end_date)).fetchone()
    if overlap: con.close(); raise HTTPException(422,"Approved leave ke saath dates overlap karti hain")
    con.execute("INSERT INTO leaves(employee_id,leave_type,start_date,end_date,reason,created_at) VALUES(?,?,?,?,?,?)",
                (eid,data.leave_type,data.start_date,data.end_date,data.reason,datetime.now().isoformat(timespec="seconds")))
    con.commit(); con.close(); audit(u["email"],"leave_applied",data.leave_type)
    return {"message":"Leave request submitted","status":"Pending"}

@app.get("/leaves")
def list_leaves(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"] in ("Admin","HR"):
        rows=con.execute("SELECT l.*,e.name,e.department FROM leaves l JOIN employees e ON e.id=l.employee_id ORDER BY l.id DESC").fetchall()
    else:
        rows=con.execute("SELECT * FROM leaves WHERE employee_id=? ORDER BY id DESC",(u["employee_id"],)).fetchall()
    con.close(); return [dict(r) for r in rows]

@app.patch("/leaves/{leave_id}")
def decide_leave(leave_id: int, data: DecisionIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    if data.status not in ("Approved","Rejected"): raise HTTPException(422,"Status Approved ya Rejected hona chahiye")
    con=db(); row=con.execute("SELECT * FROM leaves WHERE id=?",(leave_id,)).fetchone()
    if not row: con.close(); raise HTTPException(404,"Leave request nahi mili")
    if row["status"]!="Pending": con.close(); raise HTTPException(409,"Request pehle decide ho chuki hai")
    con.execute("UPDATE leaves SET status=?,comment=? WHERE id=?",(data.status,data.comment,leave_id))
    employee=con.execute("SELECT email FROM employees WHERE id=?",(row["employee_id"],)).fetchone()
    if employee:
        con.execute("INSERT INTO notifications(email,title,message,created_at) VALUES(?,?,?,?)",(employee["email"],"Leave request "+data.status.lower(),"Your leave request was "+data.status.lower()+(". "+data.comment if data.comment else "."),datetime.now().isoformat(timespec="seconds")))
    con.commit(); con.close()
    audit(u["email"],"leave_"+data.status.lower(),str(leave_id))
    return {"message":"Leave "+data.status.lower()+" ho gayi"}

def calculate_monthly_tax(monthly_gross, con):
    """Annualized progressive withholding using admin-configured annual brackets.
    Configure settings key tax_slabs_json as [{"up_to": 600000, "rate": 0.0}, ...].
    The last bracket can omit up_to to represent the top bracket. Default is no withholding.
    This is a configurable estimate, not jurisdiction-specific tax advice.
    """
    row=con.execute("SELECT value FROM settings WHERE key='tax_slabs_json'").fetchone()
    if not row or not row["value"]: return 0.0
    try: slabs=sorted(json.loads(row["value"]),key=lambda x: float(x.get("up_to",float("inf"))))
    except Exception: return 0.0
    annual=max(0.0,float(monthly_gross)*12); previous=0.0; annual_tax=0.0
    for slab in slabs:
        rate=float(slab.get("rate",0))/100.0
        upper=float(slab.get("up_to",float("inf")))
        taxable=max(0.0,min(annual,upper)-previous)
        annual_tax += taxable*rate
        previous=upper
        if annual<=upper: break
    return round(annual_tax/12,2)

@app.post("/payroll/run")
def run_payroll(data: MonthIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"HR")
    month = data.month
    if len(month)!=7 or month[4]!="-": raise HTTPException(422,"Month format YYYY-MM rakhein")
    con=db(); people=con.execute("SELECT * FROM employees WHERE active=1").fetchall(); created=0
    for e in people:
        gross=e["basic_salary"]*1.5
        tax=calculate_monthly_tax(gross,con)
        # Basic payroll draft: configurable annual tax slabs plus approved unpaid leave deduction.
        unpaid=con.execute("""SELECT start_date,end_date FROM leaves WHERE employee_id=? AND status='Approved'
          AND leave_type='unpaid' AND substr(start_date,1,7)<=? AND substr(end_date,1,7)>=?""",(e["id"],month,month)).fetchall()
        unpaid_days=0
        for lv in unpaid:
            s=max(date.fromisoformat(lv["start_date"]),date.fromisoformat(month+"-01"))
            import calendar
            last=calendar.monthrange(int(month[:4]),int(month[5:]))[1]
            en=min(date.fromisoformat(lv["end_date"]),date.fromisoformat(f"{month}-{last:02d}"))
            if en>=s:
                unpaid_days += sum(1 for n in range((en-s).days+1) if (s.fromordinal(s.toordinal()+n).weekday() < 5))
        unpaid_deduction=round((gross/30)*unpaid_days,2)
        deductions=round(tax+unpaid_deduction,2)
        net=round(gross-deductions,2)
        try:
            con.execute("INSERT INTO payroll(employee_id,month,gross,deductions,net,tax) VALUES(?,?,?,?,?,?)",
                        (e["id"],month,round(gross,2),deductions,net,tax)); created+=1
        except sqlite3.IntegrityError:
            pass
    con.commit()
    rows=con.execute("SELECT p.*,e.name FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.month=?",(month,)).fetchall()
    con.close(); audit(u["email"],"payroll_draft",month)
    return {"message":"Payroll draft ready; existing month entries were not overwritten","created":created,"payroll":[dict(r) for r in rows]}

@app.post("/payroll/finalize/{month}")
def finalize_payroll(month: str, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    con=db(); con.execute("UPDATE payroll SET status='Finalized' WHERE month=? AND status='Draft'",(month,)); con.commit()
    count=con.execute("SELECT COUNT(*) n FROM payroll WHERE month=? AND status='Finalized'",(month,)).fetchone()["n"]
    con.close(); audit(u["email"],"payroll_finalized",month)
    return {"message":"Payroll finalized and locked","finalized_records":count}

@app.get("/payroll")
def get_payroll(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"]=="Employee":
        rows=con.execute("SELECT p.month,p.gross,p.deductions,p.net,p.status FROM payroll p WHERE p.employee_id=? ORDER BY p.month DESC",(u["employee_id"],)).fetchall()
    else:
        rows=con.execute("SELECT p.*,e.name FROM payroll p JOIN employees e ON e.id=p.employee_id ORDER BY p.month DESC").fetchall()
    con.close(); return [dict(r) for r in rows]

@app.get("/dashboard")
def dashboard(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db(); today=str(date.today())
    if u["role"]=="Employee":
        eid=u["employee_id"]
        attendance_count=con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND status IN ('Present','Late')",(eid,)).fetchone()["n"]
        late=con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND status='Late'",(eid,)).fetchone()["n"]
        pending=con.execute("SELECT COUNT(*) n FROM leaves WHERE employee_id=? AND status='Pending'",(eid,)).fetchone()["n"]
        result={"my_attendance_records":attendance_count,"my_late_count":late,"my_pending_leaves":pending}
    else:
        result={
          "active_employees":con.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"],
          "present_today":con.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status IN ('Present','Late')",(today,)).fetchone()["n"],
          "late_today":con.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status='Late'",(today,)).fetchone()["n"],
          "pending_leaves":con.execute("SELECT COUNT(*) n FROM leaves WHERE status='Pending'").fetchone()["n"],
          "payroll_records":con.execute("SELECT COUNT(*) n FROM payroll").fetchone()["n"]
        }
    con.close(); return result

@app.post("/announcements")
def post_announcement(data: AnnouncementIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    con=db(); con.execute("INSERT INTO announcements(title,message,created_at,author) VALUES(?,?,?,?)",
        (data.title,data.message,datetime.now().isoformat(timespec="seconds"),u["email"])); con.commit(); con.close()
    audit(u["email"],"announcement_posted",data.title)
    return {"message":"Announcement posted"}

@app.get("/announcements")
def announcements(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db(); rows=con.execute("SELECT title,message,created_at,author FROM announcements ORDER BY id DESC").fetchall(); con.close()
    return [dict(r) for r in rows]

@app.get("/audit")
def audit_log(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    con=db(); rows=con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall(); con.close()
    return [dict(r) for r in rows]



# ---- Additional HCM Lite workflows ----
from fastapi import UploadFile, File
from fastapi.responses import Response
from pydantic import Field

class PasswordIn(BaseModel):
    old_password: str
    new_password: str

class SettingIn(BaseModel):
    office_start: str = "09:00"
    grace_minutes: int = 15
    half_day_hours: float = 5
    weekend_days: str = "5,6"
    office_lat: Optional[float] = None
    office_lng: Optional[float] = None
    office_radius_m: int = 150

class HolidayIn(BaseModel):
    day: str
    name: str

class HRUserIn(BaseModel):
    name: str
    email: str
    password: str

class CorrectionIn(BaseModel):
    day: str
    requested_check_in: Optional[str] = None
    requested_check_out: Optional[str] = None
    reason: str

class CorrectionDecisionIn(BaseModel):
    status: str
    comment: str = ""

class SmartLeaveIn(BaseModel):
    text: str

@app.post("/change-password")
def change_password(data: PasswordIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization)
    if len(data.new_password)<8: raise HTTPException(422,"New password must be at least 8 characters")
    if not password_ok(data.old_password,u["password"]): raise HTTPException(400,"Current password is incorrect")
    con=db(); con.execute("UPDATE users SET password=? WHERE id=?",(password_hash(data.new_password),u["id"])); con.commit(); con.close()
    audit(u["email"],"password_changed")
    return {"message":"Password changed successfully"}

@app.post("/hr-users")
def create_hr_user(data: HRUserIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    if len(data.password)<8: raise HTTPException(422,"Password must be at least 8 characters")
    con=db()
    try:
        con.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'HR')",(data.name,data.email,password_hash(data.password)))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); raise HTTPException(409,"Email already exists")
    con.close(); audit(u["email"],"hr_user_created",data.email)
    return {"message":"HR login created"}

@app.get("/settings")
def get_settings(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    defaults={"office_start":"09:00","grace_minutes":"15","half_day_hours":"5","weekend_days":"5,6","office_lat":"","office_lng":"","office_radius_m":"150"}
    con=db(); rows=con.execute("SELECT key,value FROM settings").fetchall(); con.close()
    defaults.update({r["key"]:r["value"] for r in rows})
    return defaults

@app.put("/settings")
def update_settings(data: SettingIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    if not 0<=data.grace_minutes<=180 or data.half_day_hours<=0 or data.office_radius_m<=0: raise HTTPException(422,"Invalid setting values")
    values={"office_start":data.office_start,"grace_minutes":str(data.grace_minutes),"half_day_hours":str(data.half_day_hours),"weekend_days":data.weekend_days,"office_lat":"" if data.office_lat is None else str(data.office_lat),"office_lng":"" if data.office_lng is None else str(data.office_lng),"office_radius_m":str(data.office_radius_m)}
    con=db(); con.executemany("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",values.items()); con.commit(); con.close()
    audit(u["email"],"settings_updated",json.dumps(values))
    return {"message":"Company settings saved","settings":values}

@app.post("/holidays")
def add_holiday(data: HolidayIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    try: date.fromisoformat(data.day)
    except ValueError: raise HTTPException(422,"Date must be YYYY-MM-DD")
    con=db()
    try: con.execute("INSERT INTO holidays(day,name) VALUES(?,?)",(data.day,data.name)); con.commit()
    except sqlite3.IntegrityError: con.close(); raise HTTPException(409,"Holiday already exists")
    con.close(); audit(u["email"],"holiday_created",data.day)
    return {"message":"Holiday added"}

@app.get("/holidays")
def get_holidays(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    con=db(); rows=con.execute("SELECT * FROM holidays ORDER BY day").fetchall(); con.close(); return [dict(r) for r in rows]

def working_days(start, end):
    if end < start: return 0
    con=db(); settings={r["key"]:r["value"] for r in con.execute("SELECT key,value FROM settings").fetchall()}; holiday_dates={r["day"] for r in con.execute("SELECT day FROM holidays").fetchall()}; con.close()
    try: weekends={int(x) for x in settings.get("weekend_days","5,6").split(",") if x.strip()}
    except ValueError: weekends={5,6}
    total=0; cur=start
    while cur<=end:
        if cur.weekday() not in weekends and cur.isoformat() not in holiday_dates: total+=1
        cur=date.fromordinal(cur.toordinal()+1)
    return total

@app.get("/leave-balance")
def leave_balance(authorization: Optional[str]=Header(None), year: int = None):
    u=current_user(authorization); role(u,"Employee")
    year=year or date.today().year; eid=u["employee_id"]
    quotas={"annual":14,"sick":8,"casual":10,"unpaid":9999}
    con=db(); rows=con.execute("SELECT leave_type,start_date,end_date FROM leaves WHERE employee_id=? AND status='Approved' AND substr(start_date,1,4)=?",(eid,str(year))).fetchall(); con.close()
    used={k:0 for k in quotas}
    for r in rows:
        typ=r["leave_type"].lower()
        if typ in used: used[typ]+=working_days(date.fromisoformat(r["start_date"]),date.fromisoformat(r["end_date"]))
    return {k:{"quota":quotas[k],"used":used[k],"remaining":max(0,quotas[k]-used[k]) if k!="unpaid" else "unlimited"} for k in quotas}

@app.delete("/leaves/{leave_id}")
def cancel_leave(leave_id: int, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); eid=employee_for(u); con=db(); row=con.execute("SELECT * FROM leaves WHERE id=? AND employee_id=?",(leave_id,eid)).fetchone()
    if not row: con.close(); raise HTTPException(404,"Leave request not found")
    if row["status"]!="Pending": con.close(); raise HTTPException(409,"Only pending leave can be cancelled")
    con.execute("DELETE FROM leaves WHERE id=?",(leave_id,)); con.commit(); con.close(); audit(u["email"],"leave_cancelled",str(leave_id))
    return {"message":"Pending leave cancelled"}

@app.post("/attendance/corrections")
def request_correction(data: CorrectionIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); eid=employee_for(u)
    try: date.fromisoformat(data.day)
    except ValueError: raise HTTPException(422,"Date must be YYYY-MM-DD")
    if not data.reason.strip(): raise HTTPException(422,"Reason is required")
    con=db(); cur=con.execute("INSERT INTO corrections(employee_id,day,requested_check_in,requested_check_out,reason,created_at) VALUES(?,?,?,?,?,?)",(eid,data.day,data.requested_check_in,data.requested_check_out,data.reason,datetime.now().isoformat(timespec="seconds"))); con.commit(); cid=cur.lastrowid; con.close()
    audit(u["email"],"attendance_correction_requested",str(cid)); return {"message":"Correction request submitted","id":cid}

@app.get("/attendance/corrections")
def list_corrections(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"]=="Employee": rows=con.execute("SELECT c.* FROM corrections c WHERE c.employee_id=? ORDER BY c.id DESC",(u["employee_id"],)).fetchall()
    else: rows=con.execute("SELECT c.*,e.name,e.department FROM corrections c JOIN employees e ON e.id=c.employee_id ORDER BY c.id DESC").fetchall()
    con.close(); return [dict(r) for r in rows]

@app.patch("/attendance/corrections/{correction_id}")
def decide_correction(correction_id: int, data: CorrectionDecisionIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"HR")
    if data.status not in ("Approved","Rejected"): raise HTTPException(422,"Status must be Approved or Rejected")
    con=db(); c=con.execute("SELECT * FROM corrections WHERE id=?",(correction_id,)).fetchone()
    if not c: con.close(); raise HTTPException(404,"Correction not found")
    if c["status"]!="Pending": con.close(); raise HTTPException(409,"Already decided")
    if data.status=="Approved":
        a=con.execute("SELECT * FROM attendance WHERE employee_id=? AND day=?",(c["employee_id"],c["day"])).fetchone()
        if a:
            ci=c["requested_check_in"] or a["check_in"]; co=c["requested_check_out"] or a["check_out"]
            con.execute("UPDATE attendance SET check_in=?,check_out=? WHERE id=?",(ci,co,a["id"]))
        elif c["requested_check_in"]:
            try: dt=datetime.fromisoformat(c["requested_check_in"]); st="Late" if dt.strftime("%H:%M")>attendance_cutoff() else "Present"
            except ValueError: con.close(); raise HTTPException(422,"Requested check-in must be ISO datetime")
            con.execute("INSERT INTO attendance(employee_id,day,check_in,check_out,status) VALUES(?,?,?,?,?)",(c["employee_id"],c["day"],c["requested_check_in"],c["requested_check_out"],st))
        else: con.close(); raise HTTPException(422,"A check-in time is required to create an attendance record")
    con.execute("UPDATE corrections SET status=?,comment=? WHERE id=?",(data.status,data.comment,correction_id)); con.commit(); con.close(); audit(u["email"],"attendance_correction_"+data.status.lower(),str(correction_id))
    return {"message":"Correction "+data.status.lower()}

@app.get("/notifications")
def notifications(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db(); rows=con.execute("SELECT * FROM notifications WHERE email=? ORDER BY id DESC LIMIT 100",(u["email"],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.post("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db(); cur=con.execute("UPDATE notifications SET is_read=1 WHERE id=? AND email=?",(notification_id,u["email"])); con.commit(); con.close()
    if cur.rowcount==0: raise HTTPException(404,"Notification not found")
    return {"message":"Marked as read"}

@app.get("/payroll/{month}/csv")
def payroll_csv(month: str, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin","HR")
    con=db(); rows=con.execute("SELECT e.code,e.name,e.department,p.month,p.gross,p.tax,p.deductions,p.net,p.status FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.month=? ORDER BY e.name",(month,)).fetchall(); con.close()
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["code","name","department","month","gross","tax","total_deductions","net","status"])
    for r in rows: writer.writerow(list(r))
    return StreamingResponse(iter([output.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f"attachment; filename=payroll-{month}.csv"})

@app.get("/employees/export.csv")
def export_employees(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"HR")
    con=db(); rows=con.execute("SELECT code,name,email,department,designation,basic_salary,phone,address,join_date FROM employees ORDER BY name").fetchall(); con.close()
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["code","name","email","department","designation","basic_salary","phone","address","join_date"])
    for r in rows: writer.writerow(list(r))
    return StreamingResponse(iter([output.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=employees.csv"})

@app.post("/employees/import/validate")
def validate_employee_csv(data: dict, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"HR")
    content=data.get("csv","")
    if not isinstance(content,str) or not content.strip(): raise HTTPException(422,"Provide CSV text in 'csv'")
    reader=csv.DictReader(io.StringIO(content)); errors=[]; valid=0
    required={"code","name","email","department","designation","basic_salary","phone","address","join_date"}
    if not required.issubset(set(reader.fieldnames or [])): raise HTTPException(422,"CSV headers required: "+", ".join(sorted(required)))
    con=db(); depts={r["name"] for r in con.execute("SELECT name FROM departments")}; codes={r["code"] for r in con.execute("SELECT code FROM employees")}; emails={r["email"] for r in con.execute("SELECT email FROM employees")}
    for i,row in enumerate(reader,start=2):
        row_errors=[]
        for f in ("code","name","email","department","join_date","basic_salary"):
            if not (row.get(f) or "").strip(): row_errors.append(f+" is required")
        if row.get("email") and "@" not in row["email"]: row_errors.append("invalid email")
        if row.get("code") in codes: row_errors.append("duplicate employee code")
        if row.get("email") in emails: row_errors.append("duplicate email")
        if row.get("department") and row["department"] not in depts: row_errors.append("unknown department")
        try:
            if float(row.get("basic_salary",0))<=0: row_errors.append("salary must be > 0")
            date.fromisoformat(row.get("join_date",""))
        except Exception: row_errors.append("invalid salary or join_date")
        if row_errors: errors.append({"row":i,"errors":row_errors})
        else: valid+=1; codes.add(row["code"]); emails.add(row["email"])
    con.close(); return {"valid_rows":valid,"errors":errors,"dry_run_only":True}

@app.get("/payslip/{month}/{employee_id}")
def payslip(month: str, employee_id: int, authorization: Optional[str]=Header(None)):
    u=current_user(authorization)
    if u["role"]=="Employee" and u["employee_id"]!=employee_id: raise HTTPException(403,"You can only view your own payslip")
    role(u,"Admin","HR","Employee")
    con=db(); row=con.execute("SELECT p.*,e.name,e.code,e.department,e.designation FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.month=? AND p.employee_id=?",(month,employee_id)).fetchone(); con.close()
    if not row: raise HTTPException(404,"Payslip not found")
    return {k:row[k] for k in row.keys()}

@app.post("/ai/smart-leave")
def smart_leave(data: SmartLeaveIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Employee")
    q=data.text.lower(); typ="casual"
    if "sick" in q or "ill" in q or "tabiyat" in q: typ="sick"
    elif "annual" in q or "vacation" in q: typ="annual"
    elif "unpaid" in q: typ="unpaid"
    # Lightweight date parsing; uncertain phrases fall back to today's date and require user confirmation.
    import re
    dates=re.findall(r"\b20\d{2}-\d{2}-\d{2}\b",data.text)
    start=dates[0] if dates else str(date.today()); end=dates[1] if len(dates)>1 else start
    try:
        if date.fromisoformat(end)<date.fromisoformat(start): raise ValueError()
    except ValueError: raise HTTPException(422,"Please provide valid dates in YYYY-MM-DD format")
    return {"type":typ,"start":start,"end":end,"reason":data.text,"requires_user_confirmation":True,"note":"Dates are only auto-detected when written as YYYY-MM-DD; confirm before submitting."}

@app.post("/ai/chat")
def ai_chat_v2(data: ChatIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); q=data.question.lower(); con=db()
    # The optional hosted model is server-side only. Without AI_API_KEY, use transparent local fallback.
    answer=None
    if os.getenv("AI_API_KEY"):
        try:
            import urllib.request
            endpoint=os.getenv("AI_BASE_URL","https://api.openai.com/v1/chat/completions")
            model=os.getenv("AI_MODEL","gpt-4o-mini")
            if u["role"]=="Employee":
                context={"my_attendance":con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=?",(u["employee_id"],)).fetchone()["n"],"my_leaves":con.execute("SELECT leave_type,status,start_date,end_date FROM leaves WHERE employee_id=? ORDER BY id DESC LIMIT 20",(u["employee_id"],)).fetchall()}
            else:
                context={"active_employees":con.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"],"pending_leaves":con.execute("SELECT COUNT(*) n FROM leaves WHERE status='Pending'").fetchone()["n"],"late_this_month":con.execute("SELECT COUNT(*) n FROM attendance WHERE status='Late' AND substr(day,1,7)=?",(str(date.today())[:7],)).fetchone()["n"]}
            payload={"model":model,"messages":[{"role":"system","content":"You are HCM Lite HR policy helper. Answer only using the provided database summary and rules: check-in after 09:15 is late; annual quota 14, sick 8, casual 10; leave excludes weekends/holidays; payroll is draft until Admin finalizes. Never reveal another employee's private salary or data. If unsure say you do not know. Label answers AI-generated."},{"role":"user","content":"Question: "+data.question+"\nAuthorized context: "+json.dumps(context,default=str)}],"temperature":0.2}
            req=urllib.request.Request(endpoint,data=json.dumps(payload).encode(),headers={"Authorization":"Bearer "+os.getenv("AI_API_KEY"),"Content-Type":"application/json"},method="POST")
            with urllib.request.urlopen(req,timeout=15) as response: out=json.loads(response.read().decode())
            answer=out["choices"][0]["message"]["content"]
        except Exception:
            answer=None
    if not answer:
        if "salary" in q and u["role"]=="Employee": answer="Privacy ke liye main kisi colleague ki salary share nahi kar sakta."
        elif any(w in q for w in ("headcount","employee count","kitne employee","employees")) and u["role"]!="Employee": answer=f"Active employees: {con.execute('SELECT COUNT(*) n FROM employees WHERE active=1').fetchone()['n']}."
        elif "late" in q:
            if u["role"]=="Employee": n=con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND status='Late'",(u["employee_id"],)).fetchone()["n"]
            else: n=con.execute("SELECT COUNT(*) n FROM attendance WHERE status='Late' AND substr(day,1,7)=?",(str(date.today())[:7],)).fetchone()["n"]
            answer=f"Late attendance records: {n}."
        elif "leave" in q:
            if u["role"]=="Employee": answer="Apni leave balance /leave-balance endpoint se check karein. Quotas: annual 14, sick 8, casual 10 working days."
            else: answer="Pending leave requests: "+str(con.execute("SELECT COUNT(*) n FROM leaves WHERE status='Pending'").fetchone()["n"])+"."
        elif "attendance" in q: answer="Check-in 09:15 ke baad ho to status Late hota hai. Attendance records dashboard se check karein."
        elif "payroll" in q: answer="HR monthly payroll draft banata hai; sirf Admin payroll finalize kar sakta hai."
        else: answer="Main HCM Lite helper hoon. Employees, late attendance, leave policy, attendance ya payroll ke bare mein poochhein."
    con.execute("INSERT INTO ai_logs(email,question,created_at) VALUES(?,?,?)",(u["email"],data.question[:1000],datetime.now().isoformat(timespec="seconds"))); con.commit(); con.close()
    return {"answer":answer,"label":"AI-generated","provider":"hosted-model" if os.getenv("AI_API_KEY") else "local-fallback"}

class EmployeeEditIn(BaseModel):
    phone: Optional[str] = None
    address: Optional[str] = None
    designation: Optional[str] = None
    department: Optional[str] = None
    basic_salary: Optional[float] = None

@app.patch("/employees/{employee_id}")
def edit_employee(employee_id: int, data: EmployeeEditIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization)
    if u["role"]=="Employee":
        if u["employee_id"]!=employee_id: raise HTTPException(403,"You can only edit your own contact details")
        allowed={"phone":data.phone,"address":data.address}
    else:
        role(u,"HR")
        allowed={"phone":data.phone,"address":data.address,"designation":data.designation,"department":data.department,"basic_salary":data.basic_salary}
    updates={k:v for k,v in allowed.items() if v is not None}
    if not updates: raise HTTPException(422,"No fields provided")
    if "basic_salary" in updates and updates["basic_salary"]<=0: raise HTTPException(422,"Salary must be greater than zero")
    con=db(); row=con.execute("SELECT id FROM employees WHERE id=?",(employee_id,)).fetchone()
    if not row: con.close(); raise HTTPException(404,"Employee not found")
    sql="UPDATE employees SET "+", ".join(k+"=?" for k in updates)+" WHERE id=?"
    con.execute(sql,tuple(updates.values())+(employee_id,)); con.commit(); con.close()
    audit(u["email"],"employee_updated",json.dumps({"employee_id":employee_id,"fields":list(updates)}))
    return {"message":"Employee details updated","fields":list(updates)}

@app.post("/employees/{employee_id}/deactivate")
def deactivate_employee(employee_id: int, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    con=db(); row=con.execute("SELECT email FROM employees WHERE id=?",(employee_id,)).fetchone()
    if not row: con.close(); raise HTTPException(404,"Employee not found")
    con.execute("UPDATE employees SET active=0 WHERE id=?",(employee_id,)); con.execute("UPDATE users SET active=0 WHERE employee_id=?",(employee_id,)); con.commit(); con.close()
    audit(u["email"],"employee_deactivated",str(employee_id)); return {"message":"Employee and login deactivated"}

@app.get("/dashboard/summary")
def dashboard_summary(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); con=db()
    if u["role"]=="Employee":
        eid=u["employee_id"]
        result={"attendance_records":con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=?",(eid,)).fetchone()["n"],"late_count":con.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND status='Late'",(eid,)).fetchone()["n"],"pending_leaves":con.execute("SELECT COUNT(*) n FROM leaves WHERE employee_id=? AND status='Pending'",(eid,)).fetchone()["n"],"approved_leaves":con.execute("SELECT COUNT(*) n FROM leaves WHERE employee_id=? AND status='Approved'",(eid,)).fetchone()["n"]}
    else:
        result={"active_employees":con.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"],"present_today":con.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status IN ('Present','Late')",(str(date.today()),)).fetchone()["n"],"late_today":con.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status='Late'",(str(date.today()),)).fetchone()["n"],"pending_leaves":con.execute("SELECT COUNT(*) n FROM leaves WHERE status='Pending'").fetchone()["n"],"departments":con.execute("SELECT COUNT(*) n FROM departments").fetchone()["n"]}
    con.close(); return result

@app.get("/ai/logs")
def ai_logs(authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    con=db(); rows=con.execute("SELECT id,email,question,created_at FROM ai_logs ORDER BY id DESC LIMIT 200").fetchall(); con.close(); return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


# ---- Completion additions: real CSV import, PDF payslips, and analytics ----
from fastapi.responses import Response

@app.post("/employees/import")
def import_employees(data: dict, authorization: Optional[str]=Header(None)):
    """Import CSV text. CSV needs code,name,email,department,basic_salary,join_date.
    Optional columns: designation,phone,address,password. Missing passwords are generated.
    The generated temporary passwords are returned once; ask users to change them immediately.
    """
    u=current_user(authorization); role(u,"Admin","HR")
    content=data.get("csv","")
    if not isinstance(content,str) or not content.strip(): raise HTTPException(422,"Provide CSV text in 'csv'")
    reader=csv.DictReader(io.StringIO(content))
    required={"code","name","email","department","basic_salary","join_date"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise HTTPException(422,"Required CSV headers: "+", ".join(sorted(required)))
    con=db(); imported=[]; errors=[]
    for line,row in enumerate(reader,start=2):
        try:
            code=(row.get("code") or "").strip(); name=(row.get("name") or "").strip()
            email=(row.get("email") or "").strip().lower(); department=(row.get("department") or "").strip()
            salary=float(row.get("basic_salary") or 0); join_date=(row.get("join_date") or "").strip()
            date.fromisoformat(join_date)
            if not all((code,name,email,department)) or "@" not in email or salary<=0:
                raise ValueError("required field/email/salary invalid")
            if not con.execute("SELECT 1 FROM departments WHERE name=?",(department,)).fetchone():
                raise ValueError("unknown department; create it first")
            temp=(row.get("password") or "").strip() or base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
            if len(temp)<8: raise ValueError("password must be at least 8 characters")
            cur=con.execute("INSERT INTO employees(code,name,email,department,designation,basic_salary,phone,address,join_date) VALUES(?,?,?,?,?,?,?,?,?)",
                (code,name,email,department,(row.get("designation") or "").strip(),salary,(row.get("phone") or "").strip(),(row.get("address") or "").strip(),join_date))
            con.execute("INSERT INTO users(name,email,password,role,employee_id) VALUES(?,?,?,'Employee',?)",(name,email,password_hash(temp),cur.lastrowid))
            imported.append({"row":line,"code":code,"email":email,"temporary_password":temp})
        except Exception as exc:
            errors.append({"row":line,"error":str(exc)[:180]})
    con.commit(); con.close()
    audit(u["email"],"employee_csv_import",json.dumps({"imported":len(imported),"errors":len(errors)}))
    return {"imported_count":len(imported),"errors":errors,"temporary_credentials":imported,"warning":"Share temporary passwords privately and require users to change them."}

@app.get("/payslip/{month}/{employee_id}/pdf")
def payslip_pdf(month: str, employee_id: int, authorization: Optional[str]=Header(None)):
    u=current_user(authorization)
    if u["role"]=="Employee" and u["employee_id"]!=employee_id:
        raise HTTPException(403,"You can only download your own payslip")
    role(u,"Admin","HR","Employee")
    con=db(); row=con.execute("SELECT p.*,e.name,e.code,e.department,e.designation,e.email FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.month=? AND p.employee_id=?",(month,employee_id)).fetchone(); con.close()
    if not row: raise HTTPException(404,"Payslip not found")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        raise HTTPException(500,"PDF dependency missing. Run: pip install -r requirements.txt")
    buff=io.BytesIO(); c=canvas.Canvas(buff,pagesize=A4); width,height=A4
    c.setTitle(f"Payslip {row['code']} {month}")
    c.setFont("Helvetica-Bold",20); c.drawString(55,height-60,"HCM Lite — Payslip")
    c.setFont("Helvetica",11); c.drawString(55,height-90,f"Payroll month: {month}")
    c.drawString(55,height-112,f"Employee: {row['name']} ({row['code']})")
    c.drawString(55,height-134,f"Department: {row['department']}")
    c.drawString(55,height-156,f"Designation: {row['designation'] or '-'}")
    c.drawString(55,height-178,f"Status: {row['status']}")
    c.line(55,height-200,width-55,height-200)
    c.setFont("Helvetica-Bold",12); c.drawString(65,height-230,"Earnings / Deductions"); c.drawString(width-170,height-230,"Amount")
    c.setFont("Helvetica",11)
    c.drawString(65,height-260,"Gross salary"); c.drawRightString(width-65,height-260,f"{row['gross']:,.2f}")
    c.drawString(65,height-285,"Estimated tax withholding"); c.drawRightString(width-65,height-285,f"{row['tax']:,.2f}")
    c.drawString(65,height-310,"Total deductions"); c.drawRightString(width-65,height-310,f"{row['deductions']:,.2f}")
    c.line(55,height-330,width-55,height-330)
    c.setFont("Helvetica-Bold",14); c.drawString(65,height-360,"Net pay"); c.drawRightString(width-65,height-360,f"{row['net']:,.2f}")
    c.setFont("Helvetica-Oblique",9); c.drawString(55,55,"Generated by HCM Lite. Verify payroll figures with your organization.")
    c.showPage(); c.save(); buff.seek(0)
    return Response(content=buff.read(),media_type="application/pdf",headers={"Content-Disposition":f"attachment; filename=payslip-{row['code']}-{month}.pdf"})

@app.get("/analytics/monthly")
def monthly_analytics(authorization: Optional[str]=Header(None), months: int=12):
    u=current_user(authorization); role(u,"Admin","HR")
    months=max(1,min(months,36)); con=db()
    rows=con.execute("SELECT substr(day,1,7) month, COUNT(*) attendance_records, SUM(CASE WHEN status='Late' THEN 1 ELSE 0 END) late_records FROM attendance WHERE day>=date('now', ?) GROUP BY substr(day,1,7) ORDER BY month",(f"-{months} months",)).fetchall()
    payroll=con.execute("SELECT month,COUNT(*) employees,ROUND(SUM(gross),2) gross,ROUND(SUM(deductions),2) deductions,ROUND(SUM(net),2) net FROM payroll GROUP BY month ORDER BY month DESC LIMIT ?",(months,)).fetchall()
    con.close(); return {"attendance": [dict(r) for r in rows],"payroll": [dict(r) for r in reversed(payroll)]}


class TaxSlabsIn(BaseModel):
    slabs: list[dict]

@app.put("/settings/tax-slabs")
def set_tax_slabs(data: TaxSlabsIn, authorization: Optional[str]=Header(None)):
    u=current_user(authorization); role(u,"Admin")
    if not data.slabs: raise HTTPException(422,"Provide at least one tax slab; use rate 0 for no withholding")
    previous=0.0
    for i,slab in enumerate(data.slabs):
        if "rate" not in slab: raise HTTPException(422,f"Slab {i+1} requires rate")
        rate=float(slab["rate"])
        if not 0<=rate<=100: raise HTTPException(422,"Tax rate must be between 0 and 100")
        if "up_to" in slab:
            upper=float(slab["up_to"])
            if upper<=previous: raise HTTPException(422,"up_to values must increase")
            previous=upper
        elif i != len(data.slabs)-1: raise HTTPException(422,"Only final slab may omit up_to")
    value=json.dumps(data.slabs)
    con=db(); con.execute("INSERT INTO settings(key,value) VALUES('tax_slabs_json',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(value,)); con.commit(); con.close()
    audit(u["email"],"tax_slabs_updated",value)
    return {"message":"Tax slabs saved. They apply to future payroll drafts only.","slabs":data.slabs}
