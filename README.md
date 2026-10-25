# HCM Lite — Human Capital Management

A runnable FastAPI + SQLite prototype for a small organization's HR workflows. It includes role-based Admin/HR/Employee access, first-run company setup, password hashing, signed expiring bearer tokens, employee records and CSV import/export, attendance, leave requests and approvals, leave balances, holidays and office settings, correction requests, payroll drafts/finalization, configurable progressive annual tax-withholding slabs, PDF payslips, announcements, notifications, audit history, dashboards/analytics, and an optional hosted AI helper with a local fallback.

> **Important:** This is a hackathon/demo prototype, not a certified payroll or production HR system. Tax brackets are deliberately not prefilled with legal rates. An Admin must configure the organization's applicable slabs; verify all payroll and legal rules with a qualified person. Do not put real employee data in a public demo.

## Run on Windows

1. Install Python 3.10 or newer.
2. Extract this ZIP into a folder.
3. Open PowerShell in that folder and run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Set a secret for your local run (PowerShell):

   ```powershell
   $env:HCM_SECRET = "replace-with-a-long-random-secret"
   uvicorn main:app --reload
   ```

5. Open `http://127.0.0.1:8000`. Create the first Admin account, then log in. API documentation is at `http://127.0.0.1:8000/docs`.

On macOS/Linux, activate with `source .venv/bin/activate` and run `uvicorn main:app --reload` after setting `HCM_SECRET`.

## First use

- Create the Admin from the home page. Setup is allowed only while the database has no users.
- Create departments, then add HR accounts from `POST /hr-users` (Admin only).
- Admin/HR can add employees. Employees receive their own login; use a temporary password of at least 8 characters and ask them to change it via `POST /change-password`.
- For protected endpoints, log in at `POST /login` and send `Authorization: Bearer <access_token>`.
- The web home page is a small starter interface. Use `/docs` for the full API surface, including workflows not surfaced as buttons on the home page.

## Tax slabs

Configure with Admin token at `PUT /settings/tax-slabs`, for example this **illustrative structure only** (the numbers below are not legal tax guidance):

```json
{
  "slabs": [
    {"up_to": 600000, "rate": 0},
    {"up_to": 1200000, "rate": 5},
    {"rate": 10}
  ]
}
```

`up_to` values are annual taxable-income thresholds; rates are percentages. The last slab may omit `up_to`. The app annualizes monthly gross, calculates progressive estimated withholding, then divides by 12. Unpaid-leave deduction is added to tax in total deductions. Previously created payroll drafts are not recalculated when slabs change; create drafts only after checking the settings.

## Useful API endpoints

| Feature | Endpoint | Access |
|---|---|---|
| Health | `GET /health` | Public |
| Initial setup | `POST /setup` | Only before first user |
| Login/profile | `POST /login`, `GET /me` | Login/profile rules |
| Departments | `GET/POST /departments` | Admin/HR read; Admin write |
| Employees | `GET/POST /employees`, `PATCH /employees/{id}` | Role-scoped |
| CSV employee import | `POST /employees/import` | Admin/HR |
| Validate CSV without importing | `POST /employees/import/validate` | HR |
| Employee export | `GET /employees/export.csv` | HR |
| Attendance | `POST /attendance/checkin`, `POST /attendance/checkout`, `GET /attendance` | Employee write; role-scoped read |
| Leave | `POST /leaves`, `GET /leaves`, `PATCH /leaves/{id}`, `GET /leave-balance` | Role-scoped |
| Attendance corrections | `/attendance/corrections` | Role-scoped; HR decides |
| Holidays/settings | `/holidays`, `/settings` | Admin manages |
| Payroll draft/finalize | `POST /payroll/run`, `POST /payroll/finalize/{month}` | HR drafts; Admin finalizes |
| Payroll CSV/PDF payslip | `GET /payroll/{month}/csv`, `GET /payslip/{month}/{employee_id}/pdf` | Admin/HR; employee own payslip |
| Tax slabs | `PUT /settings/tax-slabs` | Admin |
| Dashboards/analytics | `GET /dashboard`, `GET /dashboard/summary`, `GET /analytics/monthly` | Role-scoped |
| Announcements/notifications | `/announcements`, `/notifications` | Login; posting Admin/HR |
| Audit log | `GET /audit` | Admin |
| AI helper | `POST /ai/chat`, `POST /ai/smart-leave` | Login; optional hosted provider |

## CSV import format

`POST /employees/import` accepts JSON with a `csv` string. Required headers: `code,name,email,department,basic_salary,join_date`. Optional: `designation,phone,address,password`. The department must already exist. If `password` is blank or omitted, a temporary password is generated and returned once in the response; handle that response privately and require a password change. Review errors and imported counts before using this with real data.

## Optional hosted AI

Set `AI_API_KEY` as an environment variable and, if needed, `AI_BASE_URL` and `AI_MODEL`. The configured endpoint must support an OpenAI-compatible chat-completions request. If no key is configured or the provider fails, the app falls back to simple local answers. Never commit an API key or add it to screenshots or the repository.

## Data and reset

The SQLite database `hcm_lite.db` is created automatically in the working directory. Back it up before upgrades. For a fresh demo only, stop the server and delete that database file; this permanently deletes the local demo records.

## Verification

Run `python -m py_compile main.py` to check syntax, then start the server and use `/docs` for endpoint-level testing. A successful syntax check does not mean every business rule, external AI provider, deployment, or organization's tax policy has been production-validated.
