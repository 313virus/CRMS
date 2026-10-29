# Cybersecurity Risk Management System
# نظام إدارة المخاطر السيبرانية

Flask + SQLite web application (Arabic / English, RTL / LTR).

## Run
```
pip install -r requirements.txt
python app.py          # http://127.0.0.1:5000
python test_app.py     # automated tests (uses a temporary database)
```
The database (`risk.db`) and a random `secret.key` are created automatically on first run with sample data.

| Username | Password | Role |
|---|---|---|
| admin | Admin@123 | Admin: everything + users + audit log |
| analyst | Analyst@123 | Analyst: create/edit/delete risks, assets, catalog |
| viewer | Viewer@123 | Viewer: read-only |

Change these passwords after first login (top bar -> Change password).

## Project objectives -> features
1. Electronic risk register: Risk Register page (search, filter, CSV export)
2. Assets linked to risks: Assets page (type, owner, criticality)
3. Threats and vulnerabilities: catalog tables, selected per risk
4. Likelihood (1-5) and 5. Impact (1-5)
6. Risk level = likelihood x impact: 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical
7. Treatment: mitigate / accept / transfer / avoid, action, owner, due date, residual risk
8. Status tracking: open / in progress / treated / closed, dashboard, 5x5 matrix, printable report

## Database (SQLite, 3NF, foreign keys enforced)
```mermaid
erDiagram
  USERS ||--o{ RISKS : "owns / creates"
  ASSETS ||--o{ RISKS : "has"
  THREATS ||--o{ RISKS : "causes"
  VULNERABILITIES ||--o{ RISKS : "exploited in"
  USERS { int id PK; text username UK; text password_hash; text full_name; text role }
  ASSETS { int id PK; text name; text type; text owner; int criticality }
  THREATS { int id PK; text name UK }
  VULNERABILITIES { int id PK; text name UK }
  RISKS { int id PK; text title; int asset_id FK; int threat_id FK; int vulnerability_id FK; int likelihood; int impact; text treatment; text action; int owner_id FK; text due_date; text status; int res_likelihood; int res_impact }
  AUDIT_LOG { int id PK; text username; text action; text entity; int entity_id; text details; text created_at }
```
Full DDL with CHECK constraints: `schema.sql`.

## Security controls (good material for the report)
- Passwords hashed (PBKDF2 via Werkzeug), never stored in plain text
- Role-based access control (admin / analyst / viewer) enforced on the server
- CSRF token on every POST form
- Parameterized SQL queries only (SQL injection prevention); Jinja auto-escaping (XSS prevention)
- Login throttling: 5 failed attempts -> 5 minute lock per IP
- Session cookie HttpOnly + SameSite, 1 hour lifetime, session reset on login
- Security headers: CSP, X-Frame-Options, nosniff, no-store
- CSV export protected against formula injection
- Audit log of logins and every create / update / delete
- Input validation on server side + database CHECK constraints

## Structure
```
app.py  i18n.py  schema.sql  test_app.py  requirements.txt
templates/  (Jinja2 pages)    static/  (style.css, app.js, report.js)
```
For production: run behind HTTPS with gunicorn, set SESSION_COOKIE_SECURE=True, use a shared store for login throttling.
