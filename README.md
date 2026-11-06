# Cybersecurity Risk Management System: One Asset Case Study

Organization: Basra Educational Institution (fictional).
Single asset: Student Records Database Server.
All incidents and vulnerabilities are fictional demonstration data.

## Run (Windows)
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Accounts (local demo only)
- admin / Admin@12345
- analyst / Analyst@12345
- viewer / Viewer@12345

Change passwords after first login. The SQLite database and session secret are generated on first run.

## Backend
Flask server-side routes and SQLite schema are in `app.py` and `schema.sql`. One fixed asset (ID 1), six seeded risks, six threats and six vulnerabilities. Analyst users create and update risks, assign likelihood/impact (1-5), choose treatment and track residual risk. Admin manages users. Audit logs record changes. Reports and CSV export are available.

Risk score = likelihood x impact. Existing code thresholds: Low 1-4, Medium 5-9, High 10-16, Critical 17-25. The residual risk fields are estimates, not measured security improvements.

## Discussion with supervisor
- Why this asset: contains sensitive student identity and grade records.
- Threat -> vulnerability -> risk -> likelihood/impact -> treatment -> residual risk -> status.
- One institution, one asset, six realistic example risks.
- This is a risk register, not a real-time intrusion detection system.
- Application login permissions are distinct from the student database server's security controls.

## Test
`python test_one_asset.py`
