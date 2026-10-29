PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN('admin','analyst','viewer')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN('server','application','database','network','device','data','people')),
  owner TEXT,
  criticality INTEGER NOT NULL CHECK(criticality BETWEEN 1 AND 5),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS threats(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS vulnerabilities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS risks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
  threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE RESTRICT,
  vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE RESTRICT,
  likelihood INTEGER NOT NULL CHECK(likelihood BETWEEN 1 AND 5),
  impact INTEGER NOT NULL CHECK(impact BETWEEN 1 AND 5),
  treatment TEXT NOT NULL CHECK(treatment IN('mitigate','accept','transfer','avoid')),
  action TEXT,
  owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  due_date TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN('open','in_progress','treated','closed')),
  res_likelihood INTEGER NOT NULL CHECK(res_likelihood BETWEEN 1 AND 5),
  res_impact INTEGER NOT NULL CHECK(res_impact BETWEEN 1 AND 5),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT, action TEXT, entity TEXT, entity_id INTEGER, details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_risks_asset ON risks(asset_id);
CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
