"""Cybersecurity Risk Management System - Flask + SQLite."""
import csv
import io
import os
import secrets
import sqlite3
import time
from datetime import date
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from i18n import T

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('RISK_DB', os.path.join(BASE, 'risk.db'))
ROLES = {'viewer': 1, 'analyst': 2, 'admin': 3}
STATUS = ['open', 'in_progress', 'treated', 'closed']
TREAT = ['mitigate', 'accept', 'transfer', 'avoid']
TYPES = ['server', 'application', 'database', 'network', 'device', 'data', 'people']
FAILS = {}  # ip -> (count, first_ts)


def _secret():
    p = os.path.join(BASE, 'secret.key')
    if not os.path.exists(p):
        with open(p, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(p) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(SECRET_KEY=_secret(), SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=3600)


# ---------- helpers ----------
def lvl(s):
    return 3 if s >= 17 else 2 if s >= 10 else 1 if s >= 5 else 0


def cur_lang():
    return session.get('lang', 'ar')


def t(k):
    return T.get(k, (k, k))[0 if cur_lang() == 'ar' else 1]


def bi(s):
    """'English | عربي' -> pick by language; plain text unchanged."""
    if s and ' | ' in s:
        en, ar = s.split(' | ', 1)
        return ar if cur_lang() == 'ar' else en
    return s


def can(role):
    return bool(g.get('user')) and ROLES[g.user['role']] >= ROLES[role]


def need(role='viewer'):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                return redirect(url_for('login'))
            if not can(role):
                abort(403)
            return f(*a, **k)
        return w
    return deco


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_db(_e=None):
    db = g.pop('db', None)
    if db:
        db.close()


def audit(action, entity, eid=None, details=''):
    get_db().execute('INSERT INTO audit_log(username,action,entity,entity_id,details) VALUES(?,?,?,?,?)',
                     (g.user['username'] if g.get('user') else '-', action, entity, eid, details))


@app.before_request
def before():
    g.user = None
    if session.get('uid'):
        g.user = get_db().execute('SELECT * FROM users WHERE id=?', (session['uid'],)).fetchone()
        if not g.user:
            session.clear()
    if request.method == 'POST':
        sent, real = request.form.get('csrf', ''), session.get('csrf', '')
        if not real or not secrets.compare_digest(sent, real):
            abort(400)


@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['Referrer-Policy'] = 'same-origin'
    r.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    r.headers['Cache-Control'] = 'no-store'
    return r


@app.context_processor
def ctx():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return dict(t=t, lang=cur_lang(), user=g.get('user'), csrf=session['csrf'], lvl=lvl, bi=bi, can=can)


def all_risks():
    return get_db().execute('''
      SELECT r.*, a.name AS asset_name, th.name AS threat_name, v.name AS vuln_name,
             u.full_name AS owner_name, r.likelihood*r.impact AS score,
             r.res_likelihood*r.res_impact AS res_score
      FROM risks r JOIN assets a ON a.id=r.asset_id JOIN threats th ON th.id=r.threat_id
      JOIN vulnerabilities v ON v.id=r.vulnerability_id LEFT JOIN users u ON u.id=r.owner_id
      ORDER BY score DESC, r.id''').fetchall()


def stats(rs):
    act = [r for r in rs if r['status'] != 'closed']
    n = len(act) or 1
    cnt, mx = [0] * 4, {}
    st = {k: 0 for k in STATUS}
    for r in rs:
        st[r['status']] += 1
    for r in act:
        cnt[lvl(r['score'])] += 1
        key = (r['likelihood'], r['impact'])
        mx[key] = mx.get(key, 0) + 1
    today = date.today().isoformat()
    return dict(total=len(rs), cnt=cnt, mx=mx, st=st,
                avg=round(sum(r['score'] for r in act) / n, 1),
                avg_res=round(sum(r['res_score'] for r in act) / n, 1),
                overdue=sum(1 for r in act if r['due_date'] and r['due_date'] < today and r['status'] != 'treated'),
                top=act[:5])


# ---------- auth ----------
@app.route('/lang/<code>')
def lang(code):
    session['lang'] = 'en' if code == 'en' else 'ar'
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        cnt, first = FAILS.get(ip, (0, time.time()))
        if time.time() - first > 300:
            cnt, first = 0, time.time()
        if cnt >= 5:
            flash(t('locked'), 'err')
            return render_template('login.html'), 429
        u = get_db().execute('SELECT * FROM users WHERE username=?', (request.form.get('username', '').strip(),)).fetchone()
        if u and check_password_hash(u['password_hash'], request.form.get('password', '')):
            FAILS.pop(ip, None)
            lg, csrf = session.get('lang', 'ar'), None
            session.clear()
            session.update(uid=u['id'], lang=lg, csrf=secrets.token_hex(16))
            session.permanent = True
            g.user = u
            audit('login', 'user', u['id'])
            get_db().commit()
            return redirect(url_for('dashboard'))
        FAILS[ip] = (cnt + 1, first)
        flash(t('bad_login'), 'err')
    return render_template('login.html')


@app.route('/logout')
def logout():
    lg = session.get('lang', 'ar')
    session.clear()
    session['lang'] = lg
    return redirect(url_for('login'))


@app.route('/password', methods=['GET', 'POST'])
@need()
def password():
    if request.method == 'POST':
        old, new = request.form.get('old', ''), request.form.get('new', '')
        if not check_password_hash(g.user['password_hash'], old):
            flash(t('bad_login'), 'err')
        elif len(new) < 8:
            flash(t('pw_short'), 'err')
        else:
            db = get_db()
            db.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new), g.user['id']))
            audit('password_change', 'user', g.user['id'])
            db.commit()
            flash(t('saved'))
            return redirect(url_for('dashboard'))
    return render_template('password.html')


# ---------- dashboard / report ----------
@app.route('/')
@need()
def dashboard():
    rs = all_risks()
    return render_template('dashboard.html', s=stats(rs))


@app.route('/report')
@need()
def report():
    rs = all_risks()
    assets = get_db().execute('SELECT * FROM assets ORDER BY criticality DESC').fetchall()
    return render_template('report.html', s=stats(rs), risks=rs, assets=assets, today=date.today().isoformat())


# ---------- risks ----------
def risk_rows(args):
    q, lv, st = args.get('q', '').strip().lower(), args.get('level', ''), args.get('status', '')
    out = []
    for r in all_risks():
        text = ' '.join([r['title'], r['asset_name'], r['threat_name'], r['vuln_name']]).lower()
        if (not q or q in text) and (lv == '' or str(lvl(r['score'])) == lv) and (not st or r['status'] == st):
            out.append(r)
    return out


@app.route('/risks')
@need()
def risks():
    return render_template('risks.html', rows=risk_rows(request.args), f=request.args)


@app.route('/risks/export.csv')
@need()
def risks_csv():
    def safe(v):
        v = '' if v is None else str(v)
        return "'" + v if v[:1] in ('=', '+', '-', '@') else v
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([t(k) for k in ('title', 'asset', 'threat', 'vuln', 'likelihood', 'impact', 'level', 'treatment', 'action', 'owner', 'due', 'status', 'residual')])
    for r in risk_rows(request.args):
        w.writerow([safe(x) for x in (r['title'], bi(r['asset_name']), bi(r['threat_name']), bi(r['vuln_name']),
                    r['likelihood'], r['impact'], '%s (%d)' % (t('lv_%d' % lvl(r['score'])), r['score']),
                    t('tr_' + r['treatment']), r['action'], r['owner_name'], r['due_date'],
                    t('st_' + r['status']), r['res_score'])])
    return Response('\ufeff' + buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename=risk-register.csv'})


def risk_form(rid=None):
    db = get_db()
    row = db.execute('SELECT * FROM risks WHERE id=?', (rid,)).fetchone() if rid else None
    if rid and not row:
        abort(404)
    if request.method == 'POST':
        f = request.form
        try:
            d = dict(title=f['title'].strip(), asset_id=int(f['asset_id']), threat_id=int(f['threat_id']),
                     vulnerability_id=int(f['vulnerability_id']), likelihood=int(f['likelihood']),
                     impact=int(f['impact']), res_likelihood=int(f['res_likelihood']), res_impact=int(f['res_impact']),
                     treatment=f['treatment'], action=f.get('action', '').strip(),
                     owner_id=int(f['owner_id']) if f.get('owner_id') else None,
                     due_date=f.get('due_date') or None, status=f['status'])
            assert d['title'] and d['treatment'] in TREAT and d['status'] in STATUS
            assert all(1 <= d[k] <= 5 for k in ('likelihood', 'impact', 'res_likelihood', 'res_impact'))
            if d['due_date']:
                date.fromisoformat(d['due_date'])
            if rid:
                db.execute('''UPDATE risks SET title=:title,asset_id=:asset_id,threat_id=:threat_id,
                  vulnerability_id=:vulnerability_id,likelihood=:likelihood,impact=:impact,res_likelihood=:res_likelihood,
                  res_impact=:res_impact,treatment=:treatment,action=:action,owner_id=:owner_id,due_date=:due_date,
                  status=:status,updated_at=CURRENT_TIMESTAMP WHERE id=:id''', dict(d, id=rid))
                audit('update', 'risk', rid, d['title'])
            else:
                cur = db.execute('''INSERT INTO risks(title,asset_id,threat_id,vulnerability_id,likelihood,impact,
                  res_likelihood,res_impact,treatment,action,owner_id,due_date,status,created_by) VALUES
                  (:title,:asset_id,:threat_id,:vulnerability_id,:likelihood,:impact,:res_likelihood,:res_impact,
                  :treatment,:action,:owner_id,:due_date,:status,:cb)''', dict(d, cb=g.user['id']))
                audit('create', 'risk', cur.lastrowid, d['title'])
            db.commit()
            flash(t('saved'))
            return redirect(url_for('risks'))
        except (KeyError, ValueError, AssertionError, sqlite3.IntegrityError):
            db.rollback()
            flash(t('invalid'), 'err')
            row = dict(f)
    return render_template(
        'risk_form.html', r=row,
        assets=[(a['id'], bi(a['name'])) for a in db.execute('SELECT * FROM assets ORDER BY name')],
        threats=[(a['id'], bi(a['name'])) for a in db.execute('SELECT * FROM threats ORDER BY name')],
        vulns=[(a['id'], bi(a['name'])) for a in db.execute('SELECT * FROM vulnerabilities ORDER BY name')],
        owners=[(u['id'], u['full_name']) for u in db.execute('SELECT id, full_name FROM users ORDER BY full_name')],
        statuses=[(k, t('st_' + k)) for k in STATUS], treats=[(k, t('tr_' + k)) for k in TREAT])


@app.route('/risks/new', methods=['GET', 'POST'])
@need('analyst')
def risk_new():
    return risk_form()


@app.route('/risks/<int:rid>/edit', methods=['GET', 'POST'])
@need('analyst')
def risk_edit(rid):
    return risk_form(rid)


@app.route('/risks/<int:rid>/delete', methods=['POST'])
@need('analyst')
def risk_delete(rid):
    db = get_db()
    db.execute('DELETE FROM risks WHERE id=?', (rid,))
    audit('delete', 'risk', rid)
    db.commit()
    flash(t('deleted'))
    return redirect(url_for('risks'))


# ---------- assets ----------
@app.route('/assets')
@need()
def assets():
    rows = get_db().execute('''SELECT a.*, COUNT(r.id) AS n FROM assets a LEFT JOIN risks r ON r.asset_id=a.id
                               GROUP BY a.id ORDER BY a.criticality DESC, a.name''').fetchall()
    return render_template('assets.html', rows=rows)


def asset_form(aid=None):
    db = get_db()
    row = db.execute('SELECT * FROM assets WHERE id=?', (aid,)).fetchone() if aid else None
    if aid and not row:
        abort(404)
    if request.method == 'POST':
        f = request.form
        try:
            d = dict(name=f['name'].strip(), type=f['type'], owner=f.get('owner', '').strip(), criticality=int(f['criticality']))
            assert d['name'] and d['type'] in TYPES and 1 <= d['criticality'] <= 5
            if aid:
                db.execute('UPDATE assets SET name=:name,type=:type,owner=:owner,criticality=:criticality WHERE id=:id', dict(d, id=aid))
                audit('update', 'asset', aid, d['name'])
            else:
                cur = db.execute('INSERT INTO assets(name,type,owner,criticality) VALUES(:name,:type,:owner,:criticality)', d)
                audit('create', 'asset', cur.lastrowid, d['name'])
            db.commit()
            flash(t('saved'))
            return redirect(url_for('assets'))
        except (KeyError, ValueError, AssertionError):
            flash(t('invalid'), 'err')
            row = dict(f)
    return render_template('asset_form.html', a=row, types=[(k, t('ty_' + k)) for k in TYPES])


@app.route('/assets/new', methods=['GET', 'POST'])
@need('analyst')
def asset_new():
    return asset_form()


@app.route('/assets/<int:aid>/edit', methods=['GET', 'POST'])
@need('analyst')
def asset_edit(aid):
    return asset_form(aid)


@app.route('/assets/<int:aid>/delete', methods=['POST'])
@need('analyst')
def asset_delete(aid):
    db = get_db()
    try:
        db.execute('DELETE FROM assets WHERE id=?', (aid,))
        audit('delete', 'asset', aid)
        db.commit()
        flash(t('deleted'))
    except sqlite3.IntegrityError:
        db.rollback()
        flash(t('linked'), 'err')
    return redirect(url_for('assets'))


# ---------- threat / vulnerability catalog ----------
@app.route('/catalog', methods=['GET', 'POST'])
@need()
def catalog():
    db = get_db()
    if request.method == 'POST':
        if not can('analyst'):
            abort(403)
        kind, name = request.form.get('kind'), request.form.get('name', '').strip()
        table = {'threat': 'threats', 'vuln': 'vulnerabilities'}.get(kind)
        if not table or not name:
            flash(t('invalid'), 'err')
        else:
            try:
                cur = db.execute('INSERT INTO %s(name) VALUES(?)' % table, (name,))
                audit('create', kind, cur.lastrowid, name)
                db.commit()
                flash(t('saved'))
            except sqlite3.IntegrityError:
                flash(t('exists'), 'err')
        return redirect(url_for('catalog'))
    q = lambda tb, col: db.execute(
        'SELECT x.*, (SELECT COUNT(*) FROM risks WHERE %s=x.id) AS n FROM %s x ORDER BY name' % (col, tb)).fetchall()
    return render_template('catalog.html', threats=q('threats', 'threat_id'), vulns=q('vulnerabilities', 'vulnerability_id'))


# ---------- admin ----------
@app.route('/users', methods=['GET', 'POST'])
@need('admin')
def users():
    db = get_db()
    if request.method == 'POST':
        f = request.form
        try:
            u, n, r, p = f['username'].strip(), f['full_name'].strip(), f['role'], f['password']
            assert u and n and r in ROLES
            if len(p) < 8:
                flash(t('pw_short'), 'err')
            else:
                cur = db.execute('INSERT INTO users(username,full_name,role,password_hash) VALUES(?,?,?,?)',
                                 (u, n, r, generate_password_hash(p)))
                audit('create', 'user', cur.lastrowid, '%s (%s)' % (u, r))
                db.commit()
                flash(t('saved'))
        except (KeyError, AssertionError):
            flash(t('invalid'), 'err')
        except sqlite3.IntegrityError:
            flash(t('exists'), 'err')
        return redirect(url_for('users'))
    return render_template('users.html', rows=db.execute('SELECT * FROM users ORDER BY id').fetchall(),
                           roles=[(k, t('ro_' + k)) for k in ROLES])


@app.route('/users/<int:uid>/delete', methods=['POST'])
@need('admin')
def user_delete(uid):
    if uid == g.user['id']:
        flash(t('invalid'), 'err')
    else:
        db = get_db()
        db.execute('DELETE FROM users WHERE id=?', (uid,))
        audit('delete', 'user', uid)
        db.commit()
        flash(t('deleted'))
    return redirect(url_for('users'))


@app.route('/audit')
@need('admin')
def audit_view():
    rows = get_db().execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').fetchall()
    return render_template('audit.html', rows=rows)


# ---------- database init / seed ----------
def seed(db):
    for u, n, r, p in [('admin', 'System Admin', 'admin', 'Admin@12345'),
                       ('analyst', 'Security Analyst', 'analyst', 'Analyst@12345'),
                       ('viewer', 'Viewer', 'viewer', 'Viewer@12345')]:
        db.execute('INSERT INTO users(username,full_name,role,password_hash) VALUES(?,?,?,?)',
                   (u, n, r, generate_password_hash(p)))
    threats = ['Ransomware | برمجيات فدية', 'Unauthorized access | وصول غير مصرح به', 'Phishing | تصيّد احتيالي',
               'Data leakage | تسريب بيانات', 'Malware | برمجيات خبيثة', 'Denial of service | حجب الخدمة',
               'Insider threat | تهديد داخلي', 'Password attack | هجوم على كلمة المرور']
    vulns = ['No isolated backups | غياب نسخ احتياطي معزول', 'Excessive permissions | صلاحيات واسعة',
             'Unpatched system | نظام غير محدّث', 'Weak password policy | سياسة كلمات مرور ضعيفة',
             'Low security awareness | قلة الوعي الأمني', 'Unencrypted data | بيانات غير مشفرة',
             'No network segmentation | غياب عزل الشبكة', 'Missing monitoring | غياب المراقبة']
    db.executemany('INSERT INTO threats(name) VALUES(?)', [(x,) for x in threats])
    db.executemany('INSERT INTO vulnerabilities(name) VALUES(?)', [(x,) for x in vulns])
    assets = [('Main file server | خادم الملفات الرئيسي', 'server', 'IT', 4),
              ('Student database | قاعدة بيانات الطلبة', 'database', 'Academic Affairs', 5),
              ('Wi-Fi network | شبكة الواي فاي', 'network', 'Networks', 3),
              ('Staff laptops | حواسيب الموظفين', 'device', 'HR', 3)]
    db.executemany('INSERT INTO assets(name,type,owner,criticality) VALUES(?,?,?,?)', assets)
    risks = [('Ransomware on file server | فدية على خادم الملفات', 1, 1, 1, 4, 5, 'mitigate', 'Offline backups + EDR | نسخ احتياطي معزول وحماية', 'in_progress', 2, 4),
             ('Student data leak | تسريب بيانات الطلبة', 2, 4, 2, 3, 5, 'mitigate', 'Least privilege + review | أقل صلاحية ومراجعة دورية', 'open', 2, 3),
             ('Wi-Fi compromise | اختراق الواي فاي', 3, 8, 4, 4, 3, 'mitigate', 'WPA3 + strong passphrase | WPA3 وكلمة مرور قوية', 'treated', 1, 3),
             ('Phishing against staff | تصيّد ضد الموظفين', 4, 3, 5, 5, 3, 'mitigate', 'Awareness + mail filtering | توعية وفلترة بريد', 'open', 3, 2),
             ('Outage from old vulnerability | انقطاع بسبب ثغرة قديمة', 1, 6, 3, 2, 4, 'accept', 'Monitor | مراقبة', 'closed', 2, 3)]
    for ti, a, th, v, l, i, tr, ac, st, rl, ri in risks:
        db.execute('''INSERT INTO risks(title,asset_id,threat_id,vulnerability_id,likelihood,impact,treatment,action,
                      owner_id,due_date,status,res_likelihood,res_impact,created_by) VALUES(?,?,?,?,?,?,?,?,2,'2026-12-31',?,?,?,1)''',
                   (ti, a, th, v, l, i, tr, ac, st, rl, ri))


def init_db():
    db = sqlite3.connect(DB)
    db.execute('PRAGMA foreign_keys=ON')
    with open(os.path.join(BASE, 'schema.sql'), encoding='utf-8') as f:
        db.executescript(f.read())
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        seed(db)
    db.commit()
    db.close()


init_db()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
