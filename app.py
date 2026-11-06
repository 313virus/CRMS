"""Cybersecurity Risk Management System - Flask + PostgreSQL (Supabase), SQLite locally."""
import csv
import io
import os
import secrets
import sqlite3
import re
from db_postgres import PostgresConnection, PgIntegrityError
import time
from PIL import Image, ImageOps, UnidentifiedImageError
from io import BytesIO
from datetime import date
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for, send_from_directory)
from werkzeug.security import check_password_hash, generate_password_hash

from i18n import T

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('RISK_DB', os.path.join(BASE, 'risk.db'))
DATABASE_URL = os.environ.get('DATABASE_URL')
DBIntegrityError = (sqlite3.IntegrityError, PgIntegrityError)
AVATAR_DIR = os.path.join(BASE, 'profile_pictures')
ASSET_ID = 1  # The sole asset in this educational case study
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
app.config.update(SECRET_KEY=os.environ.get('FLASK_SECRET_KEY') or _secret(), SESSION_COOKIE_HTTPONLY=True,
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
        if DATABASE_URL:
            g.db = PostgresConnection(DATABASE_URL)
        else:
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
            return redirect(url_for('profile'))
    return redirect(url_for('profile'))



# ---------- personal profile pictures ----------
@app.route('/profile', methods=['GET', 'POST'])
@need()
def profile():
    if request.method == 'POST':
        upload = request.files.get('avatar')
        if not upload or not upload.filename:
            flash('Select a picture / اختر صورة', 'err')
            return redirect(url_for('profile'))
        raw = upload.stream.read(3 * 1024 * 1024 + 1)
        if len(raw) > 3 * 1024 * 1024:
            flash('Max image size is 3 MB / الحد 3 ميغابايت', 'err')
            return redirect(url_for('profile'))
        try:
            with Image.open(BytesIO(raw)) as verify_image:
                verify_image.verify()
            with Image.open(BytesIO(raw)) as original:
                if original.format not in ('JPEG', 'PNG', 'WEBP') or original.width * original.height > 16000000:
                    raise ValueError('Invalid image')
                picture = ImageOps.exif_transpose(original)
                picture.thumbnail((400, 400))
                if picture.mode == 'RGBA':
                    canvas = Image.new('RGB', picture.size, '#ffffff')
                    canvas.paste(picture, mask=picture.getchannel('A'))
                    picture = canvas
                else:
                    picture = picture.convert('RGB')
                filename = secrets.token_hex(20) + '.jpg'
                buffer = BytesIO()
                picture.save(buffer, 'JPEG', quality=85)
                image_bytes = buffer.getvalue()
                dest = None
                if not DATABASE_URL:
                    os.makedirs(AVATAR_DIR, exist_ok=True)
                    dest = os.path.join(AVATAR_DIR, filename)
                    with open(dest, 'wb') as output:
                        output.write(image_bytes)
        except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
            flash('Invalid image / الصورة غير صالحة', 'err')
            return redirect(url_for('profile'))
        db = get_db()
        old = g.user['avatar_filename']
        try:
            if DATABASE_URL:
                db.execute('UPDATE users SET avatar_filename=?, avatar_data=? WHERE id=?',
                           (filename, image_bytes, g.user['id']))
            else:
                db.execute('UPDATE users SET avatar_filename=? WHERE id=?', (filename, g.user['id']))
            audit('avatar_update', 'user', g.user['id'])
            db.commit()
        except Exception:
            if dest and os.path.exists(dest):
                os.remove(dest)
            raise
        if old and not DATABASE_URL:
            old_path = os.path.join(AVATAR_DIR, old)
            if os.path.isfile(old_path):
                os.remove(old_path)
        flash(t('saved'))
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/profile/avatar/<int:uid>')
@need()
def profile_avatar(uid):
    if DATABASE_URL:
        row = get_db().execute('SELECT avatar_filename, avatar_data FROM users WHERE id=?', (uid,)).fetchone()
        if not row or not row['avatar_data']:
            abort(404)
        return Response(bytes(row['avatar_data']), mimetype='image/jpeg',
                        headers={'Cache-Control': 'private, no-store'})
    row = get_db().execute('SELECT avatar_filename FROM users WHERE id=?', (uid,)).fetchone()
    if not row or not row['avatar_filename']:
        abort(404)
    return send_from_directory(AVATAR_DIR, row['avatar_filename'], mimetype='image/jpeg')

@app.route('/profile/remove', methods=['POST'])
@need()
def profile_remove():
    old = g.user['avatar_filename']
    db = get_db()
    if DATABASE_URL:
        db.execute('UPDATE users SET avatar_filename=NULL, avatar_data=NULL WHERE id=?', (g.user['id'],))
    else:
        db.execute('UPDATE users SET avatar_filename=NULL WHERE id=?', (g.user['id'],))
    audit('avatar_remove', 'user', g.user['id'])
    db.commit()
    if old and not DATABASE_URL:
        old_path = os.path.join(AVATAR_DIR, old)
        if os.path.isfile(old_path):
            os.remove(old_path)
    flash(t('saved'))
    return redirect(url_for('profile'))

@app.route('/profile/username', methods=['POST'])
@need()
def profile_username():
    username = request.form.get('username', '').strip()
    current_password = request.form.get('current_password', '')
    if not (3 <= len(username) <= 32) or not all(c.isascii() and (c.isalnum() or c in '._-') for c in username):
        flash('Username must be 3-32 characters (letters, numbers, dot, dash, underscore) / اسم المستخدم غير صالح', 'err')
    elif not check_password_hash(g.user['password_hash'], current_password):
        flash('Incorrect password / كلمة المرور غير صحيحة', 'err')
    else:
        db = get_db()
        try:
            db.execute('UPDATE users SET username=? WHERE id=?', (username, g.user['id']))
            audit('username_change', 'user', g.user['id'])
            db.commit()
            flash(t('saved'))
        except DBIntegrityError:
            db.rollback()
            flash('Username already exists / اسم المستخدم مستخدم مسبقاً', 'err')
    return redirect(url_for('profile'))

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
            d = dict(title=f['title'].strip(), asset_id=ASSET_ID, threat_id=int(f['threat_id']),
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
        except (KeyError, ValueError, AssertionError, DBIntegrityError):
            db.rollback()
            flash(t('invalid'), 'err')
            row = dict(f)
    return render_template(
        'risk_form.html', r=row,
        assets=[(a['id'], bi(a['name'])) for a in db.execute('SELECT * FROM assets WHERE id=?', (ASSET_ID,))],
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
@need('admin')
def asset_new():
    abort(403)  # Case study is restricted to exactly one asset


@app.route('/assets/<int:aid>/edit', methods=['GET', 'POST'])
@need('analyst')
def asset_edit(aid):
    if aid != ASSET_ID: abort(404)
    return asset_form(aid)


@app.route('/assets/<int:aid>/delete', methods=['POST'])
@need('analyst')
def asset_delete(aid):
    abort(403)  # The single asset must remain in the case study
    db = get_db()
    try:
        db.execute('DELETE FROM assets WHERE id=?', (aid,))
        audit('delete', 'asset', aid)
        db.commit()
        flash(t('deleted'))
    except DBIntegrityError:
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
            except DBIntegrityError:
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
        except DBIntegrityError:
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
    threats = [
        'SQL injection attack | هجوم حقن SQL',
        'Unauthorized access | وصول غير مصرح به',
        'Data exfiltration | تسريب البيانات',
        'Ransomware | برمجيات الفدية',
        'Data loss | فقدان البيانات',
        'Credential attack | هجوم على بيانات الدخول']
    vulns = [
        'Unsafe SQL query construction | استعلامات SQL غير آمنة',
        'Excessive privileges | صلاحيات زائدة',
        'Unencrypted database exports | تصدير البيانات دون تشفير',
        'Unpatched server | خادم غير محدث',
        'Untested backups | نسخ احتياطية غير مختبرة',
        'Weak password policy | سياسة كلمات مرور ضعيفة']
    db.executemany('INSERT INTO threats(name) VALUES(?)', [(x,) for x in threats])
    db.executemany('INSERT INTO vulnerabilities(name) VALUES(?)', [(x,) for x in vulns])
    db.execute('INSERT INTO assets(name,type,owner,criticality) VALUES(?,?,?,?)',
               ('Student Records Database Server | خادم قاعدة بيانات سجلات الطلبة', 'server', 'University IT Department', 5))
    risks = [
      ('SQL injection in student records | حقن SQL في سجلات الطلبة',1,1,4,5,'mitigate','Use parameterized queries and input validation | استخدام استعلامات آمنة والتحقق من المدخلات','open',2,4),
      ('Unauthorized grade modification | تعديل الدرجات دون صلاحية',2,2,4,5,'mitigate','Enforce least privilege and audit changes | تقييد الصلاحيات وتدقيق التعديلات','in_progress',2,4),
      ('Student data leak | تسريب بيانات الطلبة',3,3,3,5,'mitigate','Encrypt exports and restrict access | تشفير النسخ وتقييد الوصول','open',2,3),
      ('Ransomware on database server | فدية على خادم قاعدة البيانات',4,4,3,5,'mitigate','Patch server and isolate backups | تحديث الخادم وعزل النسخ الاحتياطية','open',2,4),
      ('Backup restore failure | فشل استرجاع النسخ الاحتياطية',5,5,3,4,'mitigate','Schedule backup restore tests | اختبار استعادة النسخ الاحتياطية دورياً','in_progress',1,4),
      ('Compromised admin password | اختراق كلمة مرور المسؤول',6,6,4,4,'mitigate','Enable MFA and strong passwords | تفعيل التحقق المتعدد وكلمات مرور قوية','open',2,3)]
    for ti, th, v, l, i, tr, ac, st, rl, ri in risks:
        db.execute('''INSERT INTO risks(title,asset_id,threat_id,vulnerability_id,likelihood,impact,treatment,action,
                      owner_id,due_date,status,res_likelihood,res_impact,created_by) VALUES(?,1,?,?,?,?,?,?,2,'2027-01-31',?,?,?,1)''',
                   (ti, th, v, l, i, tr, ac, st, rl, ri))


def init_db():
    if DATABASE_URL:
        db = PostgresConnection(DATABASE_URL)
        try:
            with open(os.path.join(BASE, 'schema_postgres.sql'), encoding='utf-8') as f:
                db.executescript(f.read())
            if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
                seed(db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return
    db = sqlite3.connect(DB)
    db.execute('PRAGMA foreign_keys=ON')
    with open(os.path.join(BASE, 'schema.sql'), encoding='utf-8') as f:
        db.executescript(f.read())
    if 'avatar_filename' not in {r[1] for r in db.execute('PRAGMA table_info(users)')}:
        db.execute('ALTER TABLE users ADD COLUMN avatar_filename TEXT')
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        seed(db)
    db.commit()
    db.close()


init_db()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
