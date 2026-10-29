"""Run: python test_app.py   (uses a temporary database)"""
import os, re, tempfile
os.environ['RISK_DB'] = os.path.join(tempfile.mkdtemp(), 'test.db')
import app as A

c = A.app.test_client()


def tok(path='/login'):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(True)).group(1)


def login(u, p):
    c.get('/logout')
    return c.post('/login', data={'username': u, 'password': p, 'csrf': tok()}, follow_redirects=True)


def check(name, cond):
    print(('PASS ' if cond else 'FAIL ') + name)
    assert cond, name


check('redirect when anonymous', c.get('/').status_code == 302)
check('csrf required', c.post('/login', data={'username': 'admin', 'password': 'x'}).status_code == 400)
check('bad login rejected', 'Invalid' in login('admin', 'wrong').get_data(True) or 'غير صحيحة' in login('admin', 'wrong').get_data(True))
A.FAILS.clear()
r = login('analyst', 'Analyst@12345')
check('analyst login + dashboard', r.status_code == 200 and 'matrix' in r.get_data(True) or 'مصفوفة' in r.get_data(True))
check('analyst cannot open users (403)', c.get('/users').status_code == 403)
t = tok('/risks/new')
r = c.post('/risks/new', data=dict(csrf=t, title='Test risk', asset_id=1, threat_id=1, vulnerability_id=1, likelihood=5, impact=5,
           treatment='mitigate', action='x', owner_id='', due_date='2026-12-01', status='open', res_likelihood=2, res_impact=2), follow_redirects=True)
check('create risk', 'Test risk' in r.get_data(True) and '25' in r.get_data(True))
check('invalid risk rejected', 'غير صالحة' in c.post('/risks/new', data=dict(csrf=t, title='', asset_id=1, threat_id=1, vulnerability_id=1, likelihood=9, impact=1, treatment='mitigate', status='open', res_likelihood=1, res_impact=1), follow_redirects=True).get_data(True))
c.get('/lang/en')
check('english UI', 'Risk Register' in c.get('/risks').get_data(True))
check('filter critical', 'Test risk' in c.get('/risks?level=3').get_data(True))
csvd = c.get('/risks/export.csv').get_data(True)
check('csv export', 'Test risk' in csvd and 'Critical' in csvd)
r = c.post('/assets/1/delete', data={'csrf': tok('/assets')}, follow_redirects=True)
check('linked asset not deletable', 'linked' in r.get_data(True))
check('report page', c.get('/report').status_code == 200)
login('viewer', 'Viewer@12345')
check('viewer cannot create', c.get('/risks/new').status_code == 403)
login('admin', 'Admin@12345')
check('admin audit log', 'create' in c.get('/audit').get_data(True))
check('admin users page', c.get('/users').status_code == 200)
print('ALL TESTS PASSED')
