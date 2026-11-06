import os, tempfile, sqlite3, re
os.environ['RISK_DB'] = os.path.join(tempfile.mkdtemp(), 'test.db')
import app as A
c = A.app.test_client()
def csrf(path):
    r=c.get(path)
    return re.search(r'name="csrf" value="([^"]+)"',r.get_data(as_text=True)).group(1)
def login(user,password):
    c.get('/logout')
    return c.post('/login',data={'username':user,'password':password,'csrf':csrf('/login')})
with sqlite3.connect(A.DB) as db:
    assert db.execute('select count(*) from assets').fetchone()[0] == 1
    assert db.execute('select count(*) from risks').fetchone()[0] == 6
    assert db.execute('select count(distinct asset_id) from risks').fetchone()[0] == 1
assert login('analyst','Analyst@12345').status_code in (302,303)
assert c.get('/risks').status_code == 200
assert c.get('/assets/new').status_code == 403
assert c.post('/assets/1/delete',data={'csrf':csrf('/assets')}).status_code == 403
assert c.post('/risks/new',data=dict(csrf=csrf('/risks/new'),title='Demo risk',asset_id='999',threat_id='1',vulnerability_id='1',likelihood='5',impact='5',res_likelihood='2',res_impact='2',treatment='mitigate',action='Apply patch',status='open')).status_code in (302,303)
with sqlite3.connect(A.DB) as db:
    assert db.execute("select asset_id,likelihood*impact from risks where title='Demo risk'").fetchone() == (1,25)
assert c.get('/report').status_code == 200
print('ALL ONE-ASSET TESTS PASSED')
