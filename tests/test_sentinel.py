import io
import json
import sqlite3
from pathlib import Path
import pytest
from werkzeug.security import generate_password_hash
from sentinel import create_app
from sentinel.detection import detect, normalize

SAMPLES = Path(__file__).resolve().parents[1] / 'samples'

def load(name):
    return [normalize(json.loads(x)) for x in (SAMPLES / f'{name}.jsonl').read_text().splitlines()]

@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path/'test.db'), 'SECRET_KEY': 't'*40})
    with sqlite3.connect(app.config['DATABASE']) as con:
        for name, role in [('alice','analyst'),('bob','viewer')]:
            con.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash('test-password-123'),role))
    return app

def token(c):
    c.get('/login')
    with c.session_transaction() as s:
        return s['csrf']

def login(c, name='alice'):
    return c.post('/login',data={'csrf':token(c),'username':name,'password':'test-password-123'})

def post(c,url,**data):
    with c.session_transaction() as s:
        csrf=s['csrf']
    return c.post(url,data={'csrf':csrf,**data})

def test_benign():
    assert detect(load('benign')) == []

def test_demo_rules_and_evidence():
    events=load('demo')
    found=detect(events)
    assert {a['rule']:a['score'] for a in found} == {'AUTH-001':70,'AUTH-002':90,'NET-001':65,'WEB-001':50}
    assert all(set(a['evidence']) <= {e['id'] for e in events} for a in found)
    assert detect(list(reversed(events))) == found

@pytest.mark.parametrize('seconds,expected',[(300,True),(301,False)])
def test_auth_window_boundary(seconds,expected):
    rows=[{'timestamp':f'2026-10-15T08:00:0{i}+00:00','kind':'auth','src_ip':'192.0.2.1','user':'a','outcome':'failure'} for i in range(4)]
    rows.append({**rows[0],'timestamp':f'2026-10-15T08:05:0{seconds-300}+00:00'})
    assert bool(detect([normalize(x) for x in rows])) is expected

def test_ports_must_be_distinct():
    e=[{**x,'dst_port':443} for x in load('suspicious') if x['kind']=='network']
    assert detect(e)==[]

def test_auth_accounts_not_combined():
    e=[{**x,'user':f'user{i}'} for i,x in enumerate(load('suspicious')) if x['kind']=='auth']
    assert detect(e)==[]

@pytest.mark.parametrize('change',[{'timestamp':'2026-10-15T08:00:00'},{'src_ip':'bad-ip'},{'kind':'unknown'},{'outcome':'maybe'},{'user':''}])
def test_validation(change):
    raw=json.loads((SAMPLES/'benign.jsonl').read_text().splitlines()[0])
    with pytest.raises(ValueError): normalize({**raw,**change})

def test_auth_csrf_and_headers(app):
    c=app.test_client()
    assert c.get('/').status_code==302
    assert c.post('/login',data={}).status_code==400
    assert login(c).status_code==302
    res=c.get('/')
    assert res.status_code==200
    assert "frame-ancestors 'none'" in res.headers['Content-Security-Policy']
    assert res.headers['Cache-Control']=='no-store'
    assert post(c,'/logout').status_code==302
    assert c.get('/events').status_code==302

def test_login_rate_limit(app):
    c=app.test_client()
    csrf=token(c)
    for _ in range(10):
        assert c.post('/login',data={'csrf':csrf,'username':'alice','password':'bad'}).status_code==200
    assert c.post('/login',data={'csrf':csrf,'username':'alice','password':'bad'}).status_code==429

def test_viewer_cannot_mutate(app):
    c=app.test_client(); login(c,'bob')
    assert c.get('/').status_code==200
    assert post(c,'/demo').status_code==403
    assert post(c,'/import').status_code==403
    assert post(c,'/alerts/anything',status='closed',note='test').status_code==403

def test_import_atomic_and_idempotent(app):
    c=app.test_client(); login(c)
    invalid=(SAMPLES/'benign.jsonl').read_bytes()+b'not json\n'
    assert post(c,'/import',logs=(io.BytesIO(invalid),'bad.jsonl')).status_code==400
    with sqlite3.connect(app.config['DATABASE']) as con:
        assert con.execute('SELECT COUNT(*) FROM events').fetchone()[0]==0
    assert post(c,'/demo').status_code==302
    assert post(c,'/demo').status_code==302
    with sqlite3.connect(app.config['DATABASE']) as con:
        assert con.execute('SELECT COUNT(*) FROM events').fetchone()[0]==75
        assert con.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]==4

def test_incident_report_and_escape(app):
    c=app.test_client(); login(c); post(c,'/demo')
    with sqlite3.connect(app.config['DATABASE']) as con:
        aid=con.execute('SELECT id FROM alerts LIMIT 1').fetchone()[0]
    assert post(c,f'/alerts/{aid}',status='investigating',note='<script>alert(1)</script>').status_code==302
    page=c.get(f'/alerts/{aid}')
    assert b'<script>alert(1)</script>' not in page.data
    assert b'&lt;script&gt;' in page.data
    report=c.get(f'/alerts/{aid}/report')
    assert report.json['alert']['status']=='investigating'
    assert report.json['observed_evidence']
    assert report.json['analyst_notes'][0]['actor']=='alice'
    assert 'attachment' in report.headers['Content-Disposition']
    assert c.get('/events').status_code==200
    assert c.get('/audit').status_code==200
    assert c.get('/alerts/missing').status_code==404

def test_filter_and_bad_status(app):
    c=app.test_client(); login(c); post(c,'/demo')
    page=c.get('/?rule=AUTH-002')
    assert b'1 matching alerts' in page.data
    with sqlite3.connect(app.config['DATABASE']) as con:
        aid=con.execute('SELECT id FROM alerts LIMIT 1').fetchone()[0]
    assert post(c,f'/alerts/{aid}',status='invalid',note='x').status_code==400

def test_oversized_upload(app):
    c=app.test_client();login(c)
    assert post(c,'/import',logs=(io.BytesIO(b'x'*(2*1024*1024)),'large.jsonl')).status_code==413

def test_cli_password_policy(app):
    r=app.test_cli_runner()
    assert r.invoke(args=['create-user','short','--password','short']).exit_code!=0
    assert r.invoke(args=['create-user','new','--role','viewer','--password','long-password-123']).exit_code==0
