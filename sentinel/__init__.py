import hashlib
import hmac
import json
import os
import secrets
import threading
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for, Response
from werkzeug.security import check_password_hash, generate_password_hash

from .detection import detect
from .parsers import FORMATS, parse_batch
from . import ai


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(g.app_db, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


def audit(action):
    db().execute('INSERT INTO audit(actor,ts,action) VALUES(?,?,?)',
                 (g.user['username'] if g.user else 'anonymous', now(), action))


def ingest(text, fmt='jsonl', year=None, offset=None, collector_id=None):
    parsed, skipped = parse_batch(text, fmt, year, offset)
    conn = db()
    with conn:
        conn.execute('BEGIN IMMEDIATE')
        existing = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        new_ids = {e['id'] for e in parsed} - {r[0] for r in conn.execute('SELECT id FROM events')}
        if existing + len(new_ids) > 10000:
            raise ValueError('Local milestone capacity is 10,000 events. Start a new lab database.')
        for e in parsed:
            conn.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)',
                         (e['id'], e['timestamp'], e['kind'], e['src_ip'], json.dumps(e)))
        if collector_id is not None:
            for e in parsed:
                conn.execute('INSERT OR IGNORE INTO event_sources VALUES(?,?)', (e['id'],collector_id))
        alerts = detect([json.loads(r['body']) for r in conn.execute('SELECT body FROM events')])
        added = 0
        for a in alerts:
            added += conn.execute('INSERT OR IGNORE INTO alerts(id,rule,src,ts,score,reason,evidence) VALUES(?,?,?,?,?,?,?)',
                                  (a['id'], a['rule'], a['src'], a['ts'], a['score'], a['reason'], json.dumps(a['evidence']))).rowcount
        audit(f'Imported {len(new_ids)} new events; created {added} alerts; skipped {skipped} non-target records; collector={collector_id}')
    return len(new_ids), added, skipped


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(DATABASE=os.environ.get('CYBER_DB', str(Path(app.instance_path) / 'sentinel.db')),
                            AI_ENABLED=os.environ.get('CYBER_AI') == '1', AI_MODEL=os.environ.get('CYBER_AI_MODEL', 'qwen2.5:1.5b'),
                            SECRET_KEY=os.environ.get('CYBER_SECRET'), MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                            MAX_FORM_MEMORY_SIZE=65536, MAX_FORM_PARTS=10,
                            SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                            SESSION_COOKIE_SECURE=os.environ.get('CYBER_HTTPS') == '1',
                            PERMANENT_SESSION_LIFETIME=timedelta(hours=1))
    if config:
        app.config.update(config)
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    if not app.config['SECRET_KEY']:
        secret_path = Path(app.config['DATABASE']).parent / '.secret'
        try:
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        app.config['SECRET_KEY'] = secret_path.read_text().strip()
    if len(app.config['SECRET_KEY']) < 32:
        raise RuntimeError('CYBER_SECRET must have at least 32 characters')
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.executescript(Path(__file__).with_name('schema.sql').read_text())
    ai_lock = threading.Lock()
    dummy = generate_password_hash(secrets.token_hex(24))

    @app.before_request
    def guard():
        g.app_db = app.config['DATABASE']
        g.user = db().execute('SELECT * FROM users WHERE id=?', (session.get('uid', -1),)).fetchone()
        if request.endpoint == 'collect':
            auth = request.headers.get('Authorization', '')
            token = auth[7:] if auth.startswith('Bearer ') else ''
            if not 32 <= len(token) <= 200:
                abort(401, 'A collector bearer token is required')
            g.collector = db().execute('SELECT * FROM collectors WHERE token_hash=? AND revoked=0',
                                      (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not g.collector:
                abort(401, 'Invalid or revoked collector token')
            g.user = db().execute('SELECT * FROM users WHERE id=?', (g.collector['owner_id'],)).fetchone()
            if not g.user or g.user['role'] != 'analyst':
                abort(403)
            with db():
                db().execute('BEGIN IMMEDIATE')
                c = db().execute('SELECT * FROM collectors WHERE id=?', (g.collector['id'],)).fetchone()
                stamp = time.time()
                count = c['requests'] if stamp-c['window_start'] < 60 else 0
                if count >= 60:
                    abort(429, 'Collector rate limit: 60 requests per minute')
                db().execute('UPDATE collectors SET window_start=?,requests=? WHERE id=?',
                             (c['window_start'] if count else stamp, count+1, c['id']))
            return None
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(24)
        if request.method == 'POST':
            if not hmac.compare_digest(session['csrf'], request.form.get('csrf', '')):
                abort(400, 'Invalid CSRF token. Reload the page and try again.')
        if request.endpoint not in ('login', 'static') and not g.user:
            return redirect(url_for('login'))
        if request.method == 'POST' and request.endpoint not in ('login', 'logout') and g.user['role'] != 'analyst':
            abort(403)

    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.teardown_appcontext
    def close(_):
        conn = g.pop('db', None)
        if conn:
            conn.close()

    @app.cli.command('create-user')
    @click.argument('username')
    @click.option('--role', type=click.Choice(['analyst', 'viewer']), default='analyst')
    @click.password_option()
    def create_user(username, role, password):
        if not 1 <= len(username) <= 80 or len(password) < 12:
            raise click.ClickException('Username: 1–80 characters; password: at least 12 characters')
        g.app_db = app.config['DATABASE']
        try:
            with db():
                db().execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',
                             (username, generate_password_hash(password), role))
        except sqlite3.IntegrityError:
            raise click.ClickException('Username already exists')
        click.echo(f'Created {role}: {username}')

    @app.cli.command('create-collector')
    @click.argument('username')
    @click.argument('name')
    @click.option('--out', required=True, type=click.Path(path_type=Path))
    def create_collector(username, name, out):
        """Create an ingest-only token file for an analyst-owned collector."""
        g.app_db = app.config['DATABASE']
        owner = db().execute('SELECT * FROM users WHERE username=? AND role="analyst"', (username,)).fetchone()
        if not owner or not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', name):
            raise click.ClickException('Use an existing analyst and a 1–60 character name: letters, digits, _ or -')
        token = secrets.token_urlsafe(32)
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise click.ClickException('Token file already exists. Choose a new path.')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(token)
            with db():
                db().execute('INSERT INTO collectors(name,owner_id,token_hash,created) VALUES(?,?,?,?)',
                             (name,owner['id'],hashlib.sha256(token.encode()).hexdigest(),now()))
        except Exception:
            out.unlink(missing_ok=True)
            raise click.ClickException('Could not create collector. Name may already exist.')
        click.echo(f'Created collector {name}. Token saved to {out}; do not share or commit this file.')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            ip = request.remote_addr or 'unknown'
            conn = db()
            # Atomic reservation limits parallel attempts; do not trust forwarded headers.
            with conn:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute('DELETE FROM attempts WHERE started<?', (time.time() - 300,))
                row = conn.execute('SELECT count FROM attempts WHERE ip=?', (ip,)).fetchone()
                if row and row['count'] >= 10:
                    abort(429, 'Too many login attempts. Try again in five minutes.')
                conn.execute('INSERT INTO attempts VALUES(?,?,1) ON CONFLICT(ip) DO UPDATE SET count=count+1', (ip, time.time()))
            user = conn.execute('SELECT * FROM users WHERE username=?', (request.form.get('username', '')[:80],)).fetchone()
            password = request.form.get('password', '')
            valid = check_password_hash(user['password'] if user else dummy, password[:1024])
            if user and valid and len(password) <= 1024:
                session.clear()
                session.update(uid=user['id'], csrf=secrets.token_hex(24))
                session.permanent = True
                g.user = user
                with conn:
                    audit('Login succeeded')
                return redirect(url_for('dashboard'))
            with conn:
                audit('Login failed')
            flash('Invalid username or password')
        return render_template('login.html')

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    def dashboard():
        status = request.args.get('status', '')
        rule = request.args.get('rule', '')
        src = request.args.get('src', '')[:45]
        alerts = db().execute('SELECT * FROM alerts WHERE (?="" OR status=?) AND (?="" OR rule=?) AND (?="" OR src=?) ORDER BY ts DESC',
                              (status, status, rule, rule, src, src)).fetchall()
        stats = dict(events=db().execute('SELECT COUNT(*) FROM events').fetchone()[0],
                     alerts=db().execute('SELECT COUNT(*) FROM alerts').fetchone()[0],
                     active=db().execute('SELECT COUNT(*) FROM alerts WHERE status != "closed"').fetchone()[0],
                     high=db().execute('SELECT COUNT(*) FROM alerts WHERE score>=70').fetchone()[0])
        trend = db().execute('SELECT substr(ts,1,13) AS hour, COUNT(*) AS n FROM events GROUP BY hour ORDER BY hour DESC LIMIT 12').fetchall()[::-1]
        return render_template('dashboard.html', alerts=alerts, stats=stats, trend=trend,
                               status=status, rule=rule, src=src, formats=FORMATS,
                               live=request.args.get('live') == '1')

    @app.post('/import')
    def import_logs():
        f = request.files.get('logs')
        if not f:
            abort(400, 'Choose a log file')
        try:
            count, alerts, skipped = ingest(f.read().decode('utf-8'), request.form.get('format','jsonl'),
                                             request.form.get('year'), request.form.get('offset'))
        except (ValueError, UnicodeError) as exc:
            abort(400, str(exc))
        flash(f'Imported {count} new events · {alerts} new alerts · {skipped} non-target records skipped')
        return redirect(url_for('dashboard'))

    @app.post('/demo')
    def demo():
        count, alerts, _ = ingest((Path(app.root_path).parent / 'samples' / 'demo.jsonl').read_text())
        flash(f'Synthetic demo loaded: {count} new events · {alerts} new alerts')
        return redirect(url_for('dashboard'))

    def get_alert(alert_id):
        row = db().execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if row is None:
            abort(404)
        evidence = [json.loads(db().execute('SELECT body FROM events WHERE id=?', (eid,)).fetchone()[0]) for eid in json.loads(row['evidence'])]
        notes = [dict(x) for x in db().execute('SELECT * FROM notes WHERE alert_id=? ORDER BY id', (alert_id,))]
        return dict(row), evidence, notes

    @app.route('/alerts/<alert_id>', methods=['GET', 'POST'])
    def detail(alert_id):
        a, evidence, notes = get_alert(alert_id)
        if request.method == 'POST':
            status = request.form.get('status')
            note = request.form.get('note', '').strip()
            if status not in ('open', 'investigating', 'closed') or not 1 <= len(note) <= 2000:
                abort(400, 'Choose a valid status and provide a note of 1–2000 characters')
            with db():
                db().execute('UPDATE alerts SET status=? WHERE id=?', (status, alert_id))
                db().execute('INSERT INTO notes(alert_id,actor,ts,body) VALUES(?,?,?,?)',
                             (alert_id, g.user['username'], now(), f'[{status}] {note}'))
                audit(f'Updated incident {alert_id} to {status}')
            return redirect(url_for('detail', alert_id=alert_id))
        summaries = [dict(r) for r in db().execute('SELECT * FROM ai_summaries WHERE alert_id=? ORDER BY id DESC LIMIT 5', (alert_id,))]
        for r in summaries:
            r['content'] = json.loads(r['content'])
        return render_template('detail.html', a=a, evidence=evidence, notes=notes, summaries=summaries, ai_enabled=app.config['AI_ENABLED'])

    @app.get('/alerts/<alert_id>/report')
    def report(alert_id):
        a, evidence, notes = get_alert(alert_id)
        payload = dict(generated_at=now(), alert=a, observed_evidence=evidence, analyst_notes=notes,
                       interpretation='Rule-based suspicion, not confirmed compromise. AI assistance, if present, is unverified and separate from observed evidence.',
                       ai_assistance=[{**dict(r), 'content': json.loads(r['content']), 'facts':json.loads(r['facts'])} for r in db().execute('SELECT * FROM ai_summaries WHERE alert_id=? ORDER BY id DESC LIMIT 5',(alert_id,))],
                       suggested_next_steps=['Confirm source ownership and expected activity.', 'Correlate with endpoint and identity logs.', 'Document disposition and evidence.'])
        return Response(json.dumps(payload, indent=2), mimetype='application/json',
                        headers={'Content-Disposition': f'attachment; filename=incident-{alert_id}.json'})

    @app.get('/collectors')
    def collectors():
        rows = [dict(r) for r in db().execute('SELECT id,name,revoked,last_seen,received,last_error FROM collectors ORDER BY id DESC')]
        for r in rows:
            r['online'] = bool(r['last_seen'] and (datetime.now(timezone.utc)-datetime.fromisoformat(r['last_seen'])).total_seconds()<20)
        return render_template('collectors.html', rows=rows)

    @app.post('/collectors/<int:collector_id>/revoke')
    def revoke_collector(collector_id):
        with db():
            if not db().execute('UPDATE collectors SET revoked=1 WHERE id=?', (collector_id,)).rowcount:
                abort(404)
            audit(f'Revoked collector {collector_id}')
        flash('Collector token revoked. It can no longer ingest logs.')
        return redirect(url_for('collectors'))

    @app.post('/api/collect')
    def collect():
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict) or set(payload)-{'logs','format','year','offset'}:
            abort(400,'Expected JSON with logs, format, and optional year/offset')
        text=payload.get('logs')
        if not isinstance(text,str) or not isinstance(payload.get('format','jsonl'),str) or payload.get('format','jsonl') not in FORMATS:
            abort(400,'Invalid logs or format')
        try:
            result = ingest(text,payload.get('format','jsonl'),payload.get('year'),payload.get('offset'),g.collector['id']) if text.strip() else (0,0,0)
        except (ValueError, UnicodeError) as exc:
            with db():
                db().execute('UPDATE collectors SET last_seen=?,last_error=? WHERE id=?', (now(),str(exc)[:300],g.collector['id']))
            abort(400,str(exc))
        with db():
            db().execute('UPDATE collectors SET last_seen=?,last_error=NULL,received=received+? WHERE id=?', (now(),result[0],g.collector['id']))
        return {'accepted':True,'new_events':result[0],'new_alerts':result[1],'skipped':result[2]}

    @app.post('/alerts/<alert_id>/summarise')
    def summarise(alert_id):
        a, evidence, _ = get_alert(alert_id)
        if not app.config['AI_ENABLED']:
            abort(400, 'AI is disabled. See docs/UPGRADE.md to enable local Ollama.')
        if not ai_lock.acquire(blocking=False):
            abort(429, 'A summary is already generating. Please wait.')
        try:
            output, facts = ai.generate_summary(a,evidence,app.config['AI_MODEL'])
            with db():
                db().execute('INSERT INTO ai_summaries(alert_id,actor,ts,model,content,facts) VALUES(?,?,?,?,?,?)',
                             (alert_id,g.user['username'],now(),app.config['AI_MODEL'],json.dumps(output),json.dumps(facts)))
                audit(f'Generated unverified local AI assistance for {alert_id}')
            flash('AI draft generated. Check every claim against the evidence before relying on it.')
        except ai.AIError as exc:
            flash(str(exc))
        finally:
            ai_lock.release()
        return redirect(url_for('detail',alert_id=alert_id))

    @app.get('/events')
    def events():
        page = min(201, max(1, request.args.get('page', 1, type=int)))
        rows = db().execute('SELECT body FROM events ORDER BY ts DESC,id LIMIT 50 OFFSET ?', ((page-1)*50,)).fetchall()
        return render_template('events.html', events=[json.loads(r[0]) for r in rows], page=page)

    @app.get('/audit')
    def audit_log():
        return render_template('audit.html', rows=db().execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200').fetchall())

    @app.errorhandler(401)
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def error(exc):
        if request.path.startswith('/api/'):
            return {'accepted':False,'error':exc.description}, exc.code
        return render_template('error.html', error=exc), exc.code

    return app
