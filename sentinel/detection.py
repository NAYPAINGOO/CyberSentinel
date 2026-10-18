"""Deterministic event-time rules. No network scanning or external calls."""
import hashlib
import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timezone


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError('Each line must be a JSON object')
    fields = {'timestamp', 'kind', 'src_ip', 'user', 'outcome', 'dst_ip', 'dst_port', 'path', 'status'}
    if set(raw) - fields:
        raise ValueError('Unknown field(s) in event')
    e = dict(raw)
    try:
        dt = datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('Timestamp must include a timezone')
        e['timestamp'] = dt.astimezone(timezone.utc).isoformat()
        e['src_ip'] = str(ipaddress.ip_address(e['src_ip']))
        if e['kind'] not in ('auth', 'web', 'network'):
            raise ValueError('kind must be auth, web, or network')
        if e['kind'] == 'auth':
            if e['outcome'] not in ('success', 'failure') or not isinstance(e['user'], str) or not 1 <= len(e['user']) <= 80:
                raise ValueError('Invalid authentication event')
        elif e['kind'] == 'network':
            e['dst_ip'] = str(ipaddress.ip_address(e['dst_ip']))
            if type(e['dst_port']) is not int or not 1 <= e['dst_port'] <= 65535:
                raise ValueError('Invalid destination port')
        else:
            if type(e['status']) is not int or not 100 <= e['status'] <= 599 or not isinstance(e['path'], str) or not 1 <= len(e['path']) <= 2048:
                raise ValueError('Invalid web event')
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('Missing or invalid event fields') from exc
    encoded = json.dumps(e, sort_keys=True, separators=(',', ':'))
    e['id'] = hashlib.sha256(encoded.encode()).hexdigest()
    return e


def detect(events):
    windows = defaultdict(deque)
    alerts = []
    emitted = set()

    def emit(rule, e, score, reason, evidence, scope):
        # One alert per rule/scope/UTC date; first threshold crossing is immutable.
        key = f'{rule}|{scope}|{e["timestamp"][:10]}'
        if key in emitted:
            return
        emitted.add(key)
        alerts.append(dict(id=hashlib.sha256(key.encode()).hexdigest()[:24], rule=rule,
                           src=e['src_ip'], ts=e['timestamp'], score=score, reason=reason,
                           evidence=[x['id'] for x in evidence]))

    for e in sorted(events, key=lambda x: (x['timestamp'], x['id'])):
        t = datetime.fromisoformat(e['timestamp']).timestamp()
        src = e['src_ip']
        if e['kind'] == 'auth':
            scope = (src, e['user'])
            q = windows[('auth', scope)]
            while q and t - datetime.fromisoformat(q[0]['timestamp']).timestamp() > 300:
                q.popleft()
            if e['outcome'] == 'failure':
                q.append(e)
                if len(q) >= 5:
                    emit('AUTH-001', e, 70, 'At least 5 failed logins for the same source and account within 300 seconds.', list(q), scope)
            elif len(q) >= 5:
                emit('AUTH-002', e, 90, 'Successful login following at least 5 failures from the same source/account within 300 seconds. Investigate; compromise is not proven.', [*q, e], scope)
        elif e['kind'] == 'network':
            scope = (src, e['dst_ip'])
            q = windows[('network', scope)]
            while q and t - datetime.fromisoformat(q[0]['timestamp']).timestamp() > 60:
                q.popleft()
            q.append(e)
            if len({x['dst_port'] for x in q}) >= 10:
                emit('NET-001', e, 65, 'At least 10 distinct destination ports on one host from one source within 60 seconds.', list(q), scope)
        elif e['kind'] == 'web':
            q = windows[('web', src)]
            while q and t - datetime.fromisoformat(q[0]['timestamp']).timestamp() > 60:
                q.popleft()
            if e['status'] == 404:
                q.append(e)
                if len({x['path'] for x in q}) >= 8:
                    emit('WEB-001', e, 50, 'At least 8 distinct HTTP 404 paths from one source within 60 seconds; possible enumeration.', list(q), src)
    return alerts
