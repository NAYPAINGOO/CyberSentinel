"""Explicit adapters. Unrecognised records fail closed; supported unrelated SSH lines are counted."""
import json
import re
from datetime import datetime, timedelta, timezone
from .detection import normalize

FORMATS = {'jsonl': 'Normalised JSONL', 'ssh': 'OpenSSH authentication log',
           'apache': 'Apache / Nginx common or combined', 'zeek': 'Zeek conn.log (JSON)'}
MONTHS = dict(zip('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), range(1, 13)))
APACHE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (?:\d+|-)(?: "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*")?$')
SSH = re.compile(r'^(?:Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port \d+\b')


def fixed_offset(value):
    if not isinstance(value, str) or not re.fullmatch(r'[+-]\d{2}:\d{2}', value):
        raise ValueError('Legacy SSH timezone must be an explicit offset, e.g. +08:00')
    hours, minutes = map(int, value[1:].split(':'))
    if hours > 23 or minutes > 59:
        raise ValueError('Invalid timezone offset')
    return timezone((1 if value[0] == '+' else -1) * timedelta(hours=hours, minutes=minutes))


def parse_line(line, fmt, year=None, offset=None):
    if fmt == 'jsonl':
        return normalize(json.loads(line))
    if fmt == 'zeek':
        x = json.loads(line)
        if not isinstance(x, dict):
            raise ValueError('Zeek record must be a JSON object')
        if x.get('proto') not in ('tcp', 'udp'):
            if x.get('proto') in ('icmp', 'icmp6'):
                return None
            raise ValueError('Only TCP/UDP Zeek connection records are supported')
        if type(x.get('ts')) not in (int, float):
            raise ValueError('Zeek ts must be Unix epoch seconds')
        e = dict(timestamp=datetime.fromtimestamp(x['ts'], timezone.utc).isoformat(), kind='network',
                 src_ip=x['id.orig_h'], dst_ip=x['id.resp_h'], dst_port=x['id.resp_p'])
    elif fmt == 'apache':
        m = APACHE.fullmatch(line)
        if not m:
            raise ValueError('Expected common or combined access log format')
        ip, stamp, request, status = m.groups()
        date = re.fullmatch(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})', stamp)
        if not date:
            raise ValueError('Invalid access-log timestamp')
        day, month, yr, hour, minute, second, zone = date.groups()
        dt = datetime(int(yr), MONTHS[month], int(day), int(hour), int(minute), int(second),
                      tzinfo=fixed_offset(zone[:3]+':'+zone[3:]))
        parts = request.split(' ')
        if len(parts) != 3 or not parts[2].startswith('HTTP/'):
            raise ValueError('Expected METHOD request-target HTTP/version')
        e = dict(timestamp=dt.isoformat(), kind='web', src_ip=ip, path=parts[1], status=int(status))
    elif fmt == 'ssh':
        m = re.fullmatch(r'(\S+) (\S+) sshd(?:-session)?\[\d+\]: (.*)', line)
        if m:
            stamp, _host, message = m.groups()
            dt = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                raise ValueError('ISO SSH timestamps must include a timezone')
        else:
            m = re.fullmatch(r'(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) sshd(?:-session)?\[\d+\]: (.*)', line)
            if not m:
                raise ValueError('Expected an sshd ISO or traditional syslog record')
            month, day, hour, minute, second, _host, message = m.groups()
            if not year or not offset:
                raise ValueError('Traditional SSH syslog has no year/zone: supply both explicitly')
            dt = datetime(int(year), MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=fixed_offset(offset))
        match = SSH.match(message)
        if not match:
            if message.startswith(('Failed ', 'Accepted ')):
                raise ValueError('Unsupported SSH authentication message')
            return None  # Valid sshd envelope but not an authentication outcome.
        username, ip = match.groups()
        e = dict(timestamp=dt.isoformat(), kind='auth', src_ip=ip, user=username,
                 outcome='success' if message.startswith('Accepted ') else 'failure')
    else:
        raise ValueError('Choose a supported log format')
    return normalize(e)


def parse_batch(text, fmt='jsonl', year=None, offset=None):
    if fmt not in FORMATS:
        raise ValueError('Choose a supported log format')
    lines = [x.strip() for x in text.lstrip('\ufeff').splitlines() if x.strip()]
    if not 1 <= len(lines) <= 2000:
        raise ValueError('Upload 1–2000 nonblank log records')
    parsed, skipped = [], 0
    for i, line in enumerate(lines, 1):
        try:
            if len(line) > 16384:
                raise ValueError('Maximum log line is 16,384 characters')
            e = parse_line(line, fmt, year, offset)
            if e is None:
                skipped += 1
            else:
                parsed.append(e)
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError, OSError) as exc:
            raise ValueError(f'Nonblank record {i}: invalid {fmt} log ({exc})') from exc
    return parsed, skipped
