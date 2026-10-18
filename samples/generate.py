"""Reproducible documentation-range IP fixtures, no real telemetry."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
base = datetime(2026, 10, 15, 8, tzinfo=timezone.utc)
def event(second, kind, src_ip, **kw):
    return dict(timestamp=(base + timedelta(seconds=second)).isoformat(), kind=kind, src_ip=src_ip, **kw)
benign = [event(i*120,'auth','192.0.2.20',user='student',outcome='success') for i in range(20)]
benign += [event(15,'auth','192.0.2.21',user='analyst',outcome='failure'), event(30,'auth','192.0.2.21',user='analyst',outcome='success')]
benign += [event(i*70,'web','192.0.2.22',path='/help',status=200) for i in range(12)]
benign += [event(i*90,'network','192.0.2.23',dst_ip='192.0.2.100',dst_port=443) for i in range(12)]
attack = [event(3600+i*15,'auth','198.51.100.10',user='lab-admin',outcome='failure') for i in range(6)]
attack += [event(3710,'auth','198.51.100.10',user='lab-admin',outcome='success')]
attack += [event(4000+i*3,'network','198.51.100.20',dst_ip='192.0.2.100',dst_port=20+i) for i in range(12)]
attack += [event(4200+i*4,'web','203.0.113.30',path=f'/missing-{i}',status=404) for i in range(10)]
for name, rows in [('benign',benign),('suspicious',attack),('demo',benign+attack)]:
    Path(__file__).with_name(name+'.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows),encoding='utf-8')
