"""Render the existing synthetic fixture in supported raw log formats."""
from pathlib import Path
from datetime import datetime
import json
base=Path(__file__).parent
rows=[json.loads(x) for x in (base/'demo.jsonl').read_text().splitlines()]
ssh=[];apache=[];zeek=[]
months='Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
for e in rows:
    dt=datetime.fromisoformat(e['timestamp'])
    if e['kind']=='auth':
        outcome='Failed' if e['outcome']=='failure' else 'Accepted'
        ssh.append(f"{e['timestamp']} lab-host sshd[4242]: {outcome} password for {e['user']} from {e['src_ip']} port 55000 ssh2")
    elif e['kind']=='web':
        stamp=f'{dt.day:02}/{months[dt.month-1]}/{dt.year}:{dt:%H:%M:%S} +0000'
        apache.append(f'{e["src_ip"]} - - [{stamp}] "GET {e["path"]} HTTP/1.1" {e["status"]} 128 "-" "CyberSentinel-Lab"')
    else:
        zeek.append(json.dumps({'ts':dt.timestamp(),'uid':f'lab{len(zeek)}','id.orig_h':e['src_ip'],'id.orig_p':55000,'id.resp_h':e['dst_ip'],'id.resp_p':e['dst_port'],'proto':'tcp','conn_state':'S0'}))
ssh.append('2026-10-15T10:00:00+00:00 lab-host sshd[4242]: Connection closed by 192.0.2.20 port 55000')
for name,lines in [('ssh-auth.log',ssh),('access.log',apache),('zeek-conn.jsonl',zeek)]:
    (base/name).write_text('\n'.join(lines)+'\n',encoding='utf-8')
(base/'ssh-legacy.log').write_text('Oct 15 16:00:00 lab-host sshd[4242]: Failed password for student from 192.0.2.20 port 55000 ssh2\n',encoding='utf-8')
