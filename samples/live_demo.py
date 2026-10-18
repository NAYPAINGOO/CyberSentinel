"""Append synthetic OpenSSH outcomes. Does not generate real login attempts."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,default=Path('instance/live-auth.log'))
p.add_argument('--interval',type=float,default=2)
a=p.parse_args()
if not 0.1<=a.interval<=30: p.error('interval must be 0.1–30 seconds')
a.output.parent.mkdir(parents=True,exist_ok=True)
account='demo-'+datetime.now(timezone.utc).strftime('%H%M%S%f')
for i in range(7):
    stamp=datetime.now(timezone.utc).isoformat(timespec='milliseconds')
    outcome='Failed' if i<6 else 'Accepted'
    line=f'{stamp} lab-host sshd[4242]: {outcome} password for {account} from 198.51.100.42 port 55000 ssh2\n'
    with a.output.open('a',encoding='utf-8',newline='') as f: f.write(line)
    print(f'Appended synthetic record {i+1}/7: {outcome}',flush=True)
    time.sleep(a.interval)
print('Finished. Expect AUTH-001 and AUTH-002 for this demo account.')
