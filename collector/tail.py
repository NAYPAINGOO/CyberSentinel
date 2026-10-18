"""Local file tailer with acknowledgement-based checkpoints. Standard library only."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

MAX_LINE = 65536
MAX_BATCH = 128 * 1024

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_url(url):
    p=urlsplit(url)
    if p.scheme != 'http' or p.hostname != '127.0.0.1' or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:
        raise ValueError('Only local http://127.0.0.1:PORT is supported')
    return url.rstrip('/')+'/api/collect'


@contextmanager
def state_lock(path):
    """OS lock released on process exit, including crashes."""
    lock=Path(str(path)+'.lock')
    lock.parent.mkdir(parents=True,exist_ok=True)
    with lock.open('a+b') as f:
        f.seek(0); f.write(b'0'); f.flush(); f.seek(0)
        if os.name=='nt':
            import msvcrt
            msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            yield
        finally:
            f.seek(0)
            if os.name=='nt': msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else: fcntl.flock(f,fcntl.LOCK_UN)


def signature(f, offset):
    f.seek(max(0,offset-64))
    return hashlib.sha256(f.read(min(offset,64))).hexdigest()


def read_batch(path, state):
    with path.open('rb') as f:
        st=os.fstat(f.fileno())
        identity=f'{st.st_dev}:{st.st_ino}'
        offset=state.get('offset',0)
        if not isinstance(offset,int) or offset<0:
            raise ValueError('Invalid checkpoint offset')
        rotated=bool(state and (state.get('identity')!=identity or st.st_size<offset or signature(f,offset)!=state.get('anchor')))
        if rotated: offset=0
        f.seek(offset)
        chunks=[];size=0
        for _ in range(200):
            start=f.tell()
            line=f.readline(MAX_LINE+1)
            if len(line)>MAX_LINE:
                raise ValueError('Log line exceeds 64 KiB; checkpoint unchanged. Correct the source before retrying.')
            if not line or not line.endswith(b'\n'):
                f.seek(start); break
            if size+len(line)>MAX_BATCH:
                f.seek(start); break
            chunks.append(line);size+=len(line)
        end=f.tell()
        checkpoint={'path':str(path.resolve()),'identity':identity,'offset':end,'anchor':signature(f,end)}
        return b''.join(chunks).decode('utf-8-sig'),checkpoint,rotated


def save_state(path, state):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(state),encoding='utf-8')
    os.replace(temporary,path)


def send(endpoint, token, text, fmt, year, offset):
    req=Request(endpoint,data=json.dumps({'logs':text,'format':fmt,'year':year,'offset':offset}).encode(),
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    with build_opener(ProxyHandler({}),NoRedirect()).open(req,timeout=30) as res:
        result=json.loads(res.read(65536))
    if not isinstance(result,dict) or result.get('accepted') is not True:
        raise ValueError('Server did not acknowledge the batch')
    return result


def run(args):
    endpoint=validate_url(args.url)
    source=args.file.resolve()
    state_path=args.state.resolve()
    token=args.token_file.read_text(encoding='utf-8').strip()
    if len(token)<32: raise ValueError('Invalid token file')
    with state_lock(state_path):
        state=json.loads(state_path.read_text()) if state_path.exists() else {}
        if not isinstance(state,dict): raise ValueError('Invalid checkpoint')
        binding={'path':str(source),'endpoint':endpoint,'format':args.format,'year':args.year,'offset_zone':args.offset}
        if state and state.get('binding')!=binding:
            raise ValueError('Checkpoint belongs to different file/server/parser settings. Choose a new --state path.')
        failures=0
        while True:
            try:
                text,next_state,rotated=read_batch(source,state)
                response=send(endpoint,token,text,args.format,args.year,args.offset)
                next_state['binding']=binding
                save_state(state_path,next_state)
                state=next_state;failures=0
                if text or rotated or args.once:
                    print(json.dumps({'rotation_or_truncation':rotated,**response}),flush=True)
                if args.once: return 0
            except HTTPError as exc:
                if exc.code in (400,401,403,413):
                    message=exc.read(2048).decode('utf-8',errors='replace')
                    raise ValueError(f'Server rejected batch ({exc.code}): {message}. Checkpoint unchanged.') from exc
                failures+=1
                print(f'HTTP {exc.code}; retrying without advancing checkpoint.',file=sys.stderr,flush=True)
                if args.once: return 1
            except (URLError,TimeoutError,OSError) as exc:
                failures+=1
                print(f'Connection/file unavailable ({type(exc).__name__}); checkpoint unchanged.',file=sys.stderr,flush=True)
                if args.once: return 1
            time.sleep(min(30,max(args.interval,2**min(failures,5))))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',required=True,type=Path)
    parser.add_argument('--format',choices=['jsonl','ssh','apache','zeek'],required=True)
    parser.add_argument('--token-file',required=True,type=Path)
    parser.add_argument('--state',type=Path,default=Path('instance/collector-state.json'))
    parser.add_argument('--url',default='http://127.0.0.1:8000')
    parser.add_argument('--year',type=int)
    parser.add_argument('--offset',help='Legacy SSH timezone, e.g. +08:00 or --offset=-05:00')
    parser.add_argument('--interval',type=float,default=2.0)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    if not 1<=args.interval<=60: parser.error('interval must be 1–60 seconds')
    try: return run(args)
    except KeyboardInterrupt:
        print('Collector stopped. Last acknowledged checkpoint retained.'); return 0
    except (ValueError,OSError) as exc:
        print(str(exc),file=sys.stderr); return 1

if __name__=='__main__': raise SystemExit(main())
