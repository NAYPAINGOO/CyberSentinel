"""Optional local-only model assistance; generated text is never treated as evidence."""
import json
from collections import Counter
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import URLError

class AIError(Exception):
    pass

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def evidence_facts(alert, evidence):
    # Deliberately exclude attacker-controlled usernames, paths, notes and raw lines.
    return {'rule': alert['rule'], 'score': alert['score'], 'event_count': len(evidence),
            'first_timestamp': min(e['timestamp'] for e in evidence),
            'last_timestamp': max(e['timestamp'] for e in evidence),
            'kinds': dict(Counter(e['kind'] for e in evidence)),
            'authentication_outcomes': dict(Counter(e['outcome'] for e in evidence if e['kind']=='auth')),
            'distinct_destination_ports': len({e['dst_port'] for e in evidence if e['kind']=='network'}),
            'distinct_web_paths': len({e['path'] for e in evidence if e['kind']=='web'}),
            'http_status_counts': dict(Counter(str(e['status']) for e in evidence if e['kind']=='web')),
            'evidence_ids': [e['id'] for e in evidence[:30]],
            'reference_ids_truncated': len(evidence)>30}


def validate_output(raw, allowed_ids):
    if not isinstance(raw, dict) or set(raw) != {'summary', 'suggested_steps', 'limitations', 'evidence_ids'}:
        raise AIError('Model output did not match the required structure. Nothing was saved.')
    if not isinstance(raw['summary'], str) or not 1 <= len(raw['summary']) <= 4000:
        raise AIError('Model summary is missing or too long.')
    for key in ('suggested_steps', 'limitations'):
        if not isinstance(raw[key], list) or not 1 <= len(raw[key]) <= 6 or any(not isinstance(x,str) or not 1<=len(x)<=1000 for x in raw[key]):
            raise AIError('Model steps or limitations failed validation.')
    refs = raw['evidence_ids']
    if not isinstance(refs, list) or not 1 <= len(refs) <= 30 or any(not isinstance(x,str) or x not in allowed_ids for x in refs):
        raise AIError('Model cited missing or unknown evidence. Nothing was saved.')
    return raw


def generate_summary(alert, evidence, model):
    facts = evidence_facts(alert, evidence)
    payload = {'model': model, 'stream': False, 'format': 'json',
               'system': 'You assist a human SOC analyst. The input is derived log evidence, not proof of an attack. '
                         'Never assert compromise or invent facts. Scores are fixed priorities, not probabilities. '
                         'Return only JSON with exactly summary (string), suggested_steps (1-6 strings), '
                         'limitations (1-6 strings), evidence_ids (1-30 exact IDs from input). '
                         'Summarise the observable pattern, propose verification steps, and explicitly state uncertainty. '
                         'You have no tools and cannot take actions.',
               'prompt': json.dumps(facts, sort_keys=True),
               'options': {'temperature': 0, 'num_predict': 700, 'num_ctx': 4096}}
    req = Request('http://127.0.0.1:11434/api/generate', data=json.dumps(payload).encode(),
                  headers={'Content-Type':'application/json'}, method='POST')
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=90) as response:
            data=response.read(65537)
        if len(data)>65536:
            raise AIError('Model response exceeded the size limit.')
        outer=json.loads(data)
        if not isinstance(outer, dict) or outer.get('done') is not True:
            raise AIError('Model did not complete the response.')
        result=json.loads(outer['response'])
    except (URLError, TimeoutError, OSError) as exc:
        raise AIError('Local Ollama is unavailable or timed out. Check Ollama and the installed model; the incident is unchanged.') from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise AIError('Ollama returned invalid JSON. The incident is unchanged.') from exc
    return validate_output(result, set(facts['evidence_ids'])), facts
