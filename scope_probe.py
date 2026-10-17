import base64, hashlib, hmac, json, os, time, urllib.request, urllib.error, urllib.parse, sys
C = json.load(open('/tmp/creds.json'))
KEY, SEC = C.get('key'), C.get('secret')
HOST = 'packagist.com'
if not KEY:
    raise SystemExit('no credential issued')

def sign(method, path, query, body):
    ts = str(int(time.time()))
    cnonce = base64.b64encode(os.urandom(48)).decode()
    params = {'timestamp': ts, 'cnonce': cnonce, 'key': KEY, 'version': '2', 'query': query or ''}
    if body:
        params['body'] = body
    q = lambda v: urllib.parse.quote(v if isinstance(v, str) else v.decode('latin-1'), safe='')
    s2s = method.upper() + "\n" + HOST + "\n" + path + "\n" + \
          '&'.join(f"{q(k)}={q(params[k])}" for k in sorted(params))
    sig = base64.b64encode(hmac.new(SEC.encode(), s2s.encode(), hashlib.sha256).digest()).decode()
    return ("PACKAGIST-HMAC-SHA256 Key=%s, Timestamp=%s, Cnonce=%s, Version=2, Signature=%s"
            % (KEY, ts, cnonce, sig))

def call(method, path, data=None, body_bytes=None, ctype='application/json', extra=None):
    body = body_bytes if body_bytes is not None else (json.dumps(data).encode() if data is not None else None)
    hdr = {'Content-Type': ctype, 'Accept': 'application/json'}
    if extra: hdr.update(extra)
    hdr['Authorization'] = sign(method, path, '', body)
    req = urllib.request.Request('https://' + HOST + path, data=body, headers=hdr, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=45)
        return r.status, r.read().decode('utf-8', 'replace')[:300]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')[:300]
    except Exception as e:
        return 0, repr(e)[:200]

print('=== SCOPE PROBES with the 15-minute trusted-publishing credential ===')
probes = [
    ('GET  /api/packages/', 'GET', '/api/packages/'),
    ('GET  /api/teams/', 'GET', '/api/teams/'),
    ('GET  /api/credentials/', 'GET', '/api/credentials/'),
    ('GET  /api/tokens/', 'GET', '/api/tokens/'),
    ('GET  /api/organization/ssh-access-key', 'GET', '/api/organization/ssh-access-key'),
    ('GET  /api/organization/access-report.csv', 'GET', '/api/organization/access-report.csv'),
    ('GET  /api/suborganizations/', 'GET', '/api/suborganizations/'),
    ('GET  /api/customers/', 'GET', '/api/customers/'),
    ('GET  /api/mirrored-repositories/', 'GET', '/api/mirrored-repositories/'),
]
for label, m, p in probes:
    st, body = call(m, p)
    print(f'{label:44s} -> [{st}] {body[:110]}')
