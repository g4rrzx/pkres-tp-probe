import base64, hashlib, hmac, json, os, time, urllib.request, urllib.error, urllib.parse, sys
C = json.load(open('/tmp/creds.json'))
KEY, SEC = C.get('key'), C.get('secret')
HOST = 'packagist.com'
if not KEY:
    print('NO CREDENTIAL ISSUED:', json.dumps(C)[:300]); raise SystemExit(0)

def sign(method, path, query, body):
    ts = str(int(time.time())); cnonce = base64.b64encode(os.urandom(48)).decode()
    params = {'timestamp': ts, 'cnonce': cnonce, 'key': KEY, 'version': '2', 'query': query or ''}
    if body: params['body'] = body
    def q(v):
        if isinstance(v, bytes): return urllib.parse.quote(v, safe='')
        return urllib.parse.quote(v.encode('utf-8','surrogateescape'), safe='')
    s2s = method.upper()+"\n"+HOST+"\n"+path+"\n"+'&'.join(f"{q(k)}={q(params[k])}" for k in sorted(params))
    sig = base64.b64encode(hmac.new(SEC.encode(), s2s.encode(), hashlib.sha256).digest()).decode()
    return ("PACKAGIST-HMAC-SHA256 Key=%s, Timestamp=%s, Cnonce=%s, Version=2, Signature=%s" % (KEY, ts, cnonce, sig))

def call(method, path, data=None, body_bytes=None, ctype='application/json', extra=None):
    body = body_bytes if body_bytes is not None else (json.dumps(data).encode() if data is not None else None)
    hdr = {'Content-Type': ctype, 'Accept': 'application/json'}
    if extra: hdr.update(extra)
    hdr['Authorization'] = sign(method, path, '', body)
    req = urllib.request.Request('https://'+HOST+path, data=body, headers=hdr, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=45)
        return r.status, r.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e: return e.code, e.read().decode('utf-8','replace')
    except Exception as e: return 0, repr(e)[:200]

print('=== OIDC credential scope probes ===')
for label, p in [('GET /api/packages/', '/api/packages/'),
                 ('GET /api/teams/', '/api/teams/'),
                 ('GET /api/credentials/', '/api/credentials/'),
                 ('GET /api/tokens/', '/api/tokens/'),
                 ('GET /api/organization/ssh-access-key', '/api/organization/ssh-access-key'),
                 ('GET /api/suborganizations/', '/api/suborganizations/'),
                 ('GET /api/customers/', '/api/customers/'),
                 ('GET /api/mirrored-repositories/', '/api/mirrored-repositories/')]:
    st, b = call('GET', p)
    print(f'{label:42s} [{st}] {b[:110]}')

print('=== upload artifacts for bound vs unbound packages ===')
for fn, pkg in [('probe-pkg.zip','pkresearchlab/tp-probe'),
                ('other-pkg.zip','pkresearchlab/other-pkg'),
                ('not-bound.zip','g4rrzx/not-bound')]:
    try: body = open('art/'+fn,'rb').read()
    except FileNotFoundError: print(fn,'missing'); continue
    st, b = call('POST','/api/packages/artifacts/', body_bytes=body, ctype='application/zip', extra={'X-FILENAME':fn})
    print(f'upload {fn:16s} [{st}] {b[:170]}')
    if st == 201:
        try: aid = json.loads(b)['id']
        except Exception: continue
        st2, b2 = call('POST','/api/packages/', data={'repoType':'artifact','artifactIds':[aid]})
        print(f'  createArtifactPackage({aid}) -> [{st2}] {b2[:250]}')

print('=== POSITIVE CONTROL: publish the BOUND package pkresearchlab/tp-probe ===')
body = open('art/tp-probe.zip','rb').read()
st, b = call('POST','/api/packages/artifacts/', body_bytes=body, ctype='application/zip', extra={'X-FILENAME':'tp-probe.zip'})
print(f'upload tp-probe.zip [{st}] {b[:200]}')
if st == 201:
    aid = json.loads(b)['id']
    st2, b2 = call('POST','/api/packages/', data={'repoType':'artifact','artifactIds':[aid]})
    print(f'createArtifactPackage({aid}) -> [{st2}] {b2[:400]}')
