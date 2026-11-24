#!/usr/bin/env python3
"""artex_hunter.py - retro-hunt web, WAF and proxy logs for ARTEX-style agentic attacks.

Scores every source address, and every rotating-IP cluster, on three layers:
  L1 strings    user agents fixed in the ARTEX code or reported from ARTEX intrusions,
                the agents' self-labels and intent numbers, zz / artx / artex- probe
                paths, control-404 canaries, ARTEX-named webshells
  L2 behaviour  user-agent family switching, truncated browser strings, hostname
                breadth, 404 fuzzing, every-verb probing, rotating client-IP headers,
                the burst-then-pause rhythm of an agent waiting on its model
  L3 sequence   map (source maps, config, OpenAPI) -> auth probing -> exploitation
It also pulls out the numbers agents stamp on their own work (i5938, artex-probe-12345,
zz-notexist-8812) so web, identity, cloud and endpoint logs can be joined on them.

Input, auto-detected per file (.gz is fine): nginx/Apache combined, with optional extra
quoted fields such as X-Forwarded-For and Host; JSON lines (Cloudflare, AWS WAF, Azure
Front Door / Application Gateway, Google Cloud load balancer, Elastic ECS, Splunk
export); CSV exports with a header row; W3C extended (IIS, CloudFront); AWS ALB.

  python3 artex_hunter.py access.log* -o hunt --since 2026-08-01
  python3 artex_hunter.py waf.json --source-from xff --xff-hops 1   # site behind a load balancer
  python3 artex_hunter.py cf/*.gz --allow-ip our_scanners.txt

Writes sources.csv, clusters.csv, evidence.csv, tags.csv and report.html to the output
folder. Scores rank what to read first. They are not a verdict: read the evidence.

ARTEX Hunting Pack - Sujay Adkesar - https://thelocalh0st.com - MIT licence
Standard library only, Python 3.8+.
"""
import argparse
import csv
import gzip
import html
import ipaddress
import json
import os
import re
import statistics
import sys
from collections import Counter, namedtuple
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import unquote_plus, urlsplit

VERSION = '1.0'
STALE_CHROME, STALE_FIREFOX = 127, 102

# --------------------------------------------------------------------------- indicators
SENSITIVE = (r'(?i)/\.env(?:\.\w+)?(?:\?|$)|/\.git/|/\.aws/|/\.svn/|/\.ssh/|/\.ds_store|/web\.config|/appsettings(?:\.\w+)?\.json|'
             r'/actuator(?:/|$)|/heapdump|/server-status|/phpinfo|/web-inf/|/etc/(?:passwd|shadow)|/id_rsa|/\.npmrc|/\.docker/config\.json|'
             r'\.(?:bak|old|orig|sql|swp)(?:\?|$)')

# id, layer, weight, title, regex, applies to, where it comes from
INDICATORS = [
    ('ua_code', 'L1', 60, 'User agent hard-coded in the ARTEX source',
     r'artex-enrich/|spa-api-recon|artex-selfupdate', 'ua', 'ARTEX source'),
    ('ua_field', 'L1', 45, 'User agent reported from ARTEX intrusions',
     r'(?i)^norma/\d|reconprobe/|artexverify|(?<![a-z])art(?:ex|x)(?![a-z])|rv:38\.0\) Gecko/20100101 Firefox/38\.0$',
     'ua', 'Wiz, Bitrise, Eye Security'),
    ('ua_intent', 'L1', 35, 'Intent number stamped into the user agent',
     r'(?i)(?:probe|pentest|artx|artex|audit|scan)[-_]?i\d{3,6}(?!\d)|(?<![a-z0-9])i\d{3,6}[-_]?(?:canary|probe)', 'ua', 'Bitrise'),
    ('ua_selflabel', 'L1', 20, 'User agent declares an authorised test',
     r'(?i)pentest|authori[sz]ed[- ]?(?:pentest|security|research|read|scan|test|private)|research[-; ]*read-?only|\(authori[sz]ed|'
     r'bounty[- ]?(?:check|hunt|research|program)|red-?team', 'ua', 'Bitrise, Profero'),
    ('path_artex', 'L1', 35, 'zz / artx / artex- probe path',
     r'(?i)^/zz|/nr\?zz|/artex[-_](?:[a-z]{0,2}\d{3,}|probe|canary|marker|nonexist|write|test)|'
     r'(?<![a-z])artx[-_]?(?:[a-z]{0,2}\d{2,}|nonexist|probe|test|s\d)|zzartx', 'path', 'Eye Security, Profero'),
    ('path_canary', 'L1', 25, 'Control-404 canary before a fuzzing round',
     r'(?i)zz+[-_]?(?:q[-_])?(?:random[-_])?no[nt][-_]?exist|nonexistent[-_]xyz|notexist[-_]xyz|_probe_missing|/nope-\d{3,}|'
     r'(?<![a-z])artx[-_]?nonexist', 'path', 'Wiz, Eye Security, Bitrise'),
    ('webshell', 'L1', 45, 'ARTEX-named webshell or its key',
     r'(?i)zzartx\d*\.(?:php\d?|phtml|jsp|aspx?)|(?<![a-z])artx_s\d+\.php|[?&]k=x9f3c2b7e(?:&|$)|/(?:cl|z|f)\d{4}a?\.jsp',
     'path', 'Eye Security, GTIG'),
    ('jwt_none', 'L2', 30, 'Unsigned JWT (alg none)',
     r'eyJhbGciOiJub25lI|eyJhbGciOiAibm9uZSI|eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lI|eyJhbGciOiJOT05FI|eyJhbGciOiJOb25lI', 'path', 'Wiz'),
    ('oauth_forge', 'L2', 20, 'Forged OAuth callback', r'(?i)[?&]code=A{4,}(?:&|$)|[?&]state=notvalid', 'path', 'Wiz'),
    ('ssrf_meta', 'L2', 30, 'Cloud metadata address in the request (SSRF)',
     r'169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254', 'path', 'Bitrise, FBI'),
    ('oast', 'L2', 25, 'Out-of-band callback domain in the request',
     r'(?i)dnslog\.cn|\.oast\.(?:me|fun|pro|site|online|live)|interact\.sh|oastify\.com|burpcollaborator\.net|webhook\.site|'
     r'ceye\.io|requestbin|pipedream\.net', 'path', 'Eye Security, GTIG, FBI'),
    ('tsql_stack', 'L2', 20, 'Stacked T-SQL in a parameter',
     r'(?i)[?&][^=&]*=[^&]*(?:\bdeclare\s+@|\bwaitfor\s+(?:delay|time)\b|\bexec(?:ute)?\s*\(|\bexec(?:ute)?\s+(?:@|sp_|xp_|master\.))',
     'path', 'Profero'),
    ('placeholder', 'L2', 10, 'Placeholder values in identifiers', r'(?i)=(?:x{3,}|9{5,})(?:&|$)', 'path', 'Profero'),
    ('upload_fuzz', 'L2', 15, 'Script-extension fuzzing',
     r'(?i)\.(?:phtml|php[3-8s]|phar|pht|pgif|shtml|jspx|jspf|ashx|asmx)(?:\?|$)|\.(?:jpe?g|png|gif)\.php|\.php\.(?:jpe?g|png|gif)(?:\?|$)',
     'path', 'Eye Security'),
    ('sensitive', 'L2', 8, 'Sensitive-file probing', SENSITIVE, 'path', 'FBI, GTIG'),
]
EXTRA = {  # signals computed in code: layer, weight, title, source
    'ua_malformed': ('L2', 15, 'Truncated or hand-written browser user agent', 'Wiz, Bitrise'),
    'ua_stale': ('L2', 5, 'Browser version two or more years old', 'Profero'),
    'tls_mismatch': ('L2', 25, 'Browser user agent on a TLS handshake without ALPN (JA4)', 'JA4 spec'),
    'fam_div': ('L2', 30, '3+ user-agent families and 20+ requests in one minute', 'Elastic'),
    'host_breadth': ('L2', 20, '10+ hostnames from one source', 'Bitrise'),
    'fuzz_404': ('L2', 15, '20+ distinct paths refused in 5 minutes', 'Wiz, GTIG'),
    'err_ratio': ('L2', 10, 'Mostly 4xx responses', 'Profero'),
    'every_verb': ('L2', 10, '5+ HTTP methods on one path', 'Profero'),
    'xff_rotation': ('L2', 25, 'Client-IP header changes on nearly every request', 'Eye Security'),
    'cadence': ('L2', 15, 'Burst-then-pause rhythm (agent waiting on its model)', 'Unit 42, GTIG, Wiz'),
    'peak_rate': ('L2', 10, '120+ requests in one minute', 'Eye Security, Profero'),
    'auth_burst': ('L2', 15, '30+ auth-endpoint requests, 10+ variants, in 5 minutes', 'Wiz'),
    'label_on_block': ('L2', 10, 'Tester label mostly on refused requests', 'Profero'),
    'rotation': ('L2', 15, 'Same unusual fingerprint from many addresses', 'Eye Security, Profero, FBI'),
    'sequence3': ('L3', 30, 'Kill-chain order: map, then auth probing, then exploitation', 'Wiz, GTIG'),
    'sequence2': ('L3', 15, 'Two kill-chain phases in order', 'Wiz, GTIG'),
}
META = {i: (l, w, t, src) for i, l, w, t, rx, where, src in INDICATORS}
META.update(EXTRA)
WEIGHT = {k: v[1] for k, v in META.items()}
TIE = {'ua_code', 'ua_field', 'ua_intent', 'path_artex', 'path_canary', 'webshell'}
AGENTIC = {'cadence', 'fam_div', 'sequence3', 'ua_selflabel', 'label_on_block', 'ua_malformed', 'tls_mismatch', 'xff_rotation', 'rotation'}
SHAPE = {'ua_malformed', 'ua_stale'}
EXPLOIT = {'jwt_none', 'oauth_forge', 'ssrf_meta', 'oast', 'tsql_stack', 'upload_fuzz', 'webshell'}


def scoped(rx):
    return '(?i:%s)' % rx[4:] if rx.startswith('(?i)') else '(?:%s)' % rx


UA_RX = [(i, re.compile(rx)) for i, l, w, t, rx, where, src in INDICATORS if where == 'ua']
PATH_RX = [(i, re.compile(rx)) for i, l, w, t, rx, where, src in INDICATORS if where == 'path']
PATH_ANY = re.compile('|'.join(scoped(rx) for i, l, w, t, rx, where, src in INDICATORS if where == 'path'))
MAP_RX = re.compile(r'(?i)\.js\.map(?:\?|$)|/env\.js(?:\?|$)|/(?:assets/)?config\.json(?:\?|$)|/swagger|/openapi|/api-docs')
AUTH_RX = re.compile(r'(?i)validateusername|password_?reset|reset_?password|forgot_?password|register_user|/sign_?up(?:/|\?|$)|'
                     r'/register(?:/|\?|$)|/confirm(?:/|\?|$)|/sso(?:/|\?|$)|/oauth|/saml|generate_redirect_link|/api/v\d+/me(?:/|\?|$)|'
                     r'/log_?in(?:/|\?|$)|/sign_?in(?:/|\?|$)|/token(?:/|\?|$)')
TRAVERSAL = re.compile(r'\.\./|\.\.\\|/etc/passwd|win\.ini')
LABEL = re.compile(r'(?i)authori[sz]ed|bounty|research|pentest|read-?only|(?<!kube-)probe')
CRAWLER = re.compile(r'(?i)googlebot|bingbot|duckduckbot|yandex|baiduspider|applebot|uptimerobot|pingdom|statuscake|site24x7|'
                     r'facebookexternalhit|slurp|semrush|ahrefs|petalbot|kube-probe|elb-healthchecker|googlehc|\+https?://')
MALFORMED = [
    re.compile(r'^Mozilla/5\.0$'),
    re.compile(r'^Mozilla/5\.0 \((?:Windows NT|Macintosh|X11|Linux|iPhone|iPad|Android)[^)]*\)(?!.*(?:AppleWebKit|Gecko|Trident|Presto))'),
    re.compile(r'Chrome/\d+(?:\.\d+){0,2}(?![\d.])'),
    re.compile(r'^(?=.*Chrome/)(?!.*AppleWebKit/)'),
    re.compile(r'^(?!.*Gecko/).*\bFirefox/\d'),
]
TAG_PRE = re.compile(r'(?i)zz|probe|artx|artex|i\d{3}')
TAG_RX = [
    ('intent', re.compile(r'(?i)(?:probe|pentest|artx|artex|audit|canary|scan|qa)[-_]?i(\d{3,6})(?!\d)')),
    ('intent', re.compile(r'(?i)(?<![a-z0-9])i(\d{3,6})[-_]?(?:canary|probe)')),
    ('artex-probe', re.compile(r'(?i)artex[-_]probe[-_](\d{3,6})(?!\d)')),
    ('probe', re.compile(r'(?i)(?<!artex-)(?<!artex_)(?<!kube-)(?<![a-z])probe[-_](\d{3,6})(?!\d)')),
    ('artx', re.compile(r'(?i)(?<![a-z])(?:zz)?artx[-_]?(\d{3,6})(?!\d)')),
    ('artex-q', re.compile(r'(?i)artex-q(\d{3,6})(?!\d)')),
    ('marker', re.compile(r'(?i)(?<![a-z0-9])(zz[a-z0-9]*(?:[-_][a-z0-9]+){0,3})')),
]


def family(ua):
    u = ua.lower()
    if not ua or ua == '-':
        return 'empty'
    if re.search(r'(?<![a-z])art(?:ex|x)|artexverify|norma/|spa-api-recon|reconprobe', u):
        return 'artex'
    if CRAWLER.search(ua):
        return 'crawler'
    if u.startswith('curl/'):
        return 'curl'
    if 'python' in u or 'aiohttp' in u or u.startswith('httpx/'):
        return 'python'
    if u.startswith('go-http-client') or 'golang' in u:
        return 'go'
    if 'boto' in u or 'aws-cli' in u or 'aws-sdk' in u:
        return 'aws'
    if re.search(r'fuzz faster|nuclei|sqlmap|nikto|gobuster|feroxbuster|dirbuster|wfuzz|masscan|zgrab|nessus|qualys|acunetix|burp', u):
        return 'scanner'
    if 'headless' in u or 'playwright' in u or 'phantomjs' in u or 'puppeteer' in u:
        return 'headless'
    if re.search(r'node-fetch|axios|undici|okhttp|java/|apache-httpclient|libwww|wget/|powershell|winhttp|reqwest', u):
        return 'library'
    if u.startswith('mozilla/'):
        return 'browser'
    return 'other'


def tags_in(text):
    out = []
    if TAG_PRE.search(text):
        for kind, rx in TAG_RX:
            for m in rx.finditer(text):
                v = m.group(1).lower()
                if kind == 'marker' and len(v) < 4:
                    continue
                out.append('%s:%s' % (kind, v))
    return out


UA = namedtuple('UA', 'family shape sids labelled tags trackable')


@lru_cache(maxsize=200000)
def ua_info(ua):
    fam = family(ua)
    shape = 'ok'
    if fam == 'browser':
        if any(rx.search(ua) for rx in MALFORMED):
            shape = 'malformed'
        else:
            m = re.search(r'Chrome/(\d+)\.0\.0\.0', ua)
            f = re.search(r'Firefox/(\d+)', ua)
            if m and int(m.group(1)) <= STALE_CHROME or f and int(f.group(1)) <= STALE_FIREFOX:
                shape = 'stale'
    sids = [i for i, rx in UA_RX if rx.search(ua)]
    if 'ua_code' in sids and 'ua_field' in sids:
        sids.remove('ua_field')
    if shape != 'ok':
        sids.append('ua_' + shape)
    trackable = fam not in ('browser', 'crawler') or shape != 'ok'
    return UA(fam, shape, tuple(sids), bool(LABEL.search(ua)), tuple(tags_in(ua)), trackable)


# --------------------------------------------------------------------------- parsing
def parse_time(v):
    if v is None or v == '' or v == '-':
        return None
    s = str(v).strip()
    if re.fullmatch(r'\d{9,20}(?:\.\d+)?', s):
        x = float(s)
        x = x / 1e9 if x > 1e17 else x / 1e6 if x > 1e14 else x / 1e3 if x > 1e11 else x
        try:
            return datetime.fromtimestamp(x, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    for fmt in ('%d/%b/%Y:%H:%M:%S %z', '%d/%b/%Y:%H:%M:%S'):
        try:
            d = datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    t = re.sub(r'(\.\d{6})\d+', r'\1', s.replace('Z', '+00:00').replace(' UTC', '+00:00'))
    t = re.sub(r'(\.\d{1,5})(?=[+-]\d{2}:?\d{2}$|$)', lambda m: m.group(1).ljust(7, '0'), t)
    t = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', t)
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        d = None
        for fmt in ('%m/%d/%Y, %I:%M:%S.%f %p', '%m/%d/%Y %I:%M:%S %p', '%m/%d/%Y %H:%M:%S', '%b %d, %Y %H:%M:%S.%f', '%d-%b-%Y %H:%M:%S'):
            try:
                d = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if d is None:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


QF = r'"((?:[^"\\]|\\.)*)"'
COMBINED = re.compile(r'^(?:(?P<vhost>[^\s:]+:\d+) )?(?P<ip>\S+) \S+ (?:\S+|"[^"]*") \[(?P<time>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" '
                      r'(?P<status>\d{3}|-) (?P<bytes>\S+)(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?(?P<rest>.*)$')
ALB = re.compile(r'^(?:https?|h2|grpcs|ws|wss) (?P<time>\S+) \S+ (?P<client>\S+) \S+ \S+ \S+ \S+ (?P<status>\d{3}|-) \S+ \S+ \S+ '
                 r'"(?P<req>[^"]*)" "(?P<ua>[^"]*)"')
IP_LIST = re.compile(r'^\s*[\da-fA-F:.]+(?:\s*,\s*[\da-fA-F:.]+)*\s*$')
HOST_LIKE = re.compile(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$')
REQ_LINE = re.compile(r'^([A-Z]{3,10}) (\S+)(?: HTTP/[\d.]+)?$')
Rec = namedtuple('Rec', 'ts ip method uri status host ua xff tls')

ALIASES = {
    'ip': ['clientip', 'client_ip', 'client.ip', 'source.ip', 'src_ip', 'srcip', 'source_ip', 'sourceip', 'c-ip', 'c_ip', 'remote_addr',
           'remoteaddr', 'remote_ip', 'httprequest.clientip', 'httprequest.remoteip', 'properties.clientip', 'properties.clientip_s',
           'clientip_s', 'src', 'ip', 'client'],
    'ua': ['clientrequestuseragent', 'useragent', 'user_agent', 'user_agent.original', 'http_user_agent', 'cs(user-agent)',
           'httprequest.useragent', 'httprequest.headers.user-agent', 'properties.useragent', 'properties.useragent_s', 'useragent_s',
           'http.request.headers.user-agent', 'requestheaders.user-agent', 'user-agent', 'http_useragent', 'agent'],
    'uri': ['clientrequesturi', 'request_uri', 'requesturi', 'properties.requesturi', 'properties.requesturi_s', 'requesturi_s',
            'httprequest.requesturl', 'url.original', 'url.full', 'httprequest.uri', 'uri', 'url', 'cs-uri-stem', 'uri_path',
            'clientrequestpath', 'url.path', 'path', 'request'],
    'query': ['httprequest.args', 'url.query', 'cs-uri-query', 'uri_query', 'clientrequestquery', 'query', 'querystring', 'args'],
    'method': ['clientrequestmethod', 'method', 'http_method', 'request_method', 'requestmethod', 'httpmethod', 'cs-method',
               'http.request.method', 'httprequest.httpmethod', 'httprequest.requestmethod', 'properties.httpmethod', 'properties.httpmethod_s'],
    'status': ['edgeresponsestatus', 'status', 'http_status', 'statuscode', 'status_code', 'response_code', 'sc-status',
               'http.response.status_code', 'properties.httpstatuscode', 'properties.httpstatus', 'httprequest.status', 'responsecodesent',
               'httpstatus', 'originresponsestatus', 'properties.httpstatuscode_s'],
    'host': ['clientrequesthost', 'host', 'http_host', 'hostname', 'url.domain', 'cs-host', 'x-host-header', 'properties.hostname',
             'properties.host', 'httprequest.headers.host', 'site', 'server_name', 'host_s'],
    'time': ['edgestarttimestamp', '@timestamp', 'timestamp', 'time', 'timegenerated', '_time', 'datetime', 'date', 'start_time',
             'eventtime', 'properties.timestamp'],
    'xff': ['x_forwarded_for', 'xff', 'http_x_forwarded_for', 'httprequest.headers.x-forwarded-for', 'requestheaders.x-forwarded-for',
            'x-forwarded-for', 'xforwardedfor', 'clientrequestxforwardedfor'],
    'tls': ['ja4', 'ja4fingerprint', 'ja4_fingerprint', 'tls.client.ja4', 'botmanagement.ja4', 'ja3hash', 'ja3', 'ja3fingerprint',
            'ja3_fingerprint', 'tls.client.ja3', 'botmanagement.ja3hash'],
}


def flatten(d, prefix='', out=None):
    out = {} if out is None else out
    for k, v in d.items():
        key = prefix + str(k).lower()
        if isinstance(v, dict):
            flatten(v, key + '.', out)
        elif isinstance(v, list) and v and all(isinstance(x, dict) and 'name' in x and 'value' in x for x in v):
            for h in v:
                out[key + '.' + str(h['name']).lower()] = h['value']
        else:
            out[key] = v
    return out


def pick(d, field):
    for k in ALIASES[field]:
        v = d.get(k)
        if v not in (None, '', '-'):
            return v
    return None


def from_mapping(d):
    ip = pick(d, 'ip')
    uri = pick(d, 'uri')
    if ip is None or uri is None:
        return None
    ip, uri = str(ip), str(uri)
    method = pick(d, 'method')
    m = REQ_LINE.match(uri)
    if m:
        method, uri = method or m.group(1), m.group(2)
    host = pick(d, 'host')
    if uri.startswith(('http://', 'https://')):
        sp = urlsplit(uri)
        host = host or sp.hostname
        uri = (sp.path or '/') + ('?' + sp.query if sp.query else '')
    q = pick(d, 'query')
    if q and '?' not in uri:
        uri += '?' + str(q).lstrip('?')
    status = pick(d, 'status')
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 403 if str(d.get('action', '')).upper() == 'BLOCK' else 0
    if ':' in ip and ip.count(':') == 1:
        ip = ip.split(':')[0]
    return Rec(parse_time(pick(d, 'time')), ip, str(method or '-').upper(), uri, status, str(host or '-'),
               str(pick(d, 'ua') or ''), str(pick(d, 'xff') or '-'), str(pick(d, 'tls') or '-'))


def parse_json_line(line):
    try:
        d = json.loads(line)
    except ValueError:
        return []
    return json_records(d)


def json_records(d):
    if isinstance(d, list):
        return [r for x in d for r in json_records(x)]
    if not isinstance(d, dict):
        return []
    if isinstance(d.get('records'), list):
        return json_records(d['records'])
    for wrap in ('result', '_source'):
        if isinstance(d.get(wrap), dict):
            d = d[wrap]
    r = from_mapping(flatten(d))
    return [r] if r else []


def parse_combined(line):
    m = COMBINED.match(line)
    if not m:
        return []
    req = m.group('req')
    parts = req.split(' ')
    method, uri = (parts[0], parts[1]) if len(parts) >= 2 else ('-', req)
    extra = re.findall(QF, m.group('rest') or '')
    xff, host = '-', (m.group('vhost') or '-').split(':')[0]
    if extra and (extra[0] in ('-', '') or IP_LIST.match(extra[0])):
        xff = extra[0] or '-'
        extra = extra[1:]
    for f in extra:
        if HOST_LIKE.match(f) and host == '-':
            host = f.split(':')[0]
    status = int(m.group('status')) if m.group('status') != '-' else 0
    return [Rec(parse_time(m.group('time')), m.group('ip'), method.upper(), uri, status, host, m.group('ua') or '', xff, '-')]


def parse_alb(line):
    m = ALB.match(line)
    if not m:
        return []
    req = m.group('req').split(' ')
    method, url = (req[0], req[1]) if len(req) >= 2 else ('-', m.group('req'))
    sp = urlsplit(url)
    status = int(m.group('status')) if m.group('status') != '-' else 0
    return [Rec(parse_time(m.group('time')), m.group('client').rsplit(':', 1)[0], method, (sp.path or '/') + ('?' + sp.query if sp.query else ''),
                status, sp.hostname or '-', m.group('ua'), '-', '-')]


class W3C:
    def __init__(self):
        self.fields = None

    def parse(self, line):
        if line.startswith('#Fields:'):
            self.fields = [f.lower() for f in line[8:].split()]
            return []
        if line.startswith('#') or not self.fields:
            return []
        vals = line.split('\t') if '\t' in line else line.split(' ')
        if len(vals) != len(self.fields):
            return []
        d = dict(zip(self.fields, vals))
        if 'cs(user-agent)' in d:
            d['cs(user-agent)'] = unquote_plus(d['cs(user-agent)'])
        d['time'] = (d.get('date', '') + ' ' + d.get('time', '')).strip()
        d.pop('date', None)
        r = from_mapping(d)
        return [r] if r else []


class CSVParser:
    def __init__(self, header):
        self.header = [h.strip().strip('"').lower() for h in next(csv.reader([header]))]

    def parse(self, line):
        try:
            vals = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            return []
        if len(vals) != len(self.header) or [v.lower() for v in vals] == self.header:
            return []
        r = from_mapping(dict(zip(self.header, vals)))
        return [r] if r else []


KNOWN_HEADERS = {'clientip', 'client_ip', 'src_ip', 'source_ip', 'c-ip', 'ip', 'useragent', 'user_agent', 'http_user_agent', 'uri', 'url',
                 'request_uri', 'status', '_time', 'timestamp', 'time', 'method', 'host', 'timegenerated', 'requesturi_s', 'clientip_s'}


def open_any(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def records(path, fmt='auto'):
    """Yield (Rec, raw_line) for one file."""
    with open_any(path) as f:
        first = ''
        for first in f:
            if first.strip():
                break
        stripped = first.lstrip()
        kind = fmt
        if kind == 'auto':
            if stripped.startswith('#'):
                kind = 'w3c'
            elif stripped.startswith('['):
                kind = 'jsonarray'
            elif stripped.startswith('{'):
                kind = 'json'
            elif ALB.match(stripped):
                kind = 'alb'
            elif COMBINED.match(stripped.rstrip('\n')):
                kind = 'combined'
            elif len({h.strip().strip('"').lower() for h in stripped.split(',')} & KNOWN_HEADERS) >= 2:
                kind = 'csv'
            else:
                kind = 'combined'
        if kind == 'jsonarray':
            try:
                data = json.loads(first + f.read())
            except ValueError:
                return
            for r in json_records(data):
                if r.ts:
                    yield r, json.dumps(r._asdict(), default=str)[:400]
            return
        w3c = W3C()
        parser = {'json': parse_json_line, 'combined': parse_combined, 'alb': parse_alb, 'w3c': w3c.parse}.get(kind)
        lines = [first]
        if kind == 'csv':
            parser, lines = CSVParser(first).parse, []
        for chunk in (lines, f):
            for line in chunk:
                line = line.rstrip('\r\n')
                if not line:
                    continue
                for r in parser(line):
                    if r.ts:
                        yield r, line


# --------------------------------------------------------------------------- state
class State:
    """Everything kept for one source address, or for one fingerprint (cluster=True)."""
    __slots__ = ('key', 'cluster', 'n', 'first', 'last', 'uas', 'hosts', 'status', 'xffs', 'tls', 'times', 'signals', 'phases', 'tags',
                 'min_key', 'min_fams', 'min_n', 'div_minutes', 'div_max', 'peak', 'w5_key', 'w5_refused', 'fuzz_max', 'w5_auth',
                 'w5_auth_u', 'auth_max', 'verbs', 'lab_blk', 'lab_ok', 'blk', 'ok', 'ips', 'attack_ips')

    def __init__(self, key, cluster=False):
        self.key, self.cluster = key, cluster
        self.n, self.first, self.last = 0, None, None
        self.uas, self.status = Counter(), Counter()
        self.hosts, self.xffs, self.tls = set(), set(), set()
        self.times, self.signals, self.phases, self.tags = [], {}, {}, {}
        self.min_key, self.min_fams, self.min_n, self.div_minutes, self.div_max, self.peak = None, set(), 0, 0, 0, 0
        self.w5_key, self.w5_refused, self.fuzz_max, self.w5_auth, self.w5_auth_u, self.auth_max = None, set(), 0, 0, set(), (0, 0)
        self.verbs = {}
        self.lab_blk = self.lab_ok = self.blk = self.ok = 0
        self.ips, self.attack_ips = (Counter(), set()) if cluster else (None, None)

    def roll_minute(self, key):
        if self.min_key is not None:
            if len(self.min_fams) >= 3 and self.min_n >= 20:
                self.div_minutes += 1
                self.div_max = max(self.div_max, len(self.min_fams))
            self.peak = max(self.peak, self.min_n)
        self.min_key, self.min_fams, self.min_n = key, set(), 0

    def roll5(self, key):
        if self.w5_key is not None:
            self.fuzz_max = max(self.fuzz_max, len(self.w5_refused))
            if self.w5_auth >= 30 and len(self.w5_auth_u) >= 10 and self.w5_auth > self.auth_max[0]:
                self.auth_max = (self.w5_auth, len(self.w5_auth_u))
        self.w5_key, self.w5_refused, self.w5_auth, self.w5_auth_u = key, set(), 0, set()

    def finish(self):
        self.roll_minute(None)
        self.roll5(None)

    def add(self, r, path, info, sids, phases, tags, spoof, raw):
        ts = r.ts
        self.n += 1
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts
        if len(self.uas) < 500 or r.ua in self.uas:
            self.uas[r.ua] += 1
        if r.host and r.host != '-' and len(self.hosts) < 1000:
            self.hosts.add(r.host.lower())
        self.status[r.status // 100] += 1
        if spoof != '-' and len(self.xffs) < 5000:
            self.xffs.add(spoof)
        if r.tls != '-' and len(self.tls) < 50:
            self.tls.add(r.tls)
        epoch = ts.timestamp()
        if len(self.times) < 20000:
            self.times.append(epoch)
        mk = int(epoch // 60)
        if mk != self.min_key:
            self.roll_minute(mk)
        self.min_fams.add(info.family)
        self.min_n += 1
        fk = int(epoch // 300)
        if fk != self.w5_key:
            self.roll5(fk)
        bare = path.split('?', 1)[0]
        if r.status in (401, 403, 404, 405) and len(self.w5_refused) < 2000:
            self.w5_refused.add(bare)
        if 'auth' in phases:
            self.w5_auth += 1
            if len(self.w5_auth_u) < 2000:
                self.w5_auth_u.add(path)
        if r.method not in ('GET', 'HEAD'):
            v = self.verbs.get(bare)
            if v is None and len(self.verbs) < 2000:
                v = self.verbs[bare] = set()
            if v is not None:
                v.add(r.method[:12])
        for sid in sids:
            s = self.signals.get(sid)
            if s is None:
                s = self.signals[sid] = [0, ts, []]
            s[0] += 1
            s[1] = min(s[1], ts)
            if len(s[2]) < 3:
                s[2].append(raw[:400])
        for ph in phases:
            if ph not in self.phases or ts < self.phases[ph]:
                self.phases[ph] = ts
        for t in tags:
            v = self.tags.get(t)
            if v is None:
                self.tags[t] = [ts, ts, 1]
            else:
                v[0], v[1], v[2] = min(v[0], ts), max(v[1], ts), v[2] + 1
        blocked = r.status in (401, 403, 404, 405, 429)
        if blocked:
            self.blk += 1
            self.lab_blk += info.labelled
        elif 200 <= r.status < 400:
            self.ok += 1
            self.lab_ok += info.labelled

    def quiet(self, cutoff):
        return (not self.signals and self.last.timestamp() < cutoff and self.div_minutes == 0 and self.fuzz_max < 10 and self.peak < 60
                and len(self.hosts) < 5 and self.status[4] < 20 and len(self.xffs) < 5 and (not self.cluster or len(self.ips) <= 1))


def cadence(times):
    if len(times) < 30:
        return None
    ts = sorted(times)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    burst = [g for g in gaps if g < 3]
    pauses = sum(1 for g in gaps if 20 <= g <= 40)
    if len(burst) < 20 or pauses < 3:
        return None
    med = statistics.median(burst)
    share = sum(1 for g in burst if 0.5 <= g <= 2.0) / len(burst)
    if 0.6 <= med <= 1.6 and share >= 0.6:
        return 'median in-burst gap %.1fs, %d pauses of 20-40s' % (med, pauses)
    return None


def every_verb(methods):
    unusual = methods - {'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
    return len(methods) >= 5 or (len(methods) >= 4 and unusual)


def evaluate(s):
    s.finish()
    agg = {}
    if s.div_minutes:
        agg['fam_div'] = '%d minute(s), up to %d user-agent families' % (s.div_minutes, s.div_max)
    if len(s.hosts) >= 10:
        agg['host_breadth'] = '%d hostnames' % len(s.hosts)
    if s.fuzz_max >= 20:
        agg['fuzz_404'] = '%d distinct paths refused in one 5-minute window' % s.fuzz_max
    if s.n >= 50 and s.status[4] / s.n >= 0.6:
        agg['err_ratio'] = '%d%% of %d requests were 4xx' % (round(100 * s.status[4] / s.n), s.n)
    hits = [(p, m) for p, m in s.verbs.items() if every_verb(m)]
    if hits:
        agg['every_verb'] = '%s (+GET/HEAD) on %s' % (','.join(sorted(hits[0][1])), hits[0][0][:90])
    if not s.cluster and len(s.xffs) >= 20 and len(s.xffs) >= 0.5 * s.n and len(s.uas) <= 5:
        agg['xff_rotation'] = '%d distinct client-IP header values in %d requests' % (len(s.xffs), s.n)
    c = cadence(s.times)
    if c:
        agg['cadence'] = c
    if s.peak >= 120:
        agg['peak_rate'] = '%d requests in the busiest minute' % s.peak
    if s.auth_max[0]:
        agg['auth_burst'] = '%d auth requests, %d distinct, in 5 minutes' % s.auth_max
    if s.lab_blk + s.lab_ok >= 5 and s.blk >= 20 and s.lab_blk / s.blk > 0.1 and s.lab_ok / max(s.ok, 1) < 0.05:
        agg['label_on_block'] = 'label on %d%% of refused, %d%% of successful requests' % (round(100 * s.lab_blk / s.blk),
                                                                                           round(100 * s.lab_ok / max(s.ok, 1)))
    if s.cluster:
        agg['rotation'] = '%d addresses share this fingerprint, %d of them with attack signals' % (len(s.ips), len(s.attack_ips))
    order = [s.phases.get(p) for p in ('map', 'auth', 'exploit')]
    if all(order) and order[0] <= order[1] <= order[2]:
        agg['sequence3'] = 'map %s, auth %s, exploit %s' % tuple(t.strftime('%m-%d %H:%M:%S') for t in order)
    else:
        seen = sorted((t, p) for p, t in s.phases.items())
        if len(seen) >= 2:
            agg['sequence2'] = ', '.join('%s %s' % (p, t.strftime('%m-%d %H:%M:%S')) for t, p in seen)
    score = sum(WEIGHT[k] for k in s.signals) + sum(WEIGHT[k] for k in agg)
    keys = set(s.signals) | set(agg)
    if score >= 70:
        verdict = 'ARTEX-linked' if keys & TIE else 'agentic attack' if keys & AGENTIC else 'automated attack'
    else:
        verdict = 'automated attack' if score >= 40 else 'automation' if score >= 20 else 'low'
    return score, verdict, agg


# --------------------------------------------------------------------------- analysis
def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def decode(uri):
    if '%' in uri or '+' in uri:
        try:
            return unquote_plus(unquote_plus(uri))
        except Exception:
            return uri
    return uri


def analyse(files, opt):
    srcs, prints = {}, {}
    total = skipped = pruned = 0
    newest = None
    allow_cache = {}
    for path in files:
        for r, raw in records(path, opt.format):
            if opt.since and r.ts < opt.since or opt.until and r.ts > opt.until:
                continue
            ip, spoof = r.ip, '-'
            chain = [x.strip() for x in r.xff.split(',') if x.strip() not in ('', '-', 'unknown')] if r.xff not in ('', '-') else []
            if opt.source_from == 'xff' and chain:
                k = opt.xff_hops
                ip = chain[-k] if len(chain) >= k else chain[0]
                spoof = chain[0] if len(chain) > k else '-'
            elif chain:
                spoof = chain[0]
            if opt.allow_ua and any(a in r.ua for a in opt.allow_ua):
                skipped += 1
                continue
            if opt.allow_nets:
                if ip not in allow_cache:
                    allow_cache[ip] = in_nets(ip, opt.allow_nets)
                if allow_cache[ip]:
                    skipped += 1
                    continue
            total += 1
            newest = r.ts if newest is None or r.ts > newest else newest
            info = ua_info(r.ua)
            dpath = decode(r.uri)
            sids = list(info.sids)
            if PATH_ANY.search(dpath):
                sids.extend(i for i, rx in PATH_RX if rx.search(dpath))
            if info.family == 'browser' and len(r.tls) >= 10 and r.tls[0] in 'tq' and r.tls[1:3].isdigit() and r.tls[8:10] == '00':
                sids.append('tls_mismatch')
            phases = []
            if MAP_RX.search(dpath):
                phases.append('map')
            if AUTH_RX.search(dpath):
                phases.append('auth')
            if 'path_canary' in sids or 'path_artex' in sids:
                phases.append('canary')
            if EXPLOIT.intersection(sids) or TRAVERSAL.search(dpath):
                phases.append('exploit')
            tags = list(info.tags) + tags_in(dpath)
            s = srcs.get(ip)
            if s is None:
                s = srcs[ip] = State(ip)
            s.add(r, dpath, info, sids, phases, tags, spoof, raw)
            if info.trackable:
                key = r.ua if r.tls == '-' else '%s | %s' % (r.ua, r.tls)
                p = prints.get(key)
                if p is None:
                    p = prints[key] = State(key, cluster=True)
                p.add(r, dpath, info, sids, phases, tags, spoof, raw)
                p.ips[ip] += 1
                if any(x not in SHAPE for x in sids) and len(p.attack_ips) < 10000:
                    p.attack_ips.add(ip)
            if total % 200000 == 0:
                cutoff = newest.timestamp() - 3600
                for d in (srcs, prints):
                    dead = [k for k, v in d.items() if v.quiet(cutoff)]
                    for k in dead:
                        del d[k]
                    pruned += len(dead) if d is srcs else 0
    rows = []
    for s in srcs.values():
        score, verdict, agg = evaluate(s)
        rows.append({'key': s.key, 'score': score, 'verdict': verdict, 'agg': agg, 's': s, 'cluster': ''})
    rows.sort(key=lambda x: (-x['score'], -x['s'].n))
    clusters = []
    for p in prints.values():
        if len(p.ips) >= 3 and len(p.attack_ips) >= 3 and len(p.attack_ips) >= 0.5 * len(p.ips):
            score, verdict, agg = evaluate(p)
            clusters.append({'key': p.key, 'score': score, 'verdict': verdict, 'agg': agg, 's': p})
    clusters.sort(key=lambda x: -x['score'])
    by_ip = {row['key']: row for row in rows}
    for n, c in enumerate(clusters, 1):
        c['id'] = 'C%d' % n
        for ip in c['s'].ips:
            if ip in by_ip and not by_ip[ip]['cluster']:
                by_ip[ip]['cluster'] = '%s (%s)' % (c['id'], c['verdict'])
    return rows, clusters, total, skipped, pruned


# --------------------------------------------------------------------------- output
def iso(d):
    return d.strftime('%Y-%m-%d %H:%M:%S') if d else ''


def keys_of(row):
    return sorted(list(row['s'].signals) + list(row['agg']), key=lambda k: -WEIGHT[k])


def write_outputs(rows, clusters, total, skipped, out, top):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'sources.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['source_ip', 'score', 'verdict', 'requests', 'first_seen_utc', 'last_seen_utc', 'hostnames', 'user_agents', 'signals',
                    'tags', 'cluster'])
        for r in rows:
            s = r['s']
            if r['score'] > 0 or r['cluster']:
                w.writerow([r['key'], r['score'], r['verdict'], s.n, iso(s.first), iso(s.last), len(s.hosts), len(s.uas),
                            '; '.join(keys_of(r)), ' '.join(sorted(s.tags)), r['cluster']])
    with open(os.path.join(out, 'clusters.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['cluster', 'fingerprint', 'score', 'verdict', 'addresses', 'requests', 'first_seen_utc', 'last_seen_utc', 'signals', 'addresses_sample'])
        for c in clusters:
            s = c['s']
            w.writerow([c['id'], c['key'], c['score'], c['verdict'], len(s.ips), s.n, iso(s.first), iso(s.last), '; '.join(keys_of(c)),
                        ' '.join(ip for ip, _ in s.ips.most_common(50))])
    with open(os.path.join(out, 'evidence.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['entity', 'layer', 'signal', 'title', 'reported_by', 'count', 'first_seen_utc', 'detail_or_sample'])
        for r in [x for x in rows if x['score'] >= 20] + clusters:
            ent = r.get('id', r['key'])
            for k, (n, first, samples) in r['s'].signals.items():
                for smp in samples:
                    w.writerow([ent, META[k][0], k, META[k][2], META[k][3], n, iso(first), smp])
            for k, v in r['agg'].items():
                w.writerow([ent, META[k][0], k, META[k][2], META[k][3], '', '', v])
    with open(os.path.join(out, 'tags.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['tag', 'source_ip', 'first_seen_utc', 'last_seen_utc', 'hits'])
        for r in rows:
            for k, (a, b, n) in sorted(r['s'].tags.items(), key=lambda x: x[1][0]):
                w.writerow([k, r['key'], iso(a), iso(b), n])
    with open(os.path.join(out, 'report.html'), 'w', encoding='utf-8') as f:
        f.write(render_html(rows, clusters, total, skipped, top))


def slug(v):
    return v.replace(' ', '-').lower()


def render_html(rows, clusters, total, skipped, top):
    e = html.escape
    shown = [r for r in rows if r['score'] >= 20][:top]
    counts = Counter(r['verdict'] for r in rows)
    cards = ''.join('<div class="card"><b class="%s">%d</b><span>%s sources</span></div>' % (slug(k), counts.get(k, 0), k)
                    for k in ('ARTEX-linked', 'agentic attack', 'automated attack', 'automation'))
    cards += '<div class="card"><b>%d</b><span>rotating-IP clusters</span></div>' % len(clusters)

    def table(r):
        rows_ = []
        for k, (n, first, samples) in sorted(r['s'].signals.items(), key=lambda x: (META[x[0]][0], -WEIGHT[x[0]])):
            rows_.append('<tr><td><span class="layer %s">%s</span></td><td>%s<div class="src">%s</div></td><td class="num">%d</td>'
                         '<td><code>%s</code></td></tr>' % (META[k][0], META[k][0], e(META[k][2]), e(META[k][3]), n, e(samples[0][:240])))
        for k, v in r['agg'].items():
            rows_.append('<tr><td><span class="layer %s">%s</span></td><td>%s<div class="src">%s</div></td><td class="num"></td><td>%s</td></tr>'
                         % (META[k][0], META[k][0], e(META[k][2]), e(META[k][3]), e(v)))
        return '<table><tr><th>Layer</th><th>Signal</th><th>Hits</th><th>Evidence</th></tr>%s</table>' % ''.join(rows_)

    def block(r, title, sub):
        s = r['s']
        tags = ' '.join('<span class="tag">%s</span>' % e(t) for t in sorted(s.tags)) or '<span class="muted">none</span>'
        uas = ''.join('<li><code>%s</code> <span class="muted">&times;%d</span></li>' % (e(u[:170] or '(empty)'), n) for u, n in s.uas.most_common(6))
        return ('<section><div class="head"><h3>%s</h3><span class="v %s">%s</span><span class="score">score %d</span></div>'
                '<p class="muted">%s</p>%s<p class="tags"><b>Join keys</b> %s</p><details><summary>User agents</summary><ul>%s</ul></details></section>'
                % (e(title), slug(r['verdict']), e(r['verdict']), r['score'], sub, table(r), tags, uas))

    parts = []
    for c in clusters[:top]:
        s = c['s']
        sub = '%d requests from %d addresses &middot; %s &rarr; %s UTC &middot; e.g. %s' % (
            s.n, len(s.ips), iso(s.first), iso(s.last), e(', '.join(ip for ip, _ in s.ips.most_common(4))))
        parts.append(block(c, '%s  %s' % (c['id'], c['key'][:110]), sub))
    srcs = []
    for r in shown:
        s = r['s']
        sub = '%d requests &middot; %s &rarr; %s UTC &middot; %d hostname%s &middot; %d user agent%s%s' % (
            s.n, iso(s.first), iso(s.last), len(s.hosts), '' if len(s.hosts) == 1 else 's', len(s.uas), '' if len(s.uas) == 1 else 's', (' &middot; member of ' + e(r['cluster'])) if r['cluster'] else '')
        srcs.append(block(r, r['key'], sub))
    alltags = {}
    for r in rows:
        for t, (a, b, n) in r['s'].tags.items():
            x = alltags.setdefault(t, [a, b, 0, set()])
            x[0], x[1], x[2] = min(x[0], a), max(x[1], b), x[2] + n
            x[3].add(r['key'])
    tagrows = ''.join('<tr><td><span class="tag">%s</span></td><td class="num">%d</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        e(t), v[2], iso(v[0]), iso(v[1]), e(', '.join(sorted(v[3]))[:200])) for t, v in sorted(alltags.items(), key=lambda x: x[1][0]))
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARTEX hunt report</title><style>
:root{--bg:#f7f8fb;--card:#fff;--ink:#0f172a;--mut:#64748b;--line:#e5e7eb;--accent:#1d4ed8}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 22px 40px}h1{margin:0;font-size:24px;letter-spacing:-.01em}h2{font-size:16px;margin:26px 0 8px}
h3{margin:0;font-size:15px;font-family:"Cascadia Mono",Consolas,monospace;word-break:break-all}.muted{color:var(--mut)}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0 8px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:140px}
.card b{display:block;font-size:24px}.card span{color:var(--mut);font-size:12px}b.artex-linked{color:#be123c}b.agentic-attack{color:#c2410c}b.automated-attack{color:#b45309}b.automation{color:#1d4ed8}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:12px 0}
.head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.score{color:var(--mut);font-size:12px;margin-left:auto}
.v{font-size:12px;border-radius:999px;padding:2px 10px;font-weight:600}.v.artex-linked{background:#ffe4e6;color:#9f1239}.v.agentic-attack{background:#ffedd5;color:#9a3412}
.v.automated-attack{background:#fef3c7;color:#92400e}.v.automation{background:#dbeafe;color:#1e40af}.v.low{background:#f1f5f9;color:#475569}
table{border-collapse:collapse;width:100%%;margin-top:8px;font-size:13px}th,td{border-bottom:1px solid #f0f2f5;padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}td.num{text-align:right;width:44px}.src{color:var(--mut);font-size:11px}
.layer{display:inline-block;font-size:11px;font-weight:700;border-radius:5px;padding:1px 6px}.layer.L1{background:#fee2e2;color:#991b1b}.layer.L2{background:#e0e7ff;color:#3730a3}.layer.L3{background:#dcfce7;color:#166534}
code{font:12px "Cascadia Mono",Consolas,monospace;word-break:break-all;color:#334155}.tag{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:6px;padding:1px 7px;margin:2px;font:12px "Cascadia Mono",Consolas,monospace}
.tags{margin:10px 0 4px}details{margin-top:4px}summary{cursor:pointer;color:var(--accent);font-size:13px}ul{margin:6px 0;padding-left:18px}
.note{font-size:12px;color:var(--mut);margin-top:24px}
</style></head><body><main><h1>ARTEX hunt report</h1>
<div class="muted">%d requests analysed%s &middot; %d sources &middot; artex_hunter %s &middot; scores rank what to read first, they are not a verdict</div>
<div class="cards">%s</div>
<h2>Rotating-IP clusters</h2>%s
<h2>Sources</h2>%s
<h2>Join keys across sources</h2><section><table><tr><th>Tag</th><th>Hits</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>Sources</th></tr>%s</table></section>
<p class="note">ARTEX Hunting Pack &middot; thelocalh0st.com &middot; L1 strings, L2 behaviour, L3 sequence. Cross-check every hit against change tickets and approved tests.</p>
</main></body></html>''' % (total, (' (%d skipped by allow-list)' % skipped) if skipped else '', len(rows), VERSION, cards,
                            ''.join(parts) or '<p class="muted">none</p>', ''.join(srcs) or '<p class="muted">none above 20</p>',
                            tagrows or '<tr><td colspan="5" class="muted">none</td></tr>')


def main():
    global STALE_CHROME
    ap = argparse.ArgumentParser(description='Retro-hunt web, WAF and proxy logs for ARTEX-style agentic attacks (thelocalh0st.com)')
    ap.add_argument('logs', nargs='+', help='log files (.log, .json, .csv, .gz); format auto-detected per file')
    ap.add_argument('-o', '--out', default='artex_hunt', help='output folder (default artex_hunt)')
    ap.add_argument('--since', help='start date, e.g. 2026-08-01 (FBI: activity since at least August 2026)')
    ap.add_argument('--until', help='end date, e.g. 2026-11-30')
    ap.add_argument('--format', default='auto', choices=['auto', 'combined', 'json', 'csv', 'w3c', 'alb'])
    ap.add_argument('--source-from', default='remote', choices=['remote', 'xff'],
                    help='take the client from the socket address (default) or from X-Forwarded-For when you sit behind a proxy')
    ap.add_argument('--xff-hops', type=int, default=1, help='with --source-from xff: which entry from the right is the real client (1 = last)')
    ap.add_argument('--allow-ip', help='file of IPs/CIDRs to skip: your scanners, monitors, egress')
    ap.add_argument('--allow-ua', nargs='*', default=[], help='user-agent substrings to skip, e.g. an approved test')
    ap.add_argument('--stale-chrome', type=int, default=STALE_CHROME, help='Chrome major version at or below which a browser counts as stale')
    ap.add_argument('--top', type=int, default=30, help='entries to show in the console and the HTML report')
    opt = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    STALE_CHROME = opt.stale_chrome

    def day(v):
        return datetime.fromisoformat(v).replace(tzinfo=timezone.utc) if v else None
    opt.since, opt.until = day(opt.since), day(opt.until)
    opt.allow_nets = []
    if opt.allow_ip:
        with open(opt.allow_ip, encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].strip()
                if line:
                    opt.allow_nets.append(ipaddress.ip_network(line, strict=False))
    rows, clusters, total, skipped, pruned = analyse(opt.logs, opt)
    write_outputs(rows, clusters, total, skipped, opt.out, opt.top)
    print('ARTEX hunter %s | %d requests | %d sources | %d clusters%s' % (
        VERSION, total, len(rows), len(clusters), (' | %d quiet sources pruned' % pruned) if pruned else ''))
    print('%-18s %5s  %-16s %6s  %s' % ('source', 'score', 'verdict', 'reqs', 'strongest signals'))
    for r in [x for x in rows if x['score'] >= 20][:opt.top]:
        print('%-18s %5d  %-16s %6d  %s%s' % (r['key'], r['score'], r['verdict'], r['s'].n, ', '.join(keys_of(r)[:6]),
                                             ('  [%s]' % r['cluster']) if r['cluster'] else ''))
    for c in clusters[:opt.top]:
        print('%-18s %5d  %-16s %6d  %d addresses, UA "%s"' % (c['id'], c['score'], c['verdict'], c['s'].n, len(c['s'].ips), c['key'][:70]))
    print('report: %s' % os.path.join(os.path.abspath(opt.out), 'report.html'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
