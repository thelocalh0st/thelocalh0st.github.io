#!/usr/bin/env python3
"""find_artex_console.py - find ARTEX consoles inside networks you own.

An ARTEX console in your estate is either a red team nobody registered, an employee trying the
tool, or a server an attacker turned into an attack platform. All three need a conversation.
The checks come from the public ARTEX source (v0.3.15):

  GET /api/health   -> {"ok": true, "service": "artex", "version": "..."}   (no login needed)
  GET /             -> <title>ARTEX — 自主渗透测试控制台</title>
  GET /favicon.ico  -> Shodan-style mmh3 hash -576220750 (AntiFox fork: -1356779733, -397770841)

Default port is 8787 (the console). Port 8787 is also RStudio Server's default, which is why the
tool reads the page instead of trusting the port.

  python3 find_artex_console.py 10.20.0.0/24 build-01.corp.example -p 8787,443,80
  python3 find_artex_console.py -f our_ranges.txt -o consoles.csv

Only scan addresses you own or are authorised to test.

ARTEX Hunting Pack - Sujay Adkesar - https://thelocalh0st.com - MIT licence
Standard library only, Python 3.8+.
"""
import argparse
import base64
import csv
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

FAVICONS = {-576220750: 'ARTEX console favicon', -1356779733: 'AntiFox fork favicon', -397770841: 'AntiFox fork favicon',
            -1898746557: 'ARTEX favicon (older build)'}
TITLE_RX = re.compile(r'<title[^>]*>([^<]{0,200})</title>', re.I)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=CTX))


def mmh3_32(data, seed=0):
    """MurmurHash3 x86_32, signed, as used for Shodan favicon hashes."""
    c1, c2, h1, n = 0xcc9e2d51, 0x1b873593, seed, len(data)
    end = n & ~3
    for i in range(0, end, 4):
        k1 = int.from_bytes(data[i:i + 4], 'little')
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        h1 ^= (k1 * c2) & 0xffffffff
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1, tail = 0, n & 3
    if tail == 3:
        k1 ^= data[end + 2] << 16
    if tail >= 2:
        k1 ^= data[end + 1] << 8
    if tail >= 1:
        k1 ^= data[end]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        h1 ^= (k1 * c2) & 0xffffffff
    h1 ^= n
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(data):
    return mmh3_32(base64.encodebytes(data))


def get(url, timeout):
    req = urllib.request.Request(url, headers={'User-Agent': 'find_artex_console/1.0 (internal asset check)'})
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(262144)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536) if e.fp else b''
    except Exception:
        return None, b''


def check(host, port, timeout):
    schemes = ['https'] if port == 443 else ['http'] if port == 80 else ['http', 'https']
    for scheme in schemes:
        base = '%s://%s:%d' % (scheme, host if ':' not in host else '[%s]' % host, port)
        status, body = get(base + '/api/health', timeout)
        if status is None:
            continue
        found, version = [], ''
        try:
            j = json.loads(body.decode('utf-8', 'replace'))
            if isinstance(j, dict) and str(j.get('service', '')).lower() == 'artex':
                found.append('/api/health says service=artex')
                version = str(j.get('version', ''))
        except ValueError:
            pass
        st, page = get(base + '/', timeout)
        m = TITLE_RX.search(page.decode('utf-8', 'replace')) if page else None
        title = m.group(1).strip() if m else ''
        if 'artex' in title.lower() or '自主渗透测试控制台' in title:
            found.append('title "%s"' % title)
        st, ico = get(base + '/favicon.ico', timeout)
        fh = favicon_hash(ico) if st == 200 and ico else None
        if fh in FAVICONS:
            found.append('%s (mmh3 %d)' % (FAVICONS[fh], fh))
        return {'target': base, 'verdict': 'ARTEX' if found else 'web service, not ARTEX', 'evidence': '; '.join(found),
                'version': version, 'title': title, 'favicon_mmh3': '' if fh is None else fh}
    return None


def expand(targets, allow_large):
    for t in targets:
        t = t.strip()
        if not t or t.startswith('#'):
            continue
        t = re.sub(r'^https?://', '', t).split('/')[0] if t.startswith('http') else t
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > 65536 and not allow_large:
                sys.exit('refusing %s: larger than a /16 (use --allow-large if you really own it)' % t)
            hosts = list(net.hosts()) or [net.network_address]
            for ip in hosts:
                yield str(ip)
        except ValueError:
            yield t


def main():
    ap = argparse.ArgumentParser(description='Find ARTEX consoles inside networks you own (thelocalh0st.com)')
    ap.add_argument('targets', nargs='*', help='hosts, IPs or CIDR ranges')
    ap.add_argument('-f', '--file', help='file with one host, IP or CIDR per line')
    ap.add_argument('-p', '--ports', default='8787', help='comma-separated ports (default 8787)')
    ap.add_argument('-t', '--threads', type=int, default=32)
    ap.add_argument('--timeout', type=float, default=4.0)
    ap.add_argument('-o', '--out', help='write results to this CSV')
    ap.add_argument('--all', action='store_true', help='also list web services that are not ARTEX')
    ap.add_argument('--allow-large', action='store_true', help='allow ranges larger than a /16')
    a = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    raw = list(a.targets)
    if a.file:
        with open(a.file, encoding='utf-8') as f:
            raw += f.read().splitlines()
    if not raw:
        ap.error('give at least one target')
    ports = [int(p) for p in a.ports.split(',') if p.strip()]
    jobs = [(h, p) for h in expand(raw, a.allow_large) for p in ports]
    print('checking %d host:port pairs' % len(jobs), file=sys.stderr)
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        results = [r for r in ex.map(lambda hp: check(hp[0], hp[1], a.timeout), jobs) if r]
    hits = [r for r in results if r['verdict'] == 'ARTEX']
    for r in (results if a.all else hits):
        print('%-34s %-22s %s %s' % (r['target'], r['verdict'], r['evidence'], ('version ' + r['version']) if r['version'] else ''))
    print('%d ARTEX console(s), %d other web service(s)' % (len(hits), len(results) - len(hits)), file=sys.stderr)
    if a.out:
        with open(a.out, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=['target', 'verdict', 'evidence', 'version', 'title', 'favicon_mmh3'])
            w.writeheader()
            w.writerows(results)
    return 1 if hits else 0


if __name__ == '__main__':
    sys.exit(main())
