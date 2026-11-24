/*! ARTEX Log Hunter 1.0 | Sujay Adkesar | thelocalh0st.com | MIT */
// Paste or drop web, WAF or proxy logs and see which sources behave like ARTEX.
// A browser port of artex_hunter.py from the ARTEX Hunting Pack. Nothing leaves the page.
(function () {
  const mount = document.getElementById('axh');
  if (!mount) return;
  const SAMPLE_URL = '/assets/files/artex/lab_access.log.gz';
  const MAX_LINES = 300000;
  const STALE_CHROME = 127, STALE_FIREFOX = 102;

  // ------------------------------------------------------------------ indicators (same as the Python tool)
  const SENS = /\/\.env(?:\.\w+)?(?:\?|$)|\/\.git\/|\/\.aws\/|\/\.svn\/|\/\.ssh\/|\/\.ds_store|\/web\.config|\/appsettings(?:\.\w+)?\.json|\/actuator(?:\/|$)|\/heapdump|\/server-status|\/phpinfo|\/web-inf\/|\/etc\/(?:passwd|shadow)|\/id_rsa|\/\.npmrc|\/\.docker\/config\.json|\.(?:bak|old|orig|sql|swp)(?:\?|$)/i;
  const IND = [
    ['ua_code', 'L1', 60, 'User agent hard-coded in the ARTEX source', /artex-enrich\/|spa-api-recon|artex-selfupdate/, 'ua', 'ARTEX source'],
    ['ua_field', 'L1', 45, 'User agent reported from ARTEX intrusions', /^norma\/\d|reconprobe\/|artexverify|(?<![a-z])art(?:ex|x)(?![a-z])|rv:38\.0\) Gecko\/20100101 Firefox\/38\.0$/i, 'ua', 'Wiz, Bitrise, Eye Security'],
    ['ua_intent', 'L1', 35, 'Intent number stamped into the user agent', /(?:probe|pentest|artx|artex|audit|scan)[-_]?i\d{3,6}(?!\d)|(?<![a-z0-9])i\d{3,6}[-_]?(?:canary|probe)/i, 'ua', 'Bitrise'],
    ['ua_selflabel', 'L1', 20, 'User agent declares an authorised test', /pentest|authori[sz]ed[- ]?(?:pentest|security|research|read|scan|test|private)|research[-; ]*read-?only|\(authori[sz]ed|bounty[- ]?(?:check|hunt|research|program)|red-?team/i, 'ua', 'Bitrise, Profero'],
    ['path_artex', 'L1', 35, 'zz / artx / artex- probe path', /^\/zz|\/nr\?zz|\/artex[-_](?:[a-z]{0,2}\d{3,}|probe|canary|marker|nonexist|write|test)|(?<![a-z])artx[-_]?(?:[a-z]{0,2}\d{2,}|nonexist|probe|test|s\d)|zzartx/i, 'path', 'Eye Security, Profero'],
    ['path_canary', 'L1', 25, 'Control-404 canary before a fuzzing round', /zz+[-_]?(?:q[-_])?(?:random[-_])?no[nt][-_]?exist|nonexistent[-_]xyz|notexist[-_]xyz|_probe_missing|\/nope-\d{3,}|(?<![a-z])artx[-_]?nonexist/i, 'path', 'Wiz, Eye Security, Bitrise'],
    ['webshell', 'L1', 45, 'ARTEX-named webshell or its key', /zzartx\d*\.(?:php\d?|phtml|jsp|aspx?)|(?<![a-z])artx_s\d+\.php|[?&]k=x9f3c2b7e(?:&|$)|\/(?:cl|z|f)\d{4}a?\.jsp/i, 'path', 'Eye Security, GTIG'],
    ['jwt_none', 'L2', 30, 'Unsigned JWT (alg none)', /eyJhbGciOiJub25lI|eyJhbGciOiAibm9uZSI|eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lI|eyJhbGciOiJOT05FI|eyJhbGciOiJOb25lI/, 'path', 'Wiz'],
    ['oauth_forge', 'L2', 20, 'Forged OAuth callback', /[?&]code=A{4,}(?:&|$)|[?&]state=notvalid/i, 'path', 'Wiz'],
    ['ssrf_meta', 'L2', 30, 'Cloud metadata address in the request (SSRF)', /169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254/, 'path', 'Bitrise, FBI'],
    ['oast', 'L2', 25, 'Out-of-band callback domain in the request', /dnslog\.cn|\.oast\.(?:me|fun|pro|site|online|live)|interact\.sh|oastify\.com|burpcollaborator\.net|webhook\.site|ceye\.io|requestbin|pipedream\.net/i, 'path', 'Eye Security, GTIG, FBI'],
    ['tsql_stack', 'L2', 20, 'Stacked T-SQL in a parameter', /[?&][^=&]*=[^&]*(?:\bdeclare\s+@|\bwaitfor\s+(?:delay|time)\b|\bexec(?:ute)?\s*\(|\bexec(?:ute)?\s+(?:@|sp_|xp_|master\.))/i, 'path', 'Profero'],
    ['placeholder', 'L2', 10, 'Placeholder values in identifiers', /=(?:x{3,}|9{5,})(?:&|$)/i, 'path', 'Profero'],
    ['upload_fuzz', 'L2', 15, 'Script-extension fuzzing', /\.(?:phtml|php[3-8s]|phar|pht|pgif|shtml|jspx|jspf|ashx|asmx)(?:\?|$)|\.(?:jpe?g|png|gif)\.php|\.php\.(?:jpe?g|png|gif)(?:\?|$)/i, 'path', 'Eye Security'],
    ['sensitive', 'L2', 8, 'Sensitive-file probing', SENS, 'path', 'FBI, GTIG'],
  ];
  const EXTRA = {
    ua_malformed: ['L2', 15, 'Truncated or hand-written browser user agent', 'Wiz, Bitrise'],
    ua_stale: ['L2', 5, 'Browser version two or more years old', 'Profero'],
    tls_mismatch: ['L2', 25, 'Browser user agent on a TLS handshake without ALPN (JA4)', 'JA4 spec'],
    fam_div: ['L2', 30, '3+ user-agent families and 20+ requests in one minute', 'Elastic'],
    host_breadth: ['L2', 20, '10+ hostnames from one source', 'Bitrise'],
    fuzz_404: ['L2', 15, '20+ distinct paths refused in 5 minutes', 'Wiz, GTIG'],
    err_ratio: ['L2', 10, 'Mostly 4xx responses', 'Profero'],
    every_verb: ['L2', 10, '5+ HTTP methods on one path', 'Profero'],
    xff_rotation: ['L2', 25, 'Client-IP header changes on nearly every request', 'Eye Security'],
    cadence: ['L2', 15, 'Burst-then-pause rhythm (agent waiting on its model)', 'Unit 42, GTIG, Wiz'],
    peak_rate: ['L2', 10, '120+ requests in one minute', 'Eye Security, Profero'],
    auth_burst: ['L2', 15, '30+ auth-endpoint requests, 10+ variants, in 5 minutes', 'Wiz'],
    label_on_block: ['L2', 10, 'Tester label mostly on refused requests', 'Profero'],
    rotation: ['L2', 15, 'Same unusual fingerprint from many addresses', 'Eye Security, Profero, FBI'],
    sequence3: ['L3', 30, 'Kill-chain order: map, then auth probing, then exploitation', 'Wiz, GTIG'],
    sequence2: ['L3', 15, 'Two kill-chain phases in order', 'Wiz, GTIG'],
  };
  const META = {};
  IND.forEach(x => { META[x[0]] = [x[1], x[2], x[3], x[6]]; });
  Object.keys(EXTRA).forEach(k => { META[k] = EXTRA[k]; });
  const W = k => META[k][1];
  const TIE = new Set(['ua_code', 'ua_field', 'ua_intent', 'path_artex', 'path_canary', 'webshell']);
  const AGENTIC = new Set(['cadence', 'fam_div', 'sequence3', 'ua_selflabel', 'label_on_block', 'ua_malformed', 'tls_mismatch', 'xff_rotation', 'rotation']);
  const SHAPE = new Set(['ua_malformed', 'ua_stale']);
  const EXPLOIT = new Set(['jwt_none', 'oauth_forge', 'ssrf_meta', 'oast', 'tsql_stack', 'upload_fuzz', 'webshell']);
  const UA_IND = IND.filter(x => x[5] === 'ua'), PATH_IND = IND.filter(x => x[5] === 'path');
  const PATH_ANY = new RegExp(PATH_IND.map(x => '(?:' + x[4].source + ')').join('|'), 'i');
  const MAP_RX = /\.js\.map(?:\?|$)|\/env\.js(?:\?|$)|\/(?:assets\/)?config\.json(?:\?|$)|\/swagger|\/openapi|\/api-docs/i;
  const AUTH_RX = /validateusername|password_?reset|reset_?password|forgot_?password|register_user|\/sign_?up(?:\/|\?|$)|\/register(?:\/|\?|$)|\/confirm(?:\/|\?|$)|\/sso(?:\/|\?|$)|\/oauth|\/saml|generate_redirect_link|\/api\/v\d+\/me(?:\/|\?|$)|\/log_?in(?:\/|\?|$)|\/sign_?in(?:\/|\?|$)|\/token(?:\/|\?|$)/i;
  const TRAVERSAL = /\.\.\/|\.\.\\|\/etc\/passwd|win\.ini/;
  const LABEL = /authori[sz]ed|bounty|research|pentest|read-?only|(?<!kube-)probe/i;
  const CRAWLER = /googlebot|bingbot|duckduckbot|yandex|baiduspider|applebot|uptimerobot|pingdom|statuscake|site24x7|facebookexternalhit|slurp|semrush|ahrefs|petalbot|kube-probe|elb-healthchecker|googlehc|\+https?:\/\//i;
  const MALFORMED = [/^Mozilla\/5\.0$/, /^Mozilla\/5\.0 \((?:Windows NT|Macintosh|X11|Linux|iPhone|iPad|Android)[^)]*\)(?!.*(?:AppleWebKit|Gecko|Trident|Presto))/,
    /Chrome\/\d+(?:\.\d+){0,2}(?![\d.])/, /^(?=.*Chrome\/)(?!.*AppleWebKit\/)/, /^(?!.*Gecko\/).*\bFirefox\/\d/];
  const TAG_PRE = /zz|probe|artx|artex|i\d{3}/i;
  const TAG_RX = [
    ['intent', /(?:probe|pentest|artx|artex|audit|canary|scan|qa)[-_]?i(\d{3,6})(?!\d)/gi],
    ['intent', /(?<![a-z0-9])i(\d{3,6})[-_]?(?:canary|probe)/gi],
    ['artex-probe', /artex[-_]probe[-_](\d{3,6})(?!\d)/gi],
    ['probe', /(?<!artex-)(?<!artex_)(?<!kube-)(?<![a-z])probe[-_](\d{3,6})(?!\d)/gi],
    ['artx', /(?<![a-z])(?:zz)?artx[-_]?(\d{3,6})(?!\d)/gi],
    ['artex-q', /artex-q(\d{3,6})(?!\d)/gi],
    ['marker', /(?<![a-z0-9])(zz[a-z0-9]*(?:[-_][a-z0-9]+){0,3})/gi],
  ];

  function family(ua) {
    const u = ua.toLowerCase();
    if (!ua || ua === '-') return 'empty';
    if (/(?<![a-z])art(?:ex|x)|artexverify|norma\/|spa-api-recon|reconprobe/.test(u)) return 'artex';
    if (CRAWLER.test(ua)) return 'crawler';
    if (u.startsWith('curl/')) return 'curl';
    if (u.includes('python') || u.includes('aiohttp') || u.startsWith('httpx/')) return 'python';
    if (u.startsWith('go-http-client') || u.includes('golang')) return 'go';
    if (u.includes('boto') || u.includes('aws-cli') || u.includes('aws-sdk')) return 'aws';
    if (/fuzz faster|nuclei|sqlmap|nikto|gobuster|feroxbuster|dirbuster|wfuzz|masscan|zgrab|nessus|qualys|acunetix|burp/.test(u)) return 'scanner';
    if (u.includes('headless') || u.includes('playwright') || u.includes('phantomjs') || u.includes('puppeteer')) return 'headless';
    if (/node-fetch|axios|undici|okhttp|java\/|apache-httpclient|libwww|wget\/|powershell|winhttp|reqwest/.test(u)) return 'library';
    if (u.startsWith('mozilla/')) return 'browser';
    return 'other';
  }
  function tagsIn(text) {
    const out = [];
    if (!TAG_PRE.test(text)) return out;
    TAG_RX.forEach(([kind, rx]) => {
      for (const m of text.matchAll(rx)) {
        const v = m[1].toLowerCase();
        if (kind === 'marker' && v.length < 4) continue;
        out.push(kind + ':' + v);
      }
    });
    return out;
  }
  const uaCache = new Map();
  function uaInfo(ua) {
    let r = uaCache.get(ua);
    if (r) return r;
    const fam = family(ua);
    let shape = 'ok';
    if (fam === 'browser') {
      if (MALFORMED.some(rx => rx.test(ua))) shape = 'malformed';
      else {
        const m = ua.match(/Chrome\/(\d+)\.0\.0\.0/), f = ua.match(/Firefox\/(\d+)/);
        if ((m && +m[1] <= STALE_CHROME) || (f && +f[1] <= STALE_FIREFOX)) shape = 'stale';
      }
    }
    const sids = UA_IND.filter(x => x[4].test(ua)).map(x => x[0]);
    if (sids.includes('ua_code') && sids.includes('ua_field')) sids.splice(sids.indexOf('ua_field'), 1);
    if (shape !== 'ok') sids.push('ua_' + shape);
    r = { family: fam, shape, sids, labelled: LABEL.test(ua), tags: tagsIn(ua), trackable: !['browser', 'crawler'].includes(fam) || shape !== 'ok' };
    uaCache.set(ua, r);
    return r;
  }

  // ------------------------------------------------------------------ parsing
  const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  function parseTime(v) {
    if (v === undefined || v === null || v === '' || v === '-') return null;
    let s = String(v).trim();
    if (/^\d{9,20}(?:\.\d+)?$/.test(s)) {
      const x = parseFloat(s);
      return x > 1e17 ? x / 1e6 : x > 1e14 ? x / 1e3 : x > 1e11 ? x : x * 1000;
    }
    const m = s.match(/^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2})(\d{2}))?$/);
    if (m && m[2] in MON) {
      let t = Date.UTC(+m[3], MON[m[2]], +m[1], +m[4], +m[5], +m[6]);
      if (m[7]) { const off = (+m[8] * 60 + +m[9]) * 60000; t += m[7] === '+' ? -off : off; }
      return t;
    }
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) s = s.replace(' ', 'T') + 'Z';
    s = s.replace(/(\.\d{3})\d+/, '$1');
    const t = Date.parse(s);
    return isNaN(t) ? null : t;
  }
  const COMBINED = /^(?:([^\s:]+:\d+) )?(\S+) \S+ (?:\S+|"[^"]*") \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$/;
  const QF = /"((?:[^"\\]|\\.)*)"/g;
  const IP_LIST = /^\s*[\da-fA-F:.]+(?:\s*,\s*[\da-fA-F:.]+)*\s*$/;
  const HOST_LIKE = /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$/;
  const REQ_LINE = /^([A-Z]{3,10}) (\S+)(?: HTTP\/[\d.]+)?$/;
  const ALIASES = {
    ip: ['clientip', 'client_ip', 'client.ip', 'source.ip', 'src_ip', 'srcip', 'source_ip', 'sourceip', 'c-ip', 'c_ip', 'remote_addr', 'remoteaddr', 'remote_ip', 'httprequest.clientip', 'httprequest.remoteip', 'properties.clientip', 'clientip_s', 'src', 'ip', 'client'],
    ua: ['clientrequestuseragent', 'useragent', 'user_agent', 'user_agent.original', 'http_user_agent', 'cs(user-agent)', 'httprequest.useragent', 'httprequest.headers.user-agent', 'properties.useragent', 'useragent_s', 'requestheaders.user-agent', 'user-agent', 'agent'],
    uri: ['clientrequesturi', 'request_uri', 'requesturi', 'properties.requesturi', 'requesturi_s', 'httprequest.requesturl', 'url.original', 'url.full', 'httprequest.uri', 'uri', 'url', 'cs-uri-stem', 'uri_path', 'clientrequestpath', 'url.path', 'path', 'request'],
    query: ['httprequest.args', 'url.query', 'cs-uri-query', 'uri_query', 'clientrequestquery', 'query', 'querystring', 'args'],
    method: ['clientrequestmethod', 'method', 'http_method', 'request_method', 'requestmethod', 'httpmethod', 'cs-method', 'http.request.method', 'httprequest.httpmethod', 'httprequest.requestmethod', 'properties.httpmethod'],
    status: ['edgeresponsestatus', 'status', 'http_status', 'statuscode', 'status_code', 'response_code', 'sc-status', 'http.response.status_code', 'properties.httpstatuscode', 'properties.httpstatus', 'httprequest.status', 'responsecodesent', 'httpstatus', 'originresponsestatus'],
    host: ['clientrequesthost', 'host', 'http_host', 'hostname', 'url.domain', 'cs-host', 'x-host-header', 'properties.hostname', 'properties.host', 'httprequest.headers.host', 'site', 'server_name'],
    time: ['edgestarttimestamp', '@timestamp', 'timestamp', 'time', 'timegenerated', '_time', 'datetime', 'date', 'start_time', 'eventtime'],
    xff: ['x_forwarded_for', 'xff', 'http_x_forwarded_for', 'httprequest.headers.x-forwarded-for', 'requestheaders.x-forwarded-for', 'x-forwarded-for', 'xforwardedfor'],
    tls: ['ja4', 'ja4fingerprint', 'ja4_fingerprint', 'tls.client.ja4', 'botmanagement.ja4', 'ja3hash', 'ja3', 'ja3fingerprint', 'tls.client.ja3'],
  };
  function flatten(d, prefix, out) {
    for (const k of Object.keys(d)) {
      const key = prefix + String(k).toLowerCase(), v = d[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key + '.', out);
      else if (Array.isArray(v) && v.length && v.every(x => x && typeof x === 'object' && 'name' in x && 'value' in x)) v.forEach(h => { out[key + '.' + String(h.name).toLowerCase()] = h.value; });
      else out[key] = v;
    }
    return out;
  }
  function pick(d, f) {
    for (const k of ALIASES[f]) { const v = d[k]; if (v !== undefined && v !== null && v !== '' && v !== '-') return v; }
    return null;
  }
  function fromMapping(d) {
    let ip = pick(d, 'ip'), uri = pick(d, 'uri');
    if (ip === null || uri === null) return null;
    ip = String(ip); uri = String(uri);
    let method = pick(d, 'method');
    const m = uri.match(REQ_LINE);
    if (m) { method = method || m[1]; uri = m[2]; }
    let host = pick(d, 'host');
    if (/^https?:\/\//.test(uri)) {
      try { const u = new URL(uri); host = host || u.hostname; uri = (u.pathname || '/') + u.search; } catch (e) { /* keep */ }
    }
    const q = pick(d, 'query');
    if (q && !uri.includes('?')) uri += '?' + String(q).replace(/^\?/, '');
    let status = parseInt(pick(d, 'status'), 10);
    if (isNaN(status)) status = String(d.action || '').toUpperCase() === 'BLOCK' ? 403 : 0;
    if ((ip.match(/:/g) || []).length === 1) ip = ip.split(':')[0];
    return { ts: parseTime(pick(d, 'time')), ip, method: String(method || '-').toUpperCase(), uri, status, host: String(host || '-'),
      ua: String(pick(d, 'ua') || ''), xff: String(pick(d, 'xff') || '-'), tls: String(pick(d, 'tls') || '-') };
  }
  function jsonRecords(d, out) {
    if (Array.isArray(d)) { d.forEach(x => jsonRecords(x, out)); return out; }
    if (!d || typeof d !== 'object') return out;
    if (Array.isArray(d.records)) return jsonRecords(d.records, out);
    if (d.result && typeof d.result === 'object') d = d.result;
    if (d._source && typeof d._source === 'object') d = d._source;
    const r = fromMapping(flatten(d, '', {}));
    if (r) out.push(r);
    return out;
  }
  function parseCombined(line) {
    const m = line.match(COMBINED);
    if (!m) return [];
    const parts = m[4].split(' ');
    const [method, uri] = parts.length >= 2 ? [parts[0], parts[1]] : ['-', m[4]];
    const extra = [...(m[9] || '').matchAll(QF)].map(x => x[1]);
    let xff = '-', host = (m[1] || '-').split(':')[0];
    if (extra.length && (extra[0] === '-' || extra[0] === '' || IP_LIST.test(extra[0]))) { xff = extra.shift() || '-'; }
    extra.forEach(f => { if (HOST_LIKE.test(f) && host === '-') host = f.split(':')[0]; });
    return [{ ts: parseTime(m[3]), ip: m[2], method: method.toUpperCase(), uri, status: m[5] === '-' ? 0 : +m[5], host, ua: m[8] || '', xff, tls: '-' }];
  }
  function splitCSV(line) {
    const out = []; let cur = '', q = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
      else if (c === '"') q = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
    }
    out.push(cur);
    return out;
  }
  const KNOWN_HEADERS = new Set(['clientip', 'client_ip', 'src_ip', 'source_ip', 'c-ip', 'ip', 'useragent', 'user_agent', 'http_user_agent', 'uri', 'url', 'request_uri', 'status', '_time', 'timestamp', 'time', 'method', 'host', 'timegenerated']);
  function records(text) {
    const lines = text.split(/\r?\n/);
    const first = (lines.find(l => l.trim()) || '').trim();
    const out = [];
    let kind = 'combined';
    if (first.startsWith('#')) kind = 'w3c';
    else if (first.startsWith('[')) kind = 'jsonarray';
    else if (first.startsWith('{')) kind = 'json';
    else if (!COMBINED.test(first) && splitCSV(first).map(h => h.trim().toLowerCase()).filter(h => KNOWN_HEADERS.has(h)).length >= 2) kind = 'csv';
    if (kind === 'jsonarray') { try { jsonRecords(JSON.parse(text), out); } catch (e) { /* not JSON */ } return { kind, recs: out.filter(r => r.ts !== null).map(r => [r, JSON.stringify(r).slice(0, 400)]) }; }
    const recs = [];
    let fields = null, header = null;
    for (let i = 0; i < lines.length && recs.length < MAX_LINES; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      let rs = [];
      if (kind === 'json') { try { rs = jsonRecords(JSON.parse(line), []); } catch (e) { rs = []; } }
      else if (kind === 'w3c') {
        if (line.startsWith('#Fields:')) { fields = line.slice(8).trim().split(/\s+/).map(f => f.toLowerCase()); continue; }
        if (line.startsWith('#') || !fields) continue;
        const vals = line.includes('\t') ? line.split('\t') : line.split(' ');
        if (vals.length !== fields.length) continue;
        const d = {}; fields.forEach((f, j) => { d[f] = vals[j]; });
        if (d['cs(user-agent)']) { try { d['cs(user-agent)'] = decodeURIComponent(d['cs(user-agent)'].replace(/\+/g, ' ')); } catch (e) { /* keep */ } }
        d.time = ((d.date || '') + ' ' + (d.time || '')).trim(); delete d.date;
        const r = fromMapping(d); if (r) rs = [r];
      } else if (kind === 'csv') {
        if (!header) { header = splitCSV(line).map(h => h.trim().toLowerCase()); continue; }
        const vals = splitCSV(line);
        if (vals.length !== header.length) continue;
        const d = {}; header.forEach((h, j) => { d[h] = vals[j]; });
        const r = fromMapping(d); if (r) rs = [r];
      } else rs = parseCombined(line);
      rs.forEach(r => { if (r.ts !== null) recs.push([r, line.slice(0, 400)]); });
    }
    return { kind, recs, truncated: lines.length > MAX_LINES };
  }

  // ------------------------------------------------------------------ state and scoring
  function newState(key, cluster) {
    return { key, cluster, n: 0, first: null, last: null, uas: new Map(), hosts: new Set(), status: [0, 0, 0, 0, 0, 0], xffs: new Set(), times: [],
      signals: {}, phases: {}, tags: {}, minKey: null, minFams: new Set(), minN: 0, divMinutes: 0, divMax: 0, peak: 0, w5Key: null,
      w5Refused: new Set(), fuzzMax: 0, w5Auth: 0, w5AuthU: new Set(), authMax: [0, 0], verbs: new Map(), labBlk: 0, labOk: 0, blk: 0, ok: 0,
      ips: cluster ? new Map() : null, attackIps: cluster ? new Set() : null };
  }
  function rollMinute(s, key) {
    if (s.minKey !== null) {
      if (s.minFams.size >= 3 && s.minN >= 20) { s.divMinutes++; s.divMax = Math.max(s.divMax, s.minFams.size); }
      s.peak = Math.max(s.peak, s.minN);
    }
    s.minKey = key; s.minFams = new Set(); s.minN = 0;
  }
  function roll5(s, key) {
    if (s.w5Key !== null) {
      s.fuzzMax = Math.max(s.fuzzMax, s.w5Refused.size);
      if (s.w5Auth >= 30 && s.w5AuthU.size >= 10 && s.w5Auth > s.authMax[0]) s.authMax = [s.w5Auth, s.w5AuthU.size];
    }
    s.w5Key = key; s.w5Refused = new Set(); s.w5Auth = 0; s.w5AuthU = new Set();
  }
  function add(s, r, path, info, sids, phases, tags, spoof, raw) {
    const ts = r.ts;
    s.n++;
    if (s.first === null || ts < s.first) s.first = ts;
    if (s.last === null || ts > s.last) s.last = ts;
    if (s.uas.size < 500 || s.uas.has(r.ua)) s.uas.set(r.ua, (s.uas.get(r.ua) || 0) + 1);
    if (r.host && r.host !== '-' && s.hosts.size < 1000) s.hosts.add(r.host.toLowerCase());
    s.status[Math.min(5, Math.floor(r.status / 100))]++;
    if (spoof !== '-' && s.xffs.size < 5000) s.xffs.add(spoof);
    if (s.times.length < 20000) s.times.push(ts / 1000);
    const mk = Math.floor(ts / 60000);
    if (mk !== s.minKey) rollMinute(s, mk);
    s.minFams.add(info.family); s.minN++;
    const fk = Math.floor(ts / 300000);
    if (fk !== s.w5Key) roll5(s, fk);
    const bare = path.split('?')[0];
    if ([401, 403, 404, 405].includes(r.status) && s.w5Refused.size < 2000) s.w5Refused.add(bare);
    if (phases.includes('auth')) { s.w5Auth++; if (s.w5AuthU.size < 2000) s.w5AuthU.add(path); }
    if (r.method !== 'GET' && r.method !== 'HEAD') {
      let v = s.verbs.get(bare);
      if (!v && s.verbs.size < 2000) { v = new Set(); s.verbs.set(bare, v); }
      if (v) v.add(r.method.slice(0, 12));
    }
    sids.forEach(sid => {
      const x = s.signals[sid] || (s.signals[sid] = [0, ts, []]);
      x[0]++; x[1] = Math.min(x[1], ts); if (x[2].length < 3) x[2].push(raw);
    });
    phases.forEach(ph => { if (!(ph in s.phases) || ts < s.phases[ph]) s.phases[ph] = ts; });
    tags.forEach(t => {
      const v = s.tags[t];
      if (!v) s.tags[t] = [ts, ts, 1]; else { v[0] = Math.min(v[0], ts); v[1] = Math.max(v[1], ts); v[2]++; }
    });
    if ([401, 403, 404, 405, 429].includes(r.status)) { s.blk++; s.labBlk += info.labelled ? 1 : 0; }
    else if (r.status >= 200 && r.status < 400) { s.ok++; s.labOk += info.labelled ? 1 : 0; }
  }
  function median(a) { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; }
  function cadence(times) {
    if (times.length < 30) return null;
    const ts = times.slice().sort((a, b) => a - b), gaps = [];
    for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
    const burst = gaps.filter(g => g < 3), pauses = gaps.filter(g => g >= 20 && g <= 40).length;
    if (burst.length < 20 || pauses < 3) return null;
    const med = median(burst), share = burst.filter(g => g >= 0.5 && g <= 2).length / burst.length;
    return med >= 0.6 && med <= 1.6 && share >= 0.6 ? 'median in-burst gap ' + med.toFixed(1) + 's, ' + pauses + ' pauses of 20-40s' : null;
  }
  function everyVerb(m) {
    const unusual = [...m].filter(x => !['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(x));
    return m.size >= 5 || (m.size >= 4 && unusual.length > 0);
  }
  const fmt = ms => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
  const fmtShort = ms => new Date(ms).toISOString().slice(5, 19).replace('T', ' ');
  function evaluate(s) {
    rollMinute(s, null); roll5(s, null);
    const agg = {};
    if (s.divMinutes) agg.fam_div = s.divMinutes + ' minute(s), up to ' + s.divMax + ' user-agent families';
    if (s.hosts.size >= 10) agg.host_breadth = s.hosts.size + ' hostnames';
    if (s.fuzzMax >= 20) agg.fuzz_404 = s.fuzzMax + ' distinct paths refused in one 5-minute window';
    if (s.n >= 50 && s.status[4] / s.n >= 0.6) agg.err_ratio = Math.round(100 * s.status[4] / s.n) + '% of ' + s.n + ' requests were 4xx';
    for (const [p, m] of s.verbs) { if (everyVerb(m)) { agg.every_verb = [...m].sort().join(',') + ' (+GET/HEAD) on ' + p.slice(0, 90); break; } }
    if (!s.cluster && s.xffs.size >= 20 && s.xffs.size >= 0.5 * s.n && s.uas.size <= 5) agg.xff_rotation = s.xffs.size + ' distinct client-IP header values in ' + s.n + ' requests';
    const c = cadence(s.times); if (c) agg.cadence = c;
    if (s.peak >= 120) agg.peak_rate = s.peak + ' requests in the busiest minute';
    if (s.authMax[0]) agg.auth_burst = s.authMax[0] + ' auth requests, ' + s.authMax[1] + ' distinct, in 5 minutes';
    if (s.labBlk + s.labOk >= 5 && s.blk >= 20 && s.labBlk / s.blk > 0.1 && s.labOk / Math.max(s.ok, 1) < 0.05)
      agg.label_on_block = 'label on ' + Math.round(100 * s.labBlk / s.blk) + '% of refused, ' + Math.round(100 * s.labOk / Math.max(s.ok, 1)) + '% of successful requests';
    if (s.cluster) agg.rotation = s.ips.size + ' addresses share this fingerprint, ' + s.attackIps.size + ' of them with attack signals';
    const order = ['map', 'auth', 'exploit'].map(p => s.phases[p]);
    if (order.every(x => x !== undefined) && order[0] <= order[1] && order[1] <= order[2]) agg.sequence3 = 'map ' + fmtShort(order[0]) + ', auth ' + fmtShort(order[1]) + ', exploit ' + fmtShort(order[2]);
    else {
      const seen = Object.entries(s.phases).sort((a, b) => a[1] - b[1]);
      if (seen.length >= 2) agg.sequence2 = seen.map(([p, t]) => p + ' ' + fmtShort(t)).join(', ');
    }
    const keys = Object.keys(s.signals).concat(Object.keys(agg));
    const score = keys.reduce((a, k) => a + W(k), 0);
    let verdict;
    if (score >= 70) verdict = keys.some(k => TIE.has(k)) ? 'ARTEX-linked' : keys.some(k => AGENTIC.has(k)) ? 'agentic attack' : 'automated attack';
    else verdict = score >= 40 ? 'automated attack' : score >= 20 ? 'automation' : 'low';
    return { key: s.key, score, verdict, agg, s, keys: keys.sort((a, b) => W(b) - W(a)), cluster: '' };
  }
  function decode(u) {
    if (!/[%+]/.test(u)) return u;
    let x = u;
    for (let i = 0; i < 2; i++) { try { x = decodeURIComponent(x.replace(/\+/g, ' ')); } catch (e) { break; } }
    return x;
  }
  function analyse(text) {
    const { kind, recs, truncated } = records(text);
    const srcs = new Map(), prints = new Map();
    recs.forEach(([r, raw]) => {
      const chain = r.xff && r.xff !== '-' ? r.xff.split(',').map(x => x.trim()).filter(x => x && x !== '-' && x !== 'unknown') : [];
      const spoof = chain.length ? chain[0] : '-';
      const info = uaInfo(r.ua), path = decode(r.uri), sids = info.sids.slice();
      if (PATH_ANY.test(path)) PATH_IND.forEach(x => { if (x[4].test(path)) sids.push(x[0]); });
      if (info.family === 'browser' && r.tls.length >= 10 && /^[tq]\d\d/.test(r.tls) && r.tls.slice(8, 10) === '00') sids.push('tls_mismatch');
      const phases = [];
      if (MAP_RX.test(path)) phases.push('map');
      if (AUTH_RX.test(path)) phases.push('auth');
      if (sids.includes('path_canary') || sids.includes('path_artex')) phases.push('canary');
      if (sids.some(x => EXPLOIT.has(x)) || TRAVERSAL.test(path)) phases.push('exploit');
      const tags = info.tags.concat(tagsIn(path));
      let s = srcs.get(r.ip); if (!s) { s = newState(r.ip, false); srcs.set(r.ip, s); }
      add(s, r, path, info, sids, phases, tags, spoof, raw);
      if (info.trackable) {
        const key = r.tls === '-' ? r.ua : r.ua + ' | ' + r.tls;
        let p = prints.get(key); if (!p) { p = newState(key, true); prints.set(key, p); }
        add(p, r, path, info, sids, phases, tags, spoof, raw);
        p.ips.set(r.ip, (p.ips.get(r.ip) || 0) + 1);
        if (sids.some(x => !SHAPE.has(x)) && p.attackIps.size < 10000) p.attackIps.add(r.ip);
      }
    });
    const rows = [...srcs.values()].map(evaluate).sort((a, b) => b.score - a.score || b.s.n - a.s.n);
    const clusters = [...prints.values()].filter(p => p.ips.size >= 3 && p.attackIps.size >= 3 && p.attackIps.size >= 0.5 * p.ips.size)
      .map(evaluate).sort((a, b) => b.score - a.score);
    const byIp = new Map(rows.map(r => [r.key, r]));
    clusters.forEach((c, i) => {
      c.id = 'C' + (i + 1);
      for (const ip of c.s.ips.keys()) { const r = byIp.get(ip); if (r && !r.cluster) r.cluster = c.id + ' (' + c.verdict + ')'; }
    });
    return { kind, total: recs.length, truncated, rows, clusters };
  }

  // ------------------------------------------------------------------ UI
  const css = [
    '.axh{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--blue:#1d4ed8;--rose:#be123c;--amber:#b45309;--orange:#c2410c;--green:#15803d;',
    'background:#fff;color:var(--ink);border:1px solid var(--line);border-radius:16px;padding:22px;margin:1.5rem 0;font:14px/1.55 "Segoe UI",Inter,system-ui,sans-serif;box-shadow:0 10px 30px #0f172a0f}',
    '.axh *{box-sizing:border-box}.axh h3{margin:2px 0 0;font-size:20px;font-weight:700;color:var(--ink)}',
    '.axh .eb{font-size:12px;letter-spacing:.16em;font-weight:700;color:var(--rose)}.axh .sub{color:var(--muted);margin:4px 0 14px}',
    '.axh textarea{width:100%;min-height:150px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--soft);color:var(--ink);font:12px/1.5 "Cascadia Mono",Consolas,monospace;resize:vertical}',
    '.axh .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0 4px}',
    '.axh button,.axh label.btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;padding:7px 14px;font:600 13px "Segoe UI",system-ui,sans-serif;cursor:pointer}',
    '.axh button.go{background:var(--ink);color:#fff;border-color:var(--ink)}.axh button:disabled{opacity:.45;cursor:default}',
    '.axh label.btn input{display:none}.axh .status{color:var(--muted);font-size:12.5px}',
    '.axh .cards{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 6px}.axh .card{border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:120px;background:var(--soft)}',
    '.axh .card b{display:block;font-size:22px;line-height:1.2}.axh .card span{font-size:12px;color:var(--muted)}',
    '.axh .c-artex-linked{color:var(--rose)}.axh .c-agentic-attack{color:var(--orange)}.axh .c-automated-attack{color:var(--amber)}.axh .c-automation{color:var(--blue)}',
    '.axh h4{margin:18px 0 6px;font-size:14px;color:var(--ink)}',
    '.axh table{width:100%;border-collapse:collapse;font-size:13px;margin:0}.axh th,.axh td{text-align:left;padding:7px 8px;border-bottom:1px solid #eef1f5;vertical-align:top}',
    '.axh th{font-size:11.5px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}',
    '.axh tr.src{cursor:pointer}.axh tr.src:hover{background:var(--soft)}.axh td.ip{font:12.5px "Cascadia Mono",Consolas,monospace;white-space:nowrap}',
    '.axh .bar{height:6px;border-radius:4px;background:#eef1f5;margin-top:5px;min-width:60px}.axh .bar i{display:block;height:6px;border-radius:4px}',
    '.axh .v{display:inline-block;font-size:11.5px;font-weight:700;border-radius:999px;padding:1px 9px;white-space:nowrap}',
    '.axh .v.artex-linked{background:#ffe4e6;color:#9f1239}.axh .v.agentic-attack{background:#ffedd5;color:#9a3412}.axh .v.automated-attack{background:#fef3c7;color:#92400e}.axh .v.automation{background:#dbeafe;color:#1e40af}.axh .v.low{background:#f1f5f9;color:#475569}',
    '.axh .chip{display:inline-block;font-size:11px;border-radius:5px;padding:0 6px;margin:1px 3px 1px 0;font-weight:600}',
    '.axh .L1{background:#fee2e2;color:#991b1b}.axh .L2{background:#e0e7ff;color:#3730a3}.axh .L3{background:#dcfce7;color:#166534}',
    '.axh .tag{display:inline-block;font:11.5px "Cascadia Mono",Consolas,monospace;background:#eef2ff;color:#3730a3;border-radius:5px;padding:0 6px;margin:1px 3px 1px 0}',
    '.axh tr.ev td{background:var(--soft);padding:10px 12px}.axh tr.ev code{font:11.5px "Cascadia Mono",Consolas,monospace;word-break:break-all;color:#334155;background:none;padding:0}',
    '.axh .evrow{margin:3px 0}.axh .evrow .t{font-weight:600}.axh .muted{color:var(--muted)}',
    '.axh .note{font-size:12px;color:var(--muted);margin-top:12px}',
    '@media (max-width:640px){.axh{padding:16px}.axh .hide-sm{display:none}}',
  ].join('');
  const style = document.createElement('style'); style.textContent = css; document.head.appendChild(style);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const slug = v => v.replace(/ /g, '-').toLowerCase();

  mount.innerHTML = '<div class="axh"><div class="eb">ARTEX LOG HUNTER</div><h3>Paste a log, see who knocked</h3>' +
    '<p class="sub">nginx or Apache combined, JSON lines (Cloudflare, AWS WAF, ECS), IIS W3C or a CSV export with a header row. ' +
    'Everything runs in this page; nothing is uploaded. For months of logs use <code>artex_hunter.py</code> from the pack.</p>' +
    '<textarea spellcheck="false" placeholder="203.0.113.45 - - [11/Nov/2026:15:00:02 +0000] &quot;GET /assets/config.json HTTP/1.1&quot; 200 37125 &quot;-&quot; &quot;norma/0.4&quot;"></textarea>' +
    '<div class="row"><button class="go">Hunt</button><button class="sample">Load the lab sample</button>' +
    '<label class="btn">Open a log file<input type="file" accept=".log,.txt,.json,.jsonl,.csv,.gz"></label>' +
    '<button class="csv" disabled>Download CSV</button><span class="status"></span></div><div class="out"></div></div>';
  const $ = sel => mount.querySelector(sel);
  const ta = $('textarea'), out = $('.out'), status = $('.status'), csvBtn = $('.csv');
  let last = null;

  function chips(keys) {
    return keys.map(k => '<span class="chip ' + META[k][0] + '" title="' + esc(META[k][2] + ' (' + META[k][3] + ')') + '">' + esc(k) + '</span>').join('');
  }
  function evidence(r) {
    const lines = [];
    Object.entries(r.s.signals).sort((a, b) => W(b[0]) - W(a[0])).forEach(([k, v]) => {
      lines.push('<div class="evrow"><span class="chip ' + META[k][0] + '">' + META[k][0] + '</span><span class="t">' + esc(META[k][2]) + '</span> <span class="muted">x' + v[0] + ' &middot; ' + esc(META[k][3]) + '</span><br><code>' + esc(v[2][0].slice(0, 260)) + '</code></div>');
    });
    Object.entries(r.agg).forEach(([k, v]) => {
      lines.push('<div class="evrow"><span class="chip ' + META[k][0] + '">' + META[k][0] + '</span><span class="t">' + esc(META[k][2]) + '</span> <span class="muted">' + esc(v) + ' &middot; ' + esc(META[k][3]) + '</span></div>');
    });
    const tags = Object.keys(r.s.tags).sort().map(t => '<span class="tag">' + esc(t) + '</span>').join('') || '<span class="muted">none</span>';
    const uas = [...r.s.uas.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([u, n]) => '<code>' + esc(u.slice(0, 150) || '(empty)') + '</code> <span class="muted">x' + n + '</span>').join('<br>');
    return lines.join('') + '<div class="evrow"><span class="t">Join keys</span> ' + tags + '</div><div class="evrow"><span class="t">User agents</span><br>' + uas + '</div>';
  }
  function table(list, isCluster) {
    let h = '<table><tr><th>' + (isCluster ? 'Cluster' : 'Source') + '</th><th>Score</th><th>Verdict</th><th class="hide-sm">Requests</th><th>Signals</th><th class="hide-sm">Join keys</th></tr>';
    list.forEach((r, i) => {
      const color = { 'ARTEX-linked': '#be123c', 'agentic attack': '#c2410c', 'automated attack': '#b45309', automation: '#1d4ed8' }[r.verdict] || '#94a3b8';
      const label = isCluster ? r.id + ' <span class="muted">' + r.s.ips.size + ' addresses</span><br><code style="font-size:11px">' + esc(r.key.slice(0, 70)) + '</code>' : esc(r.key) + (r.cluster ? '<br><span class="muted" style="font-size:11px">in ' + esc(r.cluster) + '</span>' : '');
      const tags = Object.keys(r.s.tags).slice(0, 4).map(t => '<span class="tag">' + esc(t) + '</span>').join('');
      h += '<tr class="src" data-i="' + i + '"><td class="ip">' + label + '</td><td>' + r.score + '<div class="bar"><i style="width:' + Math.min(100, r.score / 3) + '%;background:' + color + '"></i></div></td>' +
        '<td><span class="v ' + slug(r.verdict) + '">' + esc(r.verdict) + '</span></td><td class="hide-sm">' + r.s.n + '</td><td>' + chips(r.keys.slice(0, 7)) + '</td><td class="hide-sm">' + tags + '</td></tr>' +
        '<tr class="ev" data-i="' + i + '" hidden><td colspan="6">' + evidence(r) + '</td></tr>';
    });
    return h + '</table>';
  }
  function render(res) {
    const shown = res.rows.filter(r => r.score >= 20).slice(0, 40);
    const counts = {};
    res.rows.forEach(r => { counts[r.verdict] = (counts[r.verdict] || 0) + 1; });
    let h = '<div class="cards">' + ['ARTEX-linked', 'agentic attack', 'automated attack', 'automation'].map(k =>
      '<div class="card"><b class="c-' + slug(k) + '">' + (counts[k] || 0) + '</b><span>' + k + '</span></div>').join('') +
      '<div class="card"><b>' + res.clusters.length + '</b><span>rotating-IP clusters</span></div></div>';
    h += '<div class="status">' + res.total.toLocaleString() + ' requests (' + res.kind + ') &middot; ' + res.rows.length.toLocaleString() + ' sources' + (res.truncated ? ' &middot; first ' + MAX_LINES.toLocaleString() + ' lines only' : '') + ' &middot; click a row for the evidence</div>';
    if (res.clusters.length) h += '<h4>Rotating-IP clusters</h4><div class="tc">' + table(res.clusters.slice(0, 10), true) + '</div>';
    h += '<h4>Sources scoring 20 or more</h4>' + (shown.length ? '<div class="ts">' + table(shown, false) + '</div>' : '<p class="muted">Nothing scored 20 or more. That is not proof of absence: check the window, the log format and whether your logs carry user agents.</p>');
    h += '<p class="note">L1 strings, L2 behaviour, L3 sequence. Scores rank what to read first; they are not a verdict. Your own scanners, monitors and announced testers will show up here.</p>';
    out.innerHTML = h;
    [['.tc', res.clusters], ['.ts', shown]].forEach(([sel, list]) => {
      const box = out.querySelector(sel);
      if (!box) return;
      box.addEventListener('click', e => {
        const tr = e.target.closest('tr.src'); if (!tr) return;
        const ev = box.querySelector('tr.ev[data-i="' + tr.dataset.i + '"]'); if (ev) ev.hidden = !ev.hidden;
      });
    });
  }
  function run(text) {
    if (!text.trim()) { status.textContent = 'Paste some log lines first.'; return; }
    status.textContent = 'Hunting...';
    setTimeout(() => {
      const t0 = performance.now();
      last = analyse(text);
      render(last);
      csvBtn.disabled = !last.rows.length;
      status.textContent = 'Done in ' + Math.round(performance.now() - t0) + ' ms.';
    }, 20);
  }
  async function readFile(file) {
    if (/\.gz$/i.test(file.name)) {
      if (!('DecompressionStream' in window)) throw new Error('this browser cannot read .gz; unzip it first');
      return new Response(file.stream().pipeThrough(new DecompressionStream('gzip'))).text();
    }
    return file.text();
  }
  $('.go').addEventListener('click', () => run(ta.value));
  $('.sample').addEventListener('click', async () => {
    status.textContent = 'Loading the lab sample...';
    try {
      const resp = await fetch(SAMPLE_URL);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      if (!('DecompressionStream' in window)) throw new Error('this browser cannot read .gz');
      const text = await new Response(resp.body.pipeThrough(new DecompressionStream('gzip'))).text();
      ta.value = text;
      run(text);
    } catch (e) { status.textContent = 'Could not load the sample: ' + e.message; }
  });
  $('input[type=file]').addEventListener('change', async e => {
    const f = e.target.files[0]; if (!f) return;
    status.textContent = 'Reading ' + f.name + '...';
    try {
      const text = await readFile(f);
      ta.value = text.length > 2000000 ? text.slice(0, 2000000) + '\n...' : text;
      run(text);
    } catch (err) { status.textContent = 'Could not read the file: ' + err.message; }
  });
  csvBtn.addEventListener('click', () => {
    if (!last) return;
    const q = v => '"' + String(v).replace(/"/g, '""') + '"';
    const lines = [['source_ip', 'score', 'verdict', 'requests', 'first_seen_utc', 'last_seen_utc', 'hostnames', 'user_agents', 'signals', 'tags', 'cluster'].join(',')];
    last.rows.filter(r => r.score > 0 || r.cluster).forEach(r => {
      lines.push([r.key, r.score, r.verdict, r.s.n, fmt(r.s.first), fmt(r.s.last), r.s.hosts.size, r.s.uas.size, r.keys.join('; '), Object.keys(r.s.tags).sort().join(' '), r.cluster].map(q).join(','));
    });
    last.clusters.forEach(c => {
      lines.push([c.id + ' ' + c.key, c.score, c.verdict, c.s.n, fmt(c.s.first), fmt(c.s.last), c.s.hosts.size, c.s.ips.size + ' addresses', c.keys.join('; '), Object.keys(c.s.tags).sort().join(' '), 'cluster'].map(q).join(','));
    });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([lines.join('\n') + '\n'], { type: 'text/csv' }));
    a.download = 'artex_hunt_sources.csv';
    document.body.appendChild(a); a.click(); a.remove();
  });
})();
