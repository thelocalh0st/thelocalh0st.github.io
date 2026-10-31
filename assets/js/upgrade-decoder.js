/*! Upgrade History Decoder 1.0 | Sujay Adkesar | thelocalh0st.com | MIT */
// Paste the one-liner output (or reg query output) and get the host's upgrade history,
// evidence floor and the traps that come with it. Everything runs in the browser.
(function () {
  var mount = document.getElementById('upd');
  if (!mount) return;

  var ONE_LINER = "Get-ChildItem HKLM:\\SYSTEM\\Setup | ? PSChildName -like 'Source OS*' | % { $p = Get-ItemProperty $_.PSPath; '{0}|{1}|{2}|{3}|{4}' -f $_.PSChildName,$p.CurrentBuild,$p.UBR,$p.DisplayVersion,$p.InstallDate }; $c = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; 'CURRENT|{0}|{1}|{2}|{3}' -f $c.CurrentBuild,$c.UBR,$c.DisplayVersion,$c.InstallDate";
  var SAMPLE = [
    'Source OS (Updated on 1/29/2025 20:25:13)|22631|4751|23H2|1665512186',
    'Source OS (Updated on 1/31/2026 19:53:26)|26100|6584|24H2|1749659552',
    'Source OS (Updated on 10/11/2022 22:43:24)|22000|1042|21H2|1634835063',
    'Source OS (Updated on 10/21/2021 21:46:43)|19043|1288|21H1|1617943386',
    'Source OS (Updated on 6/11/2025 08:51:16)|26100|4061|24H2|1739080211',
    'CURRENT|26200|9711|25H2|1770464783'].join('\n');
  var NAMES = { 10240: 'Windows 10 1507', 10586: 'Windows 10 1511', 14393: 'Windows 10 1607', 15063: 'Windows 10 1703', 16299: 'Windows 10 1709',
    17134: 'Windows 10 1803', 17763: 'Windows 10 1809', 18362: 'Windows 10 1903', 18363: 'Windows 10 1909', 19041: 'Windows 10 2004',
    19042: 'Windows 10 20H2', 19043: 'Windows 10 21H1', 19044: 'Windows 10 21H2', 19045: 'Windows 10 22H2', 22000: 'Windows 11 21H2',
    22621: 'Windows 11 22H2', 22631: 'Windows 11 23H2', 26100: 'Windows 11 24H2', 26200: 'Windows 11 25H2', 26300: 'Windows 11 26H2' };

  var css = [
    '.upd{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--blue:#1d4ed8;--amber:#b45309;--rose:#be123c;--green:#15803d;',
    'background:#fff;color:var(--ink);border:1px solid var(--line);border-radius:16px;padding:22px;margin:1.5rem 0;font:14px/1.55 "Segoe UI",Inter,system-ui,sans-serif;box-shadow:0 10px 30px #0f172a0f}',
    '.upd *{box-sizing:border-box}.upd h3{margin:2px 0 0;font-size:20px;font-weight:700;color:var(--ink)}',
    '.upd .eb{font-size:12px;letter-spacing:.16em;font-weight:700;color:var(--blue)}',
    '.upd .sub{color:var(--muted);margin:4px 0 14px}',
    '.upd .cmd{display:flex;gap:8px;align-items:stretch;margin-bottom:10px}',
    '.upd .cmd code{flex:1;display:block;background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:9px 12px;font:12px/1.5 "Cascadia Mono",Consolas,Menlo,monospace;color:#334155;white-space:nowrap;overflow-x:auto}',
    '.upd button{font:inherit;cursor:pointer;border-radius:10px;padding:7px 14px;border:1px solid #cbd5e1;background:#fff;color:var(--ink);font-size:13px;white-space:nowrap}',
    '.upd button.primary{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:600}',
    '.upd button:hover{filter:brightness(.96)}',
    '.upd textarea{width:100%;min-height:118px;border:1px solid #cbd5e1;border-radius:10px;padding:10px 12px;font:12px/1.5 "Cascadia Mono",Consolas,Menlo,monospace;color:var(--ink);background:#fff;resize:vertical}',
    '.upd .row{display:flex;gap:8px;margin:10px 0 4px;flex-wrap:wrap}',
    '.upd .out{margin-top:14px}',
    '.upd .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:14px}',
    '.upd .card{border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:var(--soft)}',
    '.upd .card b{display:block;font-size:17px;color:var(--ink)}.upd .card span{font-size:12px;color:var(--muted)}',
    '.upd .card.warn{background:#fffbeb;border-color:#fcd34d}.upd .card.warn b{color:var(--amber)}',
    '.upd .card.ok{background:#f0fdf4;border-color:#bbf7d0}.upd .card.ok b{color:var(--green)}',
    '.upd ol{list-style:none;margin:0;padding:0;border-left:2px solid var(--line);margin-left:8px}',
    '.upd li{position:relative;padding:4px 0 12px 18px}',
    '.upd li:before{content:"";position:absolute;left:-7px;top:9px;width:12px;height:12px;border-radius:50%;background:#fff;border:2px solid var(--blue)}',
    '.upd li.first:before{border-color:var(--green);background:var(--green)}.upd li.cur:before{border-color:var(--amber);background:var(--amber)}',
    '.upd li.rep:before{border-color:#94a3b8}',
    '.upd li .t{font-weight:600}.upd li .m{color:var(--muted);font-size:12.5px}',
    '.upd .tag{display:inline-block;font-size:11px;font-weight:700;border-radius:999px;padding:1px 8px;margin-left:6px;vertical-align:1px}',
    '.upd .tag.g{background:#dcfce7;color:var(--green)}.upd .tag.a{background:#fef3c7;color:var(--amber)}.upd .tag.s{background:#e2e8f0;color:#475569}',
    '.upd .notes{margin:6px 0 0;padding-left:18px;color:#334155}.upd .notes li{padding:2px 0;border:0}',
    '.upd .notes li:before{display:none}',
    '.upd .err{color:var(--rose)}',
    '@media (max-width:560px){.upd{padding:16px}.upd .cmd{flex-direction:column}}'
  ].join('');
  var st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function d(ts) { return new Date(ts * 1000); }
  function fmt(dt) { return dt ? dt.toISOString().slice(0, 16).replace('T', ' ') + 'Z' : '?'; }
  function days(a, b) { return Math.round((b - a) / 86400000); }
  function span(n) { return n >= 365 ? (n / 365).toFixed(1) + ' years' : n + ' days'; }
  function name(b) { return NAMES[b] || ('build ' + b); }

  function parse(text) {
    var olds = [], cur = null, m;
    text.split(/\r?\n/).forEach(function (line) {
      var p = line.trim().split('|');
      if (p.length >= 5 && /^Source OS/i.test(p[0])) olds.push({ key: p[0], build: +p[1], ubr: p[2], ver: p[3], inst: +p[4] });
      else if (p.length >= 5 && p[0] === 'CURRENT') cur = { build: +p[1], ubr: p[2], ver: p[3], inst: +p[4] };
    });
    if (!olds.length) { // reg query output: key headers followed by values
      var k = null;
      text.split(/\r?\n/).forEach(function (line) {
        if ((m = line.match(/\\(Source OS \(Updated on [^)]+\))\s*$/i))) { k = { key: m[1] }; olds.push(k); return; }
        if (/^HKEY_/i.test(line.trim())) { k = null; return; }
        if (!k) return;
        if ((m = line.match(/^\s+(CurrentBuild|UBR|DisplayVersion|InstallDate)\s+REG_\w+\s+(\S+)/i))) {
          var v = m[2]; if (/^0x/i.test(v)) v = parseInt(v, 16);
          if (/CurrentBuild/i.test(m[1])) k.build = +v; else if (/UBR/i.test(m[1])) k.ubr = String(v);
          else if (/DisplayVersion/i.test(m[1])) k.ver = v; else k.inst = +v;
        }
      });
    }
    olds = olds.filter(function (o) { return o.inst; }).sort(function (a, b) { return a.inst - b.inst; });
    olds.forEach(function (o) { var mm = o.key.match(/Updated on (\d+)\/(\d+)\/(\d{4}) (\d\d:\d\d)/); o.began = mm ? mm[3] + '-' + ('0' + mm[1]).slice(-2) + '-' + ('0' + mm[2]).slice(-2) + ' ' + mm[4] : ''; });
    return { olds: olds, cur: cur };
  }

  function render(text) {
    var out = mount.querySelector('.out');
    var r = parse(text);
    if (!r.olds.length) {
      out.innerHTML = '<p class="err">No Source OS records found. Paste the one-liner output (lines starting with <code>Source OS (Updated on</code>), or <code>reg query</code> output of those keys. No records at all means this OS was never upgraded in place.</p>';
      return;
    }
    var first = r.olds[0], last = r.cur ? d(r.cur.inst) : null, now = new Date();
    var since = last ? days(last, now) : null;
    var h = '<div class="cards">' +
      '<div class="card ok"><b>' + fmt(d(first.inst)).slice(0, 10) + '</b><span>first install on record (' + esc(name(first.build)) + ')</span></div>' +
      '<div class="card warn"><b>' + (last ? fmt(last).slice(0, 10) : '?') + '</b><span>InstallDate says this. It is the last upgrade: your evidence floor</span></div>' +
      '<div class="card"><b>' + r.olds.length + '</b><span>in-place upgrades / reinstalls</span></div>' +
      '<div class="card' + (since !== null && since > 10 ? ' warn' : '') + '"><b>' + (since !== null ? since + ' days' : '?') + '</b><span>since the last upgrade' + (since !== null && since > 10 ? ': Windows.old is probably gone' : ': grab Windows.old now') + '</span></div></div><ol>';
    r.olds.forEach(function (o, i) {
      var next = r.olds[i + 1] || r.cur;
      var lived = next ? days(d(o.inst), d(next.inst)) : null;
      var same = next && next.build === o.build;
      h += '<li class="' + (i === 0 ? 'first' : same ? 'rep' : '') + '"><div class="t">' + esc(name(o.build)) + ' <span class="m">' + o.build + '.' + esc(o.ubr || '?') + '</span>' +
        (i === 0 ? '<span class="tag g">first install</span>' : '') + '</div><div class="m">installed ' + fmt(d(o.inst)) + (lived !== null ? ', lived ' + span(lived) : '') + '</div>' +
        (next ? '<div class="m">upgrade began ' + esc(o.began) + ' local' + (o.began ? ', finished ' + fmt(d(next.inst)) : '') +
          (same ? ' <span class="tag s">same build: repair / reinstall</span>' : '') + '</div>' : '') + '</li>';
    });
    if (r.cur) h += '<li class="cur"><div class="t">' + esc(name(r.cur.build)) + ' <span class="m">' + r.cur.build + '.' + esc(r.cur.ubr) + '</span><span class="tag a">current</span></div><div class="m">InstallDate ' + fmt(last) + '</div></li>';
    h += '</ol><ul class="notes">' +
      '<li>Prefetch, BAM, PCA, most event logs, setupapi logs and the live USBSTOR / Enum tree start at <b>' + (last ? fmt(last) : 'the last upgrade') + '</b> after a media upgrade. No entry before it means <i>not recorded</i>, not <i>did not happen</i>.</li>' +
      '<li>Before that date, go to what carries over (jump lists, LNK, browser history, SRUM, UserAssist values) and to the second chances: DeviceMigration, NetworkList, Windows.old.</li>' +
      '<li>The Source OS key names are local time; InstallDate is UTC. Their LastWrite times are reset by every upgrade, so ignore them.</li></ul>';
    out.innerHTML = h;
  }

  mount.className = 'upd';
  mount.innerHTML = '<div class="eb">UPGRADE HISTORY DECODER</div><h3>When was this box really installed?</h3>' +
    '<p class="sub">Run this on the host (PowerShell, Live Response, any remote shell), paste the output below. Decoded in your browser; nothing is sent anywhere.</p>' +
    '<div class="cmd"><code>' + esc(ONE_LINER) + '</code><button data-a="copy">Copy</button></div>' +
    '<textarea spellcheck="false" placeholder="Source OS (Updated on 1/31/2026 19:53:26)|26100|6584|24H2|1749659552&#10;CURRENT|26200|9711|25H2|1770464783"></textarea>' +
    '<div class="row"><button class="primary" data-a="go">Decode</button><button data-a="sample">Load my lab laptop</button></div><div class="out"></div>';
  var ta = mount.querySelector('textarea');
  mount.addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    if (b.dataset.a === 'copy') {
      var done = function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1400); };
      if (navigator.clipboard) navigator.clipboard.writeText(ONE_LINER).then(done, done); else done();
    } else if (b.dataset.a === 'sample') { ta.value = SAMPLE; render(SAMPLE); }
    else if (b.dataset.a === 'go') render(ta.value);
  });
})();
