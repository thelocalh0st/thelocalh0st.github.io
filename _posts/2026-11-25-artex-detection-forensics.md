---
title: "When ARTEX Knocks: Hunting an Open-Source AI Attack Framework in Your Logs"
date: 2026-11-25 00:30:00 +0530
categories: [Resources, DFIR]
comments: true
pin: true
description: "What ARTEX is, read from its own source code; why WAFs let it through; the strings, behaviours and attack order that give it away; how to check months of your own logs for it; and what to collect when it got in. With a paste-and-hunt log tool, a Python retro-hunter, Sigma, WAF, Splunk and KQL rules, 89 IOCs and an internal console finder."
image:
  path: /assets/images/artex/artex-banner.png
  alt: When ARTEX knocks. Hunting the open-source AI attack framework in your web, WAF and identity logs
tags: [artex, ai-attacks, detection-engineering, threat-hunting, waf, sigma, incident-response, web-forensics, kql, splunk]
---

> **`Mozilla/5.0 (compatible; authorized-pentest/bitrise-readonly)`**

Nobody at Bitrise hired that tester. An ARTEX agent wrote the string itself, because its system prompt tells it that it works for an *authorised penetration-testing system*. It sent 1,074 requests under that label and 12,813 more as `pentest-probe-i5938/1.0`. Requests that announce themselves as an approved test are easy to wave through.

This post is for the people who have to answer two questions this week: **did ARTEX hit us in the last few months, and how do we catch it next time?** I read the ARTEX source end to end, went through every public incident write-up I could find, and built the tools I wanted while doing it.

> **Short on time?** Paste a log into the [hunter](#paste-your-logs), run the [retro-hunt](#check-the-last-four-months) from 1 August onward, check [your own network](#is-artex-running-inside-your-network) for consoles, and fix the [foundations](#what-actually-stops-it) the agents actually used. Everything is in the [downloads](#downloads).
{: .prompt-tip }

## What ARTEX is, read from its code

ARTEX is an open-source (AGPL-3.0) framework that points a team of LLM agents at a target: a Go engine, a Next.js console and a PostgreSQL database, with an agent core called `norma`. Autumn-27 made the first commit on 26 July 2026. The original repository went offline on 8 October. The forks did not: ReversingLabs counts 11 fork families, an archive of `Hinln/ARTEX` still circulates, and the FBI mentions a paid "ARTEX PRO".

I read the last public commit (v0.3.15). Wherever this post names a file, the claim comes from that code, not from someone's summary of it.

![How one ARTEX task reaches your edge, from the source code](/assets/images/artex/artex-how-it-works.svg){: w="1200" h="640" }
*An operator types a goal. A planner splits it into intents, three workers run them in parallel, and every request leaves through a recording proxy. Each code fact on the bottom row shows up in your logs.*

The console is Chinese-first. These are the repository's own screenshots, with made-up Acme data; the red boxes are mine and mark what the text talks about.

![Exhibit 1: the ARTEX overview dashboard](/assets/images/artex/artex-ui-dashboard.webp){: w="1600" h="1000" }
*Exhibit 1: the overview. Token spend per model on top; the findings feed below: default credentials, weak JWT, IDOR, SQL injection. ARTEX repository screenshot, demo data, AGPL-3.0.*

![Exhibit 2: one task with a main agent, a planner and numbered workers](/assets/images/artex/artex-ui-sessions.webp){: w="1600" h="1000" }
*Exhibit 2: one task is a main agent, a planner and numbered workers, each chasing one intent: subdomain scan, admin default passwords, back-office enumeration, SQL injection, an IDOR on orders.*

![Exhibit 3: the exploration graph with goals, intents, facts and findings](/assets/images/artex/artex-ui-graph.webp){: w="1600" h="1000" }
*Exhibit 3: the exploration graph. Goals (目标) become intents (意图), intents produce facts (事实) and findings (漏洞). Every node gets its number from one database counter, which matters [later](#join-keys-the-number-on-everything).*

### What the prompts tell the model

The behaviour you see at your edge is written down in two prompts.

![Exhibit 4: the worker prompt and the intercept prompt, with translations](/assets/images/artex/artex-code-prompts.webp){: w="1600" h="871" }
*Exhibit 4: `agent/worker.go` and `intercept/prompt.go`, translated. Yellow lines are the ones that shape the traffic you see.*

- **"Authorised penetration-testing system."** The model believes it is on an approved engagement, so it labels its traffic honestly: `authorized-pentest`, `read-only`, `research`. That label is a confession, not a permission.
- **"A first block is not the end; exhaust every bypass."** After a 403 or a 404 the worker keeps going: encodings, other verbs, other paths, other clients. Hence the bursts of refused requests.
- **Reading is always allowed.** The model that approves tool calls lets through `cat /etc/shadow`, `.env`, source code and whole-database dumps, and anything it cannot classify is allowed by default.

![Exhibit 5: guardrail code, update check and the enrich user agent](/assets/images/artex/artex-code-guardrails.webp){: w="1600" h="936" }
*Exhibit 5: the scope ("RoE") check was removed, the built-in exfiltration rule ships disabled, the console calls GitHub as `artex-selfupdate`, and `artex-enrich/1.0` is never sent.*

> `artex-enrich/1.0` is the ARTEX user agent most write-ups quote. It is in `enrich/enrich.go`, but nothing in the last public commit calls the functions that send it. A hunt for it that comes back empty proves nothing. A hit means you are looking at another build or fork.
{: .prompt-warning }

![Exhibit 6: the intercept rules page](/assets/images/artex/artex-ui-intercept.webp){: w="1600" h="1000" }
*Exhibit 6: the only brake between the model and your network: a short list of regex and string rules. In the demo, "outbound traffic" is blocked by matching the word `exfil`.*

## Sixteen weeks in one picture

![ARTEX timeline from first commit to the FBI FLASH](/assets/images/artex/artex-timeline.svg){: w="1200" h="520" }
*Research above the line, the tool and the intrusions below it.*

The FBI's FLASH-20261113-001 (TLP:CLEAR) puts the numbers on it:

- In use against victims **since at least August 2026**, across finance, government, technology, defence, semiconductors, energy, healthcare, manufacturing, telecoms and legal.
- Some intrusions went **from first targeting to privileged access in under three hours**.
- About **67,000 people's** data taken from South Korean financial institutions; a ConnectWise Cloud Backup supply-chain compromise led to sign-in attempts against **more than 2,250** downstream tenants.
- **DeepSeek Flash** models dominate; GLM, Grok and Kimi also appear.
- **Over 1,600** exposed consoles in early November, with more behind firewalls.

> Not every ARTEX incident is a criminal one. WorkOS traced its 30 October incident to a researcher's ARTEX benchmark that escaped its sandbox. Scope the response accordingly, but respond: the requests were just as real.
{: .prompt-info }

## Why the firewall let it through

![Each request is ordinary; the source is not](/assets/images/artex/artex-waf-blindspot.svg){: w="1200" h="600" }
*Left: seven real lines from my lab replay, as a per-request rule sees them. Right: the same traffic grouped by source.*

Every published case has the same shape: the WAF was there, it just looked at one request at a time.

- **The pace is polite.** Unit 42 measured bursts of 1 to 14 requests about a second apart, then a 25 to 31 second pause while the model thinks. Volume rules never fire.
- **The exits rotate.** Eye Security counted more than 17,000 residential proxy addresses; Profero saw 31 Thordata exits across 16 networks.
- **The client-IP header lies.** Eye Security's attacker got past a rate limiter in about three minutes by sending a different client-IP header on every call. Three minutes after a WAF block, it copied a payment provider's webhook user agent and walked through.
- **The traffic is spread out.** Bitrise saw one address send 36,698 requests to more than 20 hostnames over two and a half days. Per-host limits never trip.
- **Nobody escalated.** Profero's WAF blocked requests from the start, but nobody looked for about 26 hours. By then it was roughly 9 million requests, 90 tables and 3 GB.

## Three layers that work, and one that matters more

![Four detection layers, from what ages in days to what never does](/assets/images/artex/artex-layers.svg){: w="1200" h="600" }
*Strings are cheap and short-lived, behaviour lasts longer, the order of operations lasts as long as agents plan like testers. The foundations are what the agents actually used.*

### L1: strings, and which ones are real

Most IOC lists mix three kinds of string. Treat them differently.

| String | Where it comes from | What to do with it |
|---|---|---|
| `artex-enrich/1.0` | `enrich/enrich.go:233`, never called in v0.3.15 | Block, but a miss means nothing |
| `Mozilla/5.0 (spa-api-recon)` and `(spa-api-recon spider)` | the `api-recon` skill scripts, sent when the skill runs | Block |
| `artex-selfupdate` | `selfupdate/github.go:129`, only towards `api.github.com` | Hunt in your **proxy** logs: it means a console inside your network |
| `norma/0.4`, `ReconProbe/1.0` | seen by Wiz and Bitrise, not in the ARTEX repo | Block |
| `Mozilla/5.0 (ARTEX)`, `Mozilla/5.0 (compatible; ArtExVerify/1.0)` | written by the model (Eye Security) | Block, expect variants |
| `pentest-probe-i5938/1.0`, `authorized-pentest/<you>-readonly` | written by the model, with its intent number (Bitrise) | Match the pattern, not the string |
| `ARTEX-worker/1.0` | `web/src/lib/mock/data.ts`, demo data only | Do not build rules on it |
| `python-requests/2.34.2`, `curl/7.88.1`, `Python-urllib/3.14` | normal clients the agents use | Context only, never alone |

**The zz markers are not in the code.** There is no `zz` convention anywhere in the repository. The model invents them, for one reason: before fuzzing, it asks for a page that cannot exist to learn what a 404 looks like on your site. Wiz saw `/zzz-nonexistent-xyz123` before every fuzz round; Eye Security saw `zz-notexist-*` and `artx-nonexistent`; Bitrise saw `/_i6084_probe_missing`, `/nope-1774` and `zzq-random-nonexist-9182`. The agents name their own artefacts the same way: `zzartx0000.php`, `artx_s5.php?k=x9f3c2b7e`, `ARTEX_WRITE_PROBE`, `artex-probe-12345`.

So match the habit as well as the strings: **a random-looking path that 404s, followed within seconds by a burst of 404s from the same source.**

### L2: behaviour

| Signal | Starting threshold | From | Also fires on |
|---|---|---|---|
| User-agent families per source | 3+ families and 20+ requests in one minute | Elastic | Developers behind one NAT |
| Hostnames per source | 10+ | Bitrise (20+) | Uptime monitors |
| Refused paths per source | 20+ distinct 401/403/404/405 in 5 minutes | Wiz, GTIG (500+ fuzz requests) | Your own scanner, a broken release |
| Client-IP header values | changes on most requests, 20+ distinct | Eye Security | Badly chained proxies |
| Rhythm | ~1 s apart, then 25 to 31 s pauses | Unit 42, GTIG | Some scrapers |
| Verbs per path | 5+ methods on one path | Profero | REST clients with CORS preflight |
| Labels | tester label on refused requests, gone on successful ones | Profero | Announced testers |
| Placeholders | `=XXX`, `=99999` in identifiers | Profero | Rarely anything |

None of these is a verdict on its own. Together they are hard to fake.

### L3: order

Wiz watched ARTEX work through one target like a careful tester: source maps, `/assets/config.json`, `/env.js` and the OpenAPI document first; then a canary 404; then `ValidateUserName`, `GeneratePasswordResetToken`, `register_user` and `generate_redirect_link?role=admin`; then a forged OAuth callback (`code=AAAA&state=notvalidb64!!`) and more than 60 SSO variants with an unsigned JWT in two minutes.

**Map, canary, auth probing, exploitation, in that order, from one source or one fingerprint.** Strings and addresses change between campaigns. The plan does not, because the planner prompt asks for depth before coverage.

### Join keys: the number on everything

![The intent number ARTEX writes on what it touches](/assets/images/artex/artex-intent-numbers.svg){: w="1200" h="560" }
*Every node in the exploration graph takes the next number from one counter. Bitrise's artefacts carry numbers of exactly that shape.*

Each worker runs in a folder called `tasks/<task>/i<intentID>`, in a session named `exp<N>-worker-i<intentID>`. The model sees that number and reuses it: in user agents (`pentest-probe-i5938/1.0`), paths (`/_i6084_probe_missing`) and the accounts it creates (`i871-probe`, `i1040probe`, `i3694canary`).

For an investigator that is a gift. **The same number in your WAF log, your identity provider and your cloud audit log is the same intent.** A larger number came later from the same ARTEX instance. The hunter below pulls these out into `tags.csv` so you can search everything else for them.

## Check the last four months

The FBI says "since at least August 2026", so start there. CDN and WAF logs often keep only 30 to 90 days: export them before you do anything else.

### Paste your logs

Paste or open a log file: nginx or Apache combined, JSON lines from Cloudflare, AWS WAF or Elastic, IIS W3C, or a CSV export. It runs entirely in this page. Press *Load the lab sample* to see what a hit looks like.

<div id="axh"></div>
<script src="/assets/js/artex-log-hunter.js"></script>

### Run it over everything

For months of logs, use [`artex_hunter.py`](/assets/files/artex/artex_hunter.py): one file, standard library only, Python 3.8 or newer. It reads the same formats plus AWS ALB logs and `.gz` files, and handled a million lines in about 75 seconds on my laptop.

```bash
python3 artex_hunter.py /var/log/nginx/access.log* -o hunt --since 2026-08-01

# behind a load balancer: take the client from X-Forwarded-For (1 = right-most entry)
python3 artex_hunter.py alb/*.log.gz -o hunt --source-from xff --xff-hops 1

# skip your own scanners and monitors
python3 artex_hunter.py cf/*.json -o hunt --allow-ip our_scanners.txt
```

It scores every source address and every **rotating-IP cluster** (one unusual fingerprint shared by several addresses, which is how rotating exits give themselves away), and writes `report.html`, `sources.csv`, `clusters.csv`, `evidence.csv` and `tags.csv`.

![Exhibit 7: the hunt report for the Wiz-style source in the lab](/assets/images/artex/artex-hunter-report.webp){: w="1600" h="1919" }
*Exhibit 7: one source from the lab replay. Strings (L1), behaviour (L2) and order (L3), each with the line that proves it and who reported the pattern.*

I tested it on a synthetic log that replays four published cases inside ordinary traffic. Addresses are documentation ranges; the log is in the [downloads](#downloads).

| Replayed case | Hunter | Sigma rules that fired |
|---|---|---|
| Recon to SSO forgery (Wiz) | ARTEX-linked, score 293 | user agent, probe path, unsigned JWT, hand-written UA; UA count, refused paths, map then auth then exploit |
| Labelled scanner across 22 hostnames (Bitrise) | ARTEX-linked, 223 | user agent, tester label, probe path, metadata SSRF, hand-written UA; UA count, refused paths, hostnames |
| Webshell operator with rotating client-IP header (Eye Security) | ARTEX-linked, 258 | user agent, probe path, webshell name, OAST callback; UA count |
| Eight rotating exits, one fingerprint (Profero) | each address 0 to 60 alone; as a cluster ARTEX-linked, 125 | probe path, tester label; no per-address correlation |
| A developer behind shared egress (benign) | automation, 30 | UA count (a false positive, as Elastic warns) |
| About 350 benign browsers, crawlers, monitors and a scanner | nothing above 20 | nothing |

> The rotating-exit row is the reason the hunter clusters on fingerprints: any rule that groups by source address misses an agent that changes address every few requests. If your CDN logs JA4, the hunter uses it, and flags a browser user agent on a TLS handshake that offered no ALPN.
{: .prompt-info }

### The same logic in your SIEM

[`kql_artex_hunts.kql`](/assets/files/artex/kql_artex_hunts.kql) has eleven Sentinel and Defender XDR queries; [`splunk_artex_hunts.spl`](/assets/files/artex/splunk_artex_hunts.spl) has nine Splunk searches. Every query is self-contained: copy one block and run it. They alert only on ARTEX-specific user agents; generic clients such as `python-requests` and `curl` are left out because they flood results without pointing at ARTEX. Elastic users can take Elastic's own rules (detection-rules PR #7211). The core behavioural hunt in KQL:

```kusto
// in the .kql file this query starts with the "let ArtexWeb = () {...};" block; run them together
ArtexWeb()
| where TimeGenerated > datetime(2026-08-01)
| extend Family = case(isempty(UA) or UA == "-", "empty",
                       UA matches regex @"(?i)arte?x|norma/|spa-api-recon|reconprobe", "artex",
                       UA matches regex @"(?i)^curl/", "curl",
                       UA matches regex @"(?i)python|aiohttp|^httpx/", "python",
                       UA matches regex @"(?i)^go-http-client", "go",
                       UA matches regex @"(?i)^mozilla/", "browser", "other")
| summarize Families = dcount(Family), Requests = count() by Src, Minute = bin(TimeGenerated, 1m)
| where Families >= 3 and Requests >= 20
| summarize Minutes = count(), MaxFamilies = max(Families), First = min(Minute) by Src
```

The pack also covers the places web logs do not:

- **Entra ID sign-ins** (interactive, non-interactive, service principals) from the published addresses or with ARTEX-style user agents.
- **Microsoft Graph activity** from the ConnectWise campaign addresses in the FBI FLASH.
- **New accounts and apps with agent names**: `i871-probe`, `artex-probe-NNNNN`, `qa_probe_*`.
- **Servers talking to LLM APIs**, which the FBI says to investigate when unexpected.
- **An IOC sweep** with [`artex_iocs.csv`](/assets/files/artex/artex_iocs.csv): 89 indicators, each with its source, date, confidence and a use of `block`, `hunt` or `hunt-internal`.

> Proxy and VPN exits in the IOC list are shared with innocent users. They are marked `hunt`. Block the operator servers and C2 nodes; hunt the rest.
{: .prompt-warning }

## Is ARTEX running inside your network?

An ARTEX console on your own network is a red team nobody registered, an employee trying the tool, or one of your servers turned into an attack platform. It is easy to find, because it announces itself.

![An ARTEX console announces itself: favicon, title, health endpoint, ports](/assets/images/artex/artex-fingerprint.svg){: w="1200" h="600" }
*Everything on the left comes from the source. The favicon hash matches the one ReversingLabs published; Censys reportedly found its 1,465 by the page title.*

```bash
python3 find_artex_console.py 10.0.0.0/16 -p 8787,443,80 -o consoles.csv
```

[`find_artex_console.py`](/assets/files/artex/find_artex_console.py) checks `/api/health` (no login needed), the page title and the favicon hash, and ignores look-alikes on port 8787 such as RStudio Server. Pair it with the Sigma rule for `artex -addr :8787 -proxy :8788` and the `autumn27/artex` images, and with the proxy rule for `artex-selfupdate`: a console checks GitHub for updates when someone opens it, at most every 30 minutes.

## Stop it at the edge

Rules for [Cloudflare](/assets/files/artex/cloudflare_rules.md), [AWS WAF](/assets/files/artex/aws_waf_artex_rules.json), [ModSecurity and Coraza](/assets/files/artex/modsecurity_artex.conf), [nginx](/assets/files/artex/nginx_artex.conf) and [HAProxy](/assets/files/artex/haproxy_artex.cfg). Run each in log-only mode for a few days first. In order of value:

1. **Trust a client-IP header only from your own proxy.** This one change undoes Eye Security's three-minute rate-limit bypass.
2. **Rate-limit per real client across all hostnames**, not per host.
3. **Count refused requests**, not just requests: 40 refusals in 5 minutes is a fuzzing round.
4. **Challenge self-declared testers** that are not on your approved list.
5. **Block the strings**: cheap, quick, and expect them to change.
6. **Lock the origin** so only your CDN can reach it, and stop servers calling `webhook.site`, `dnslog.cn` and `oast.*`.

```nginx
set_real_ip_from  10.0.0.0/8;   # your load balancer or CDN ranges only
real_ip_header    X-Forwarded-For;
real_ip_recursive on;

map $http_user_agent $artex_ua {
    default 0;
    "~*artex-enrich/|spa-api-recon|artex-selfupdate|^norma/[0-9]|reconprobe/|artexverify|\(artex\)" 1;
    "~*(probe|pentest|artx|artex)[-_]?i[0-9]{3,6}" 1;
}
```

## When it got in: what to collect, in order

Speed is the defining feature. At Bitrise a dormant bot account created in 2018, unused since 2022 and without 2FA signed in at 11:46:48; the first secret was read **8 minutes 41 seconds** later and the first cloud key at 10 minutes 37 seconds. Contain first.

| Order | Evidence | What ARTEX leaves there |
|---|---|---|
| 1 | CDN and WAF logs | The only record of rotating exits and forged client-IP headers. Shortest retention. |
| 2 | Identity provider | Sign-ins with the user agents above; dormant and bot accounts suddenly active. |
| 3 | Application and API logs | Password reset, registration, `role=admin` redirects, ID sweeps with placeholder values. |
| 4 | Cloud control plane | ARM `validate` and AWS `DryRun` calls across many resource types in seconds; blob write and delete pairs 330 to 400 ms apart (GTIG). |
| 5 | CI/CD and Kubernetes | Runners re-registered every 8 minutes, pods recreated within a second, names like `artx-pod` and `sink-*` (Eye Security). |
| 6 | Databases | `artx_*` tables, `LOAD DATA LOCAL INFILE`, webshells written through MySQL `general_log` (GTIG), rows such as `ARTEX_WRITE_PROBE`. |
| 7 | Mail and tickets | `artex-probe-NNNNN` reused in subjects, file names and passwords (GTIG). |
| 8 | Egress | `webhook.site`, OAST domains, Chisel and SoftEther tunnels, LLM APIs. |

Then join everything on the numbers and markers from `tags.csv`. Rotate **everything** the reachable accounts could read, including SSH keys: Bitrise revoked 919 keys and about 25,000 tokens, and five days later watched replay attempts bounce off: 19 GCP requests denied and 9 sign-ins refused.

### If you get hold of the ARTEX host

An ARTEX box keeps a better record of the intrusion than the victim does.

![Exhibit 8: the recording proxy's traffic table](/assets/images/artex/artex-ui-traffic.webp){: w="1600" h="1000" }
*Exhibit 8: the recording proxy on `:8788` logs every exchange with the target. Here: a `/.git/HEAD` read and an IDOR walk over order IDs.*

| Where | What it holds |
|---|---|
| traffic store (file tree + `_index/index.sqlite`, tables `exchanges`, `exchange_bodies`) | Every request and response sent to the targets, in plain text, including the data taken |
| PostgreSQL `explorations`, `exploration_nodes`, `findings`, `finding_traffic_bindings` | The plan: goals, intents, facts and findings, with the intent numbers seen in victim logs |
| PostgreSQL, written by `llmrec` | The full prompt and response of every model call: the operator's intent in their own words |
| `llm_profiles` | Model providers and API keys, a route to resellers such as `xcai.pro` |
| `notification_channels` | DingTalk, Feishu, WeCom, Telegram and webhook targets with their credentials |
| `tasks/<task>/i<intentID>/` | Scripts, payloads and saved responses for each intent |
| `intercept_rules`, `intercept_pending` | What the operator allowed, blocked or approved by hand |

Image it before anyone browses it. The FBI FLASH lists eight evidence categories, from console artefacts to loss and impact; use it as the checklist for the report.

## What actually stops it

ARTEX is fast, not magic. In the published cases it walked through doors that were already open:

- **Dormant accounts and bots without MFA.** The Bitrise bot account was eight years old.
- **Keys that never expire.** Every one the agent finds stays useful until someone rotates it.
- **Secrets in front-end bundles and source maps.** The `api-recon` skill downloads every webpack and Vite chunk with 20 to 24 threads; the FBI lists hard-coded admin passwords in SPA bundles among the techniques. Ship no source maps to production.
- **Trusting client-IP headers.** See above.
- **Unauthenticated and IDOR-prone APIs.** The demo findings in Exhibit 1 are the real menu.
- **Open egress.** Callbacks, webhooks and tunnels are how the agent confirms blind bugs and moves data out.

| Today | This week | This month |
|---|---|---|
| Export CDN and WAF logs back to 1 August; run the hunter | Fix client-IP trust; add cross-host and refused-request limits | Disable dormant accounts; put MFA on service and bot accounts |
| Sweep the IOC list through your SIEM | Deploy the Sigma and WAF rules in log mode, then enforce | Expiry on all keys and tokens; remove source maps and bundled secrets |
| Run the console finder on your ranges | Alert on self-declared testers you did not hire | Egress control for servers: webhooks, OAST, tunnels, LLM APIs |

## Watch

SafeBreach on the FBI FLASH and how the agents hunt for machines your EDR does not cover:

{% include embed/youtube.html id='kTev7ZbKmlM' %}

ReliaQuest on what widely available AI hacking means for defenders:

{% include embed/youtube.html id='bYq8oVn8Ro0' %}

Also worth your time: GitGuardian on [how ARTEX abuses leaked secrets](https://www.youtube.com/watch?v=EcFH9BAwg1Q), and a [walk-through of ARTEX's internals](https://www.youtube.com/watch?v=Q-t9r1GkNTI) from How The Breach Happened.

## Downloads

Everything below, plus the README and the lab log, is in one zip: [**artex-hunting-pack.zip**](/assets/files/artex/artex-hunting-pack.zip). MIT licence.

| File | What it does |
|---|---|
| [`artex_hunter.py`](/assets/files/artex/artex_hunter.py) | Retro-hunt for web, WAF and proxy logs; HTML and CSV output |
| [`find_artex_console.py`](/assets/files/artex/find_artex_console.py) | Find ARTEX consoles on networks you own |
| [Sigma rules](/assets/files/artex/artex-hunting-pack.zip) | 7 single-event, 5 correlation, 1 process and 1 proxy rule (in the zip, `sigma/`) |
| [`kql_artex_hunts.kql`](/assets/files/artex/kql_artex_hunts.kql) | 11 Sentinel and Defender XDR hunts |
| [`splunk_artex_hunts.spl`](/assets/files/artex/splunk_artex_hunts.spl) | 9 Splunk hunts |
| [`cloudflare_rules.md`](/assets/files/artex/cloudflare_rules.md), [`aws_waf_artex_rules.json`](/assets/files/artex/aws_waf_artex_rules.json), [`modsecurity_artex.conf`](/assets/files/artex/modsecurity_artex.conf), [`nginx_artex.conf`](/assets/files/artex/nginx_artex.conf), [`haproxy_artex.cfg`](/assets/files/artex/haproxy_artex.cfg) | Edge rules |
| [`artex_iocs.csv`](/assets/files/artex/artex_iocs.csv) | 89 indicators with source, date, confidence and use |
| [`lab_access.log.gz`](/assets/files/artex/lab_access.log.gz) | The synthetic test log |

## What I tested, and what I did not

- **Tested:** the hunter and the in-page tool on the synthetic replay in six formats (combined, Cloudflare JSON, AWS WAF JSON, CSV, IIS, ALB), with identical results in both; the hunter on a million lines; the console finder against a mock console and a look-alike; the Sigma rules replayed on the same log with a small evaluator.
- **Checked but not run:** the KQL, SPL, Cloudflare, AWS WAF, ModSecurity, nginx and HAProxy rules. They are written against documented field names, not tested in a live SIEM or WAF. Run them in log mode first.
- **Not tested on real victim logs.** The replay follows the published cases, but real traffic is messier. Thresholds are starting points.
- **Inference, flagged as such:** that the `i<number>` values are ARTEX intent IDs. The code makes it likely; nobody has confirmed it from an operator's database.

## References

- FBI, [FLASH-20261113-001: Threat Overview of ARTEX Autonomous Penetration Testing Framework](https://www.ic3.gov/CSA/2026/261113.pdf) (TLP:CLEAR), 13 November 2026, and WaterISAC's [summary](https://www.waterisac.org/tlpclear-fbi-warns-threat-actors-are-weaponizing-artex-ai-penetration-testing-framework)
- Wiz, [ARTEX in the wild: STORM-0940 expands targeting of IT and software vendors](https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors), 22 October 2026
- Google Threat Intelligence, [ARTEX and friends: agentic offensive frameworks](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks), 30 October 2026
- Profero, [One operator, several AI attack agents: the Ultra suite and ARTEX](https://profero.io/blog/ultra-suite-artex-ai-attack-agents/), 31 October 2026, and [Polite, methodical, machine-driven](https://profero.io/blog/ai-attack-cluster-tells), 19 November 2026
- WorkOS, [Update for the October 30th, 2026 data security incident](https://workos.com/security/bulletins/update-for-october-30th-2026-data-security-incident), 6 November 2026
- Unit 42, [ARTEX and AI-powered red-teaming tools](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/), 11 November 2026
- Eye Security, [How we defended against an AI-driven attack](https://labs.eye.security/how-we-defended-against-an-ai-driven-attack/), 12 November 2026
- Elastic Security Labs, [Agentic offensive frameworks: detecting ARTEX](https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex), 13 November 2026
- Cisco Talos, [ARTEX and beyond](https://blog.talosintelligence.com/artex-and-beyond/), 13 November 2026, with [IOCs](https://github.com/Cisco-Talos/IOCs/tree/main/2026/11)
- ReversingLabs, [Detection strategies for ARTEX and related forks](https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks), 18 November 2026
- Bitrise, [ARTEX incident report v1.6](https://bitrise.io/artex-incident-report) (TLP:CLEAR), 19 November 2026
- SafeBreach, [FBI FLASH coverage](https://www.safebreach.com/blog/artex-ai-attack-framework-fbi-flash-alert-20261113-001-safebreach-coverage/); GitGuardian, [ARTEX and public secrets](https://blog.gitguardian.com/the-agents-have-now-found-your-secrets-on-github-artex-is-abusing-public-secrets-right-now/); StepSecurity, [ARTEX and leaked secrets](https://www.stepsecurity.io/blog/artex-ai-pentesting-tool-attackers-leaked-secrets); SOCRadar, [what security teams need to know](https://socradar.io/blog/artex-ai-pentest-tool-what-security-teams-need-to-know/)
- More rule packs: [ThreatDefence](https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting), [MalwareMustDie MMD-072-2026](https://github.com/unixfreaxjp/malwaremustdie/tree/master/etc/artex-stix-osquery-sigma-kql-snort-suricata-yara)
- The code: [Wayback copy of Autumn-27/ARTEX](https://web.archive.org/web/20261004125825/https://github.com/Autumn-27/ARTEX) and the [Hinln/ARTEX fork page](https://www.artex.sh/forks/hinln-artex) on artex.sh (an unofficial tracker)

---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
