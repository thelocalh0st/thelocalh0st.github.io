# Cloudflare rules for ARTEX-style traffic

ARTEX Hunting Pack, Sujay Adkesar, https://thelocalh0st.com

Paste each expression into **Security > WAF > Custom rules** (or the rate limiting rules tab)
with the expression editor. Start every rule as **Log** for a few days, read what it caught,
then switch the action. `matches` (regex) needs a Business or Enterprise plan; every other rule
here works on all plans. The JA4 rule needs Bot Management (Enterprise).

Create an IP list called `approved_testers` first (Manage Account > Configurations > Lists) with
the addresses of testers you have actually hired.

## 1. Strings from the ARTEX code and from published intrusions: Block

```
(http.user_agent contains "artex-enrich/")
or (http.user_agent contains "spa-api-recon")
or (http.user_agent contains "artex-selfupdate")
or starts_with(http.user_agent, "norma/")
or (http.user_agent contains "ReconProbe/")
or (http.user_agent contains "ArtExVerify")
or (http.user_agent contains "(ARTEX)")
or (lower(http.user_agent) contains "pentest-probe-i")
```

## 2. Probe paths, canaries and webshell names: Block

Follows Profero's rule: block `/zz*`, `/artex-*` and `/nr?zz*`, never a bare `/nr`.

```
starts_with(http.request.uri.path, "/zz")
or (lower(http.request.uri.path) contains "/artex-")
or (lower(http.request.uri.path) contains "zzartx")
or (lower(http.request.uri.path) contains "/artx_s")
or (lower(http.request.uri.path) contains "artx-nonexist")
or (lower(http.request.uri.path) contains "_probe_missing")
or (http.request.uri.path eq "/nr" and starts_with(http.request.uri.query, "zz"))
or (http.request.uri.query contains "k=x9f3c2b7e")
```

## 3. Self-declared testers you did not hire: Managed Challenge

The label is the model being honest about its prompt, not an authorisation.

```
(
  lower(http.user_agent) contains "pentest"
  or lower(http.user_agent) contains "authorized-"
  or lower(http.user_agent) contains "authorised-"
  or lower(http.user_agent) contains "(authorized"
  or lower(http.user_agent) contains "read-only"
  or lower(http.user_agent) contains "readonly"
  or lower(http.user_agent) contains "security-research"
  or lower(http.user_agent) contains "bounty"
)
and not ip.src in $approved_testers
```

## 4. Forged tokens, SSRF and callbacks in the request: Block

```
(http.request.uri.query contains "eyJhbGciOiJub25lI")
or (http.request.uri.query contains "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lI")
or any(http.request.headers["authorization"][*] contains "eyJhbGciOiJub25lI")
or (http.request.uri.query contains "state=notvalid")
or (url_decode(http.request.uri.query) contains "169.254.169.254")
or (lower(url_decode(http.request.uri.query)) contains "metadata.google.internal")
or (lower(url_decode(http.request.uri.query)) contains "dnslog.cn")
or (lower(url_decode(http.request.uri.query)) contains ".oast.")
or (lower(url_decode(http.request.uri.query)) contains "webhook.site")
```

## 5. Hand-written browser strings: Managed Challenge

Real Chrome always sends `AppleWebKit/`. A bare `Mozilla/5.0` is not a browser.

```
(http.user_agent contains "Chrome/" and not http.user_agent contains "AppleWebKit/")
or http.user_agent eq "Mozilla/5.0"
or (http.user_agent matches "Chrome/[0-9]+(\\.[0-9]+){0,2}$")
```

## 6. Browser user agent on a non-browser TLS stack (Enterprise Bot Management): Managed Challenge

Every real browser offers ALPN. JA4 records "00" in characters 9-10 when no ALPN was sent, which
is what python-requests and urllib do.

```
http.user_agent contains "Mozilla/5.0"
and substring(cf.bot_management.ja4, 8, 10) eq "00"
and not cf.bot_management.verified_bot
```

## Rate limiting rules

| Name | If incoming requests match | Count by | Limit | Action |
|---|---|---|---|---|
| auth-burst | `http.request.uri.path matches "(?i)^/(api/)?(v[0-9]+/)?(login\|signin\|sign_in\|sso\|oauth\|saml\|token\|register\|signup\|forgot_password\|password)"` | IP (add JA4 on Enterprise) | 20 per 1 minute | Managed Challenge, 10 min |
| refused-paths | `true`, with counting expression `http.response.code in {401 403 404 405}` | IP | 40 per 5 minutes | Block, 1 hour |
| zone-wide | `true` (counts across every hostname in the zone) | IP | 1,500 per 10 minutes | Managed Challenge |

The zone-wide rule is the one Bitrise needed: one address spread 36,698 requests over 20+
hostnames, so no per-host limit ever fired. Counting expressions on response codes depend on
your plan; check the rate limiting docs for yours.

## The fix that is not a rule

Make your origin accept traffic only from Cloudflare (Authenticated Origin Pulls or a tunnel),
and make the application read the client address from `CF-Connecting-IP` only. Eye Security's
attacker beat a rate limiter in about three minutes by sending a different client-IP header on
every call.
