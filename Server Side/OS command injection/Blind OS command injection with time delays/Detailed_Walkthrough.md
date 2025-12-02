

## 1. Initial reconnaissance
Navigate to the `/feedback` page and observed a typical feedback form with fields:
- `name`
- `email`
- `subject`
- `message`

Inspecting the HTML showed that the form submits a POST request to `/feedback/submit` and includes a hidden CSRF token. The lab description mentioned a blind OS command injection in the feedback function, so focus on this endpoint.

## 2. Testing methodology
Because the vulnerability is blind (no command output in the response), chose a **timing-based** approach.

Steps:
1. Intercept `POST /feedback/submit` in Burp and sent it to Intruder.
2. Configure **Sniper** attack type.
3. Mark each of the parameters `name`, `email`, `subject`, `message` as possible injection points (one at a time).
4. Select a payload list containing time-based OS command injection payloads, such as:
   - `$(sleep 5)`
   - `;sleep 5;`
   - `&& sleep 5 &&`

The goal is to find which parameter, when modified, caused a noticeable delay in the server’s response.

## 3. Payload construction
To keep things simple and robust in form-encoded requests, use payloads like:

- `$(sleep 5)` and `$(sleep 10)`  
  When sent in the body as plain text, `requests` or the browser URL-encodes spaces as `+`, and the server decodes them back to spaces, making the shell interpret `sleep 5` correctly.

In Intruder:
- Inject `$(sleep 5)` into each parameter individually.
- Observe the response times in the Intruder results table.

The critical observation:
- When the payload was injected into the **`email`** field, the response time increased by about 5 seconds.
- Injecting the same payload into the other fields did not significantly change response time.

This identified `email` as the vulnerable parameter.

## 4. Completing the attack
To clearly demonstrate exploitation, send a manual request (or via Repeater) using:

- Endpoint: `POST /feedback/submit`
- Body (example):
  ```
  csrf=<valid_token>&name=test&email=email@example.com$(sleep 10)&subject=test&message=test
  ```

The server responded after approximately 10 seconds, confirming that:

- The `sleep 10` command was executed on the server.
- Achieved blind OS command injection via the `email` parameter.

In a real-world context, this primitive timing proof-of-concept can be extended to execute more complex commands or to pivot to other systems, but for the lab, demonstrating the delay is sufficient to mark the vulnerability as exploited.

## Results and observations

It is important to mix all combinations of possible payloads. If we pentest black-box and don’t see the source code, we never know how the application exactly serves files, what extensions are allowed and filtered, what exact path would work this time.