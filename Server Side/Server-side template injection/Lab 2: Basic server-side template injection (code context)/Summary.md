## Lab Information

**Topic:** SSTI

**Difficulty:** Practitioner

**Template engine:** Tornado

**Language:** Python

## Lab Description

The application embeds user input into a Tornado template used for rendering blog metadata. Unsafe template rendering enables execution of arbitrary Python expressions.

## Vulnerability Analysis

Tornado templates support both expressions and control structures. When user input is injected without validation, attackers can execute arbitrary Python code.

## Exploitation Steps

### 1. Identify the injection point
The POST parameter `blog-post-author-display` is identified as being processed by a Tornado template during page rendering.

### 2. Test for vulnerability
Arithmetic evaluation confirms server-side template execution within the Tornado engine.

### 3. Craft the payload and execute the attack
Control blocks are leveraged to import the `os` module and execute filesystem operations.

### 4. Verify successful exploitation
The target file is deleted using `os.remove`, confirming arbitrary code execution. See Lab solved.

## AppSec Perspective

### **What the underlying code might be**

```python
# handlers/account.py
import tornado.web
import tornado.template

class AccountHandler(tornado.web.RequestHandler):
    def post_change_blog_author_display(self):
        author_display = self.get_body_argument("blog-post-author-display", default="")

        # Vulnerable pattern: user-controlled content becomes part of the template source.
        template_source = (
            "<div class='comment-author'>"
            "{author_display}"
            "</div>"
        ).format(author_display=author_display)

        t = tornado.template.Template(template_source)
        rendered = t.generate(user=self.current_user)

        self.write(rendered)
```

### **Security issues enabling exploitation**

General issues:
* Untrusted input is incorporated into template rendering in a way that allows interpretation as template syntax (template injection).
* Template rendering occurs in a privileged server-side context with access to application objects and OS-level capabilities.
* Missing validation/encoding allows template metacharacters and expression delimiters to reach the interpreter.

### **How to fix it**

General recommendations:
* Avoid dynamic template construction
* Use strict variable substitution
* Escape and validate all user-controlled data

## Key Takeaways

### Lessons from Attacker perspective

* Tornado SSTI allows arbitrary Python code execution without additional sandbox escape.
* Access to standard Python classes makes filesystem and command execution straightforward.
* Tornado templates allow multi-stage payloads
* Import controls can be bypassed

### Lessons from AppSec (defender) perspective

* Template engines are programming languages, not formatting tools.
* User input must never influence template source code.
* SSTI is a design flaw, not an input validation bug.

## References

* [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)
* [https://www.tornadoweb.org/en/stable/template.html](https://www.tornadoweb.org/en/stable/template.html)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Cheat_Sheet.html)