## Lab Information

**Topic:** SSTI

**Difficulty:** Practitioner

**Template engine:** Django

**Language:** Python

## Lab Description

User-controlled template editing exposes internal Django context objects. This enables disclosure of sensitive configuration data.

## Vulnerability Analysis

Django templates restrict code execution but allow access to context variables. When sensitive objects are exposed, attackers can retrieve secrets.

## Exploitation Steps

### 1. Identify the injection point
Template editing functionality reveals direct control over rendered content.

### 2. Test for vulnerability
Syntax errors confirm the Django template engine.

### 3. Craft the payload and execute the attack
Context variables are enumerated using debug functionality.

### 4. Verify successful exploitation
The `SECRET_KEY` value is retrieved from the template context, completing the lab. Submit result and see Lab solved.

## Theory box

### What are Django templates?

Django templates are not Python. This is the most important premise.

Django’s template language (DTL):
- is intentionally not Turing-complete
- does not allow arbitrary Python execution
- is designed for presentation, not logic
- enforces a sandboxed expression resolver

So Django SSTI is **NOT** the same class of vulnerability as:
- Jinja2 SSTI
- FreeMarker SSTI
- ERB SSTI

In Django, the realistic impact is usually I**nformation Disclosure**, not RCE.

### {{ ... }} vs {% ... %} - execution model
**{{ ... }} — Variable resolution and output**
- Resolves a variable from the template context
- Applies:
    1. dictionary lookup
    2. attribute access
    3. list indexing
- Calls only explicitly allowed methods
- Outputs the result as text

**{% ... %} - template tags (control & utilities)**
- Executes template tags (template logic, not Python code)
- Tags are:
    - predefined
    - whitelisted
    - registered in the template engine

Examples:
- {% if %}
- {% for %}
- {% include %}
- {% debug %}

### Why {% debug %} changes everything?
From Django’s own documentation:

> The {% debug %} tag outputs a complete dump of the current context.
> 

That includes:
- all context variables
- request object (often)
- settings (if exposed)
- user/session data
- internal framework objects

This is intentional behaviour, meant for development only.  Without debug directive settings is not in the template context, Django does not expose it by default.
However, {% debug %}:
1. Dumps the entire context
2. Often introduces settings into scope
3. Removes the usual “what is reachable” uncertainty

So this is not a sandbox bypass, it is context expansion.

## AppSec Perspective

### **What the underlying code might be**

```python
# app/views.py
from django.conf import settings
from django.shortcuts import render
from django.template import Template, Context


def product_template_preview(request):
    # User-controlled template editing capability.
    user_template = request.POST.get("template", "")

    # Vulnerable pattern: sensitive objects included in context.
    ctx = Context({
        "product": get_product(request.POST.get("product_id")),
        "settings": settings,
        "user": request.user,
    })

    rendered = Template(user_template).render(ctx)
    return render(request, "preview.html", {"rendered": rendered})


def get_product(product_id):
    # Simplified placeholder for ORM retrieval.
    return {"price": 100, "name": "Example"}
```

### **Security issues enabling exploitation**
General issues:
* USER CONTROLLED TEMPLATES
* Untrusted input is incorporated into template rendering in a way that allows interpretation as template syntax (template injection).
* Template rendering occurs in a privileged server-side context with access to application objects and OS-level capabilities.
* Missing validation/encoding allows template metacharacters and expression delimiters to reach the interpreter.

Engine-specific issues:
* Logic-capable template engine.
* Sensitive objects in context.
* Debug mode exposing stack traces.
* No template sandboxing.

### **How to fix it**
General recommendations:
* Avoid dynamic template construction.
* Use strict variable substitution.
* Escape and validate all user-controlled data.
* REMOVE USER CONTROLLED TEMPLATES FUNCTIONALITY, but if it's not possible due to the business reasons see below

Engine-specific recommendations:
* Remove sensitive objects from context.
* Disable template editing.
* Turn off debug features.

## Key Takeaways

### Lessons from Attacker perspective

* Django SSTI often leads to information disclosure.
* Secrets provide high-impact leverage.

### Lessons from AppSec (defender) perspective

* Template engines are programming languages, not formatting tools.
* User input must never influence template source code.
* SSTI is a design flaw, not an input validation bug.
* If user input is parsed by the template engine, SSTI is inevitable: try to avoid it.

## References

* [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)
* [https://docs.djangoproject.com/en/stable/topics/templates/](https://docs.djangoproject.com/en/stable/topics/templates/)
* [https://owasp.org/www-community/attacks/Server_Side_Template_Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)
* [A cheatsheet with Django reading secret payload](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)