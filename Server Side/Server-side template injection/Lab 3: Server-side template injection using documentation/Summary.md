## Lab Information

**Topic:** SSTI

**Difficulty:** Practitioner

**Template engine:** FreeMarker

**Language:** Java

## Lab Description

The application processes user-supplied templates using FreeMarker. Dangerous utility classes are exposed, enabling execution of operating system commands.

## Vulnerability Analysis

FreeMarker allows object instantiation and method invocation. When unsafe utility classes are accessible, attackers can achieve remote code execution.

## Exploitation Steps

### 1. Identify the injection point
The ability of template editing takes place after log-in. Template syntax errors reveal FreeMarker as the underlying engine.

### 2. Test for vulnerability
The FreeMarker version is retrieved using built-in variables.

### 3. Craft the payload and execute the attack
The `Execute` utility class is instantiated to run system commands.

### 4. Verify successful exploitation
A shell command is executed to remove the target file, confirming exploitation. See Lab solved.

## Theory box

FreeMarker is **not a general Java interpreter**. It is:

- a **template language** with its own AST
- evaluated by the FreeMarker engine
- operating over:
    - a **data model** (objects explicitly exposed)
    - **built-ins** and **template language constructs**
    - **utility classes** (optionally enabled)

Key consequence: You never execute arbitrary Java statements. You only execute FreeMarker expressions that delegate to Java objects. This distinction is critical.

But why the payload works?

**Step-by-step (engine view)**

1. "freemarker.template.utility.Execute"
    - A **string literal**, not Java code
2. ?new()
    - A **FreeMarker built-in**
    - Interpreted as:
        
        > “Load this class and instantiate it using reflection”
        > 
3. ("cat /etc/passwd")
    - Calls the instance as a function
    - Delegates to:
    `Execute.exec(String command)`

It’s possible because:

- freemarker.template.utility.Execute is:
    - On the classpath
    - Not blocked by the **ObjectWrapper**
- ?new is enabled
- No sandbox (or an old / misconfigured one) is in place

Technically this is **not Java execution**, it is **abusing exposed Java APIs through FreeMarker’s expression engine**.

## AppSec Perspective

### **What the underlying code might be**

```java
// src/main/java/com/acme/template/TemplatePreviewController.java
public final class TemplatePreviewController {

  private final TemplateRenderer renderer = new TemplateRenderer();

  // The fragment is assumed to originate from a template "preview" feature.
  // Example: an HTTP parameter named "template" is sent from the UI and passed into this method.
  public String preview(String userFragment) {
    Map<String, Object> model = new HashMap<>();
    model.put("user", getCurrentUser());
    return renderer.renderFragment(userFragment, model);
  }
  
  // Example entry-point showing how user-controlled input can reach preview().
  // In real applications this may be a Spring MVC/JAX-RS handler or a servlet.
  public String previewEndpoint(HttpServletRequest req) {
    String userFragment = req.getParameter("template"); // attacker-controlled
    return preview(userFragment);
  }
}

// src/main/java/com/acme/template/TemplateRenderer.java
public final class TemplateRenderer {

  private final freemarker.template.Configuration cfg;

  public TemplateRenderer() {
    cfg = new freemarker.template.Configuration(freemarker.template.Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");

    // Vulnerable configuration: permissive class resolution.
    cfg.setNewBuiltinClassResolver(freemarker.core.TemplateClassResolver.UNRESTRICTED_RESOLVER);
  }

  public String renderFragment(String fragment, Map<String, Object> model) {
    try (StringWriter out = new StringWriter()) {
      String source = "<h1>Preview</h1>\n" + fragment;
      freemarker.template.Template t = new freemarker.template.Template("user", source, cfg);
      t.process(model, out);
      return out.toString();
    } catch (Exception e) {
      // Debug deployments often leak full stack traces.
      throw new RuntimeException("Rendering failed", e);
    }
  }
}
```

### **Security issues enabling exploitation**
General issues:
* USER CONTROLLED TEMPLATES
* Untrusted input is incorporated into template rendering in a way that allows interpretation as template syntax (template injection).
* Template rendering occurs in a privileged server-side context with access to application objects and OS-level capabilities.
* Missing validation/encoding allows template metacharacters and expression delimiters to reach the interpreter.

Engine-specific issues:
* Logic-capable template engine
* Dangerous utility classes enabled
* Debug mode exposing stack traces
* No template sandboxing

### **How to fix it**
General recommendations:
* Avoid dynamic template construction
* Use strict variable substitution
* Escape and validate all user-controlled data
* REMOVE USER CONTROLLED TEMPLATES FUNCTIONALITY, but if it's not possible due to the business reasons see below

Engine-specific recommendations:
* Disable `Execute` utility class
* Use safer class resolvers
* Disable debug mode in production

## Key Takeaways

### Lessons from Attacker perspective

* FreeMarker SSTI allows arbitrary Python code execution without additional sandbox escape.
* Access to standard Java classes makes filesystem and command execution straightforward.
* Version detection simplifies exploitation

### Lessons from AppSec (defender) perspective

* Template engines are programming languages, not formatting tools.
* User input must never influence template source code.
* SSTI is a design flaw, not an input validation bug.
* If user input is parsed by the template engine, SSTI is inevitable: try to avoid it.

## References

* [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)
* [https://freemarker.apache.org/docs/](https://freemarker.apache.org/docs/)
* [https://owasp.org/www-community/attacks/Server_Side_Template_Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)