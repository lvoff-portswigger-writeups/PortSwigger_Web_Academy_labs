## Lab Information

**Topic:** SSTI

**Difficulty:** Practitioner

**Template engine:** ERB

**Language:** Ruby

## Lab Description

The application dynamically embeds user-controlled input into an ERB template without sanitization. This behavior enables arbitrary Ruby expression evaluation on the server, resulting in server-side template injection.

## Vulnerability Analysis

ERB templates evaluate Ruby expressions enclosed in `<% %>` and `<%= %>`. When user input is interpolated directly into the template, attackers can inject Ruby code, leading to arbitrary code execution within the application context.

## Exploitation Steps

### 1. Identify the injection point
The `message` parameter in a GET request is reflected into the rendered page output, indicating possible template processing of user input.

### 2. Test for vulnerability
Arithmetic expressions such as `<%=77*77%>` are injected to confirm server-side evaluation of ERB template expressions. Current date and time is retrieved using Ruby’s built-in `Time.now` method.

### 3. Craft the payload and execute the attack
Ruby expressions are tested incrementally to determine execution capabilities, confirming access to core Ruby classes and methods.

### 4. Verify successful exploitation
The file `/home/carlos/morale.txt` is deleted using Ruby’s `File.delete` method, confirming successful exploitation. See Lab solved.

## AppSec Perspective

### **What the underlying code might be**

```ruby
class MessagesController
  def show
    template = "Message: #{params[:message]}"
    renderer = ERB.new(template)
    @output = renderer.result(binding)
  end
end
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

* ERB SSTI allows arbitrary Ruby code execution without additional sandbox escape.
* Access to standard Ruby classes makes filesystem and command execution straightforward.

### Lessons from AppSec (defender) perspective

* Template engines are programming languages, not formatting tools.
* User input must never influence template source code.
* SSTI is a design flaw, not an input validation bug.

## References

* [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)
* [https://docs.ruby-lang.org/en/master/ERB.html](https://docs.ruby-lang.org/en/master/ERB.html)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Cheat_Sheet.html)