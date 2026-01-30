# Detailed Walkthrough

## 1. Initial reconnaissance

Go to My account, log in using provided credentials.

Go to any product page. See the template is now editable with a couple of placeholders. To save template changes POST request sent `/product/template?productId=<productId>` and body with parameters

`"csrf": csrf_token,"template": payload,"template-action": "save"` . This is our injection point.

Since we need to visit the page after saving the template it’s not very handy to bruteforce the injection point with Intruder. There’s another way - to change a template directly on the page and click preview to enable the rendering.

When I changed `{{product.price}}` to `{{7*7}}` I saw an error indicating Django template engine is used.

```java
Internal Server Error
Traceback (most recent call last): File "<string>", line 11, in <module> File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 191, in __init__ self.nodelist = self.compile_nodelist() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 230, in compile_nodelist return parser.parse() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 486, in parse raise self.error(token, e) django.template.exceptions.TemplateSyntaxError: Could not parse the remainder: '*7' from '7*7'
```

When I send `whoami` command, another error arised.

![image.png](Detailed%20Walkthrough/image.png)

Looks like we can’t execute system commands (we’ll see that SSTI works another way in Django later). Find this article [https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti) with multiple template engines payloads. It’s possible to enable DEBUG mode using expression `{% debug %}`, and directly call engine to display specific parameters. It’s very close to Information Disclosure that we actually need in this lab.

Put `{% debug %}` to the placeholder.

![image.png](Detailed%20Walkthrough/image%201.png)

Observe settings variable we can refer to. Review the documentation [https://docs.djangoproject.com/en/6.0/ref/settings/](https://docs.djangoproject.com/en/6.0/ref/settings/) and see ‘settings’ object including sensitive ones (SECRET_KEY specifically). These values won’t be seen in the trace, but when we explicitly “call” this parameter, it will be shown.

![image.png](Detailed%20Walkthrough/image%202.png)

Add this payload to a template `{% debug %} {{ settings.SECRET_KEY }}` or just `{{ settings.SECRET_KEY }}` and click Preview. See a long piece of trace and a secret exposed at the end. Put this value to Submit solution and see Lab solved.

![image.png](Detailed%20Walkthrough/image%203.png)

Django template engine SSTI exploitation is not the same type that other template engines. See Theory box paragraph for the detailed explanation.