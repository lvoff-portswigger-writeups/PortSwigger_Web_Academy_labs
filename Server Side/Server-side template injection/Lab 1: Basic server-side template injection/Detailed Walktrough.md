# Detailed Walkthrough

When clicking on the first product **View details** icon observe GET request `/?message=Unfortunately%20this%20product%20is%20out%20of%20stock`. The message from GET parameter is reflected to the page.

Run Intruder for `GET /?message=msg` with Simple list payload - “Fuzzing - template injection”. See only 1 payload with 77*77 expression result = 5929. The payload is `<%=77*77%>`.

![image.png](Detailed%20Walkthrough/image.png)

It is probably a Ruby ERB template engine. Visit [https://docs.ruby-lang.org/en/master/ERB.html](https://docs.ruby-lang.org/en/master/ERB.html) to see how the execution in Ruby works.

Execute  `<%=whoami%>`, see the error. It’s what we expect, since whoami is not a correct Ruby syntax command.

![image.png](Detailed%20Walkthrough/image%201.png)

Execute `<%=Date::DAYNAMES[Date.today.wday]%>`, see another error.

![image.png](Detailed%20Walkthrough/image%202.png)

Execute `<%=Time.now%>`, it works.

![image.png](Detailed%20Walkthrough/image%203.png)

Since we confirm SSTI now let’s execute expression to delete Carlos file as it expected: `<%= File.delete("/home/carlos/morale.txt") %>` (or encoded `/?message=%3c%%3dFile.delete("/home/carlos/morale.txt")%%3e`). See Lab solved.

Another way of deleting the file is to run `<%=system("rm+/home/carlos/morale.txt")%>`.