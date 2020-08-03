---
title: verb tampering
category: web
order: 1
---


# Verb Tampering
It is possible to misconfigure Apache, such that authentication is only requested for a particular
method, leading to a basic authentication bypass. Start Burp and intercept the request to
/monitoring, then hit Ctrl+R to send it to Repeater. Change the request method to POST and send
the request.
