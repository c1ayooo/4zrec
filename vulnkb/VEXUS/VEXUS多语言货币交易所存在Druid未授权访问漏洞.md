# VEXUS多语言货币交易所存在Druid未授权访问漏洞

- **系统**：VEXUS　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`"image/n2.png"`
- **请求**：`GET /normal/LoginSuccessAction!view.action?username=admin HTTP/1.1`

**请求体 / payload**
```
Druid版本为 1.2.8，存在未授权访问漏洞，直接访问 /druid/index.html 即可进入
访问 /druid/websession.html 这里还存储了所有登陆后台的Session，只需要找到可用Session的即可直接绕过登录后台。
Cookie: JSESSIONID=可用的SESSION
Host: admin.kftust.com
PS:该漏洞利用比较简单，但是在利用时，运气也是占非常大的成分。只有当用户在线时，才可以拿到有效的Session进行利用，要不然拿着一堆过期的Session是没有任何作用的。在利用时可以根据时间点进行利用，比如上班时间，肯定会有大量用户进行登录，这样可能利用成功的可能性是比较大的。
```
- **预期**：200　|　—