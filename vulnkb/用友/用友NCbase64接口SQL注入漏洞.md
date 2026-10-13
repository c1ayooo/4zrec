# 用友NCbase64接口SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="UClient.dmg"`
- **请求**：`GET /u8cloud/api/file/upload/base64 HTTP/1.1`
- **响应特征**：200 ^(?=.*?nvarchar)(?=.*?3200).*?$